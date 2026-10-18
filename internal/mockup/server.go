// Package mockup is the mock upstream for curd test mode (spec 15.3).
package mockup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options configures Start.
type Options struct {
	Addr    string // default 127.0.0.1:0 (host part used for all listeners)
	CertDir string // if set, cert.pem is written there
}

// Recorded is one request seen by the mock upstream.
type Recorded struct {
	Seq      int                 `json:"seq"`
	Time     time.Time           `json:"time"`
	Host     string              `json:"host"`
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	RawQuery string              `json:"raw_query"`
	Headers  map[string][]string `json:"headers"`
	Cookies  map[string]string   `json:"cookies"`
	Body     string              `json:"body"`
	TLS      bool                `json:"tls"`
}

const maxRecordedBody = 1 << 20

// Server is a running mock upstream.
type Server struct {
	certPEM  []byte
	pool     *x509.CertPool
	certFile string

	tlsLn, httpLn, ctlLn net.Listener
	servers              []*http.Server

	mu        sync.Mutex
	records   []Recorded
	seq       int
	st        state
	closeOnce sync.Once
}

type state struct {
	validSession string
	flakySeen    bool
	flakyMode    string // "", "ok" (never fail), "fail" (always fail)
	csrf         map[string]string
	theme        string
}

func freshState() state {
	return state{validSession: SessionCookie, csrf: map[string]string{}, theme: "light"}
}

// Start launches the TLS, plain-HTTP and control listeners.
func Start(opts Options) (*Server, error) {
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	s := &Server{st: freshState()}
	cert, certPEM, err := genCert()
	if err != nil {
		return nil, err
	}
	s.certPEM = certPEM
	s.pool = x509.NewCertPool()
	s.pool.AppendCertsFromPEM(certPEM)
	if opts.CertDir != "" {
		if err := os.MkdirAll(opts.CertDir, 0o755); err != nil {
			return nil, err
		}
		s.certFile = filepath.Join(opts.CertDir, "cert.pem")
		if err := os.WriteFile(s.certFile, certPEM, 0o644); err != nil {
			return nil, err
		}
	}
	listen := func(a string) (net.Listener, error) { return net.Listen("tcp", a) }
	if s.tlsLn, err = listen(addr); err != nil {
		return nil, err
	}
	other := net.JoinHostPort(host, "0")
	if s.httpLn, err = listen(other); err != nil {
		s.tlsLn.Close()
		return nil, err
	}
	if s.ctlLn, err = listen(other); err != nil {
		s.tlsLn.Close()
		s.httpLn.Close()
		return nil, err
	}
	tlsLn := tls.NewListener(s.tlsLn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	for _, p := range []struct {
		ln net.Listener
		h  http.Handler
	}{{tlsLn, http.HandlerFunc(s.serve)}, {s.httpLn, http.HandlerFunc(s.serve)}, {s.ctlLn, s.controlMux()}} {
		hs := &http.Server{Handler: p.h, ReadHeaderTimeout: 10 * time.Second}
		s.servers = append(s.servers, hs)
		go hs.Serve(p.ln)
	}
	return s, nil
}

func genCert() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "curd mock upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{HostApp, HostAPI, HostOther, "*.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pemBytes, nil
}

func (s *Server) TLSURL() string     { return "https://127.0.0.1:" + strconv.Itoa(s.TLSPort()) }
func (s *Server) TLSPort() int       { return s.tlsLn.Addr().(*net.TCPAddr).Port }
func (s *Server) HTTPPort() int      { return s.httpLn.Addr().(*net.TCPAddr).Port }
func (s *Server) ControlURL() string { return "http://" + s.ctlLn.Addr().String() }
func (s *Server) CertPEM() []byte    { return append([]byte(nil), s.certPEM...) }
func (s *Server) CertPool() *x509.CertPool {
	return s.pool
}

// Requests returns a copy of all recorded requests, in order.
func (s *Server) Requests() []Recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Recorded(nil), s.records...)
}

// Reset clears recorded requests and scripted state.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = nil
	s.seq = 0
	s.st = freshState()
}

// Close shuts down all listeners.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		for _, hs := range s.servers {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if hs.Shutdown(ctx) != nil {
				hs.Close()
			}
			cancel()
		}
	})
	return nil
}

func (s *Server) record(r *http.Request, host string, body []byte) {
	rec := Recorded{
		Time: time.Now(), Host: host, Method: r.Method, Path: r.URL.Path,
		RawQuery: r.URL.RawQuery, Headers: map[string][]string{}, Cookies: map[string]string{},
		TLS: r.TLS != nil,
	}
	for k, v := range r.Header {
		rec.Headers[k] = append([]string(nil), v...)
	}
	if r.Host != "" {
		rec.Headers["Host"] = []string{r.Host}
	}
	for _, c := range r.Cookies() {
		rec.Cookies[c.Name] = c.Value
	}
	if len(body) > maxRecordedBody {
		body = body[:maxRecordedBody]
	}
	rec.Body = string(body)
	s.mu.Lock()
	s.seq++
	rec.Seq = s.seq
	s.records = append(s.records, rec)
	s.mu.Unlock()
}

func (s *Server) controlMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, r *http.Request) {
		host, path := r.URL.Query().Get("host"), r.URL.Query().Get("path")
		out := []Recorded{}
		for _, rec := range s.Requests() {
			if (host == "" || rec.Host == host) && (path == "" || rec.Path == path) {
				out = append(out, rec)
			}
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		s.Reset()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /state", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ValidSession *string `json:"valid_session"`
			FlakyAuth    *string `json:"flaky_auth"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		s.mu.Lock()
		if in.ValidSession != nil {
			s.st.validSession = *in.ValidSession
		}
		if in.FlakyAuth != nil {
			s.st.flakyMode = *in.FlakyAuth
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

func writeHTML(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func hostOnly(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	host := hostOnly(r.Host)
	s.record(r, host, body)
	switch host {
	case HostApp:
		s.serveApp(w, r, body)
	case HostAPI:
		s.serveAPI(w, r, body)
	case HostOther:
		if r.URL.Path == "/collect" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "collected")
			return
		}
		writeJSON(w, 404, map[string]any{"error": "not found"})
	default:
		writeJSON(w, 404, map[string]any{"error": "unknown host"})
	}
}

// hostPort returns the port the client used (from Host), falling back to
// the listener port for the request's scheme.
func (s *Server) hostPort(r *http.Request) string {
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		return p
	}
	if r.TLS != nil {
		return strconv.Itoa(s.TLSPort())
	}
	return strconv.Itoa(s.HTTPPort())
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
