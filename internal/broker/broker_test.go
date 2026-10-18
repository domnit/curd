package broker

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/source"
)

const (
	secretSession = "SESSIONSECRET123"
	secretToken   = "TOKENSECRET456"
	secretOther   = "OTHERSECRET789"
)

type rec struct {
	Host, Method, Path, RawQuery, Cookie, Auth, Body string
	Header                                           http.Header
}

type env struct {
	t      *testing.T
	srv    *httptest.Server // TLS
	plain  *httptest.Server // http
	port   string
	pport  string
	pool   *x509.CertPool
	file   string
	mu     sync.Mutex
	reqs   []rec
	h      func(w http.ResponseWriter, r *http.Request)
	static *source.StaticFile
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "curd test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		DNSNames:    []string{"app.example.com", "other.example.net", "evil.example.org", "a.example.net", "b.example.net"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return cert, pool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t}
	cert, pool := selfSigned(t)
	e.pool = pool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			buf := new(strings.Builder)
			b := make([]byte, 4096)
			for {
				n, err := r.Body.Read(b)
				buf.Write(b[:n])
				if err != nil {
					break
				}
			}
			body = []byte(buf.String())
		}
		host, _, _ := net.SplitHostPort(r.Host)
		e.mu.Lock()
		e.reqs = append(e.reqs, rec{Host: host, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
			Cookie: r.Header.Get("Cookie"), Auth: r.Header.Get("Authorization"), Body: string(body), Header: r.Header.Clone()})
		h := e.h
		e.mu.Unlock()
		if h == nil {
			w.WriteHeader(200)
			return
		}
		h(w, r)
	})
	e.srv = httptest.NewUnstartedServer(handler)
	e.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	e.srv.StartTLS()
	e.plain = httptest.NewServer(handler)
	t.Cleanup(e.srv.Close)
	t.Cleanup(e.plain.Close)
	_, e.port, _ = net.SplitHostPort(e.srv.Listener.Addr().String())
	_, e.pport, _ = net.SplitHostPort(e.plain.Listener.Addr().String())
	e.file = filepath.Join(t.TempDir(), "static.yaml")
	e.static = &source.StaticFile{
		Cookies: []source.StaticCookie{{Name: "session", Value: secretSession, Domain: "app.example.com"}},
		LocalStorage: []source.StaticLocalStorage{
			{Origin: "https://app.example.com", Key: "authToken", Value: secretToken},
		},
	}
	return e
}

func (e *env) save() {
	e.t.Helper()
	if err := source.WriteStaticFile(e.file, e.static); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) handle(h func(w http.ResponseWriter, r *http.Request)) {
	e.mu.Lock()
	e.h = h
	e.mu.Unlock()
}

func (e *env) recs() []rec {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]rec(nil), e.reqs...)
}

func (e *env) reset() {
	e.mu.Lock()
	e.reqs = nil
	e.mu.Unlock()
}

func (e *env) url(host, path string) string {
	return fmt.Sprintf("https://%s:%s%s", host, e.port, path)
}

func (e *env) purl(host, path string) string {
	return fmt.Sprintf("http://%s:%s%s", host, e.pport, path)
}

const basePolicy = `
name: dash
match:
  hosts: [app.example.com]
credentials:
  local_storage:
    - origin: https://app.example.com
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET, HEAD, POST]
    paths: ['^/.*$']
request:
  header_allowlist: [accept, content-type, x-csrf-token]
test:
  host_map:
    app.example.com: 127.0.0.1
    other.example.net: 127.0.0.1
    evil.example.org: 127.0.0.1
    a.example.net: 127.0.0.1
    b.example.net: 127.0.0.1
`

// pol builds a policy: basePolicy with replacements applied (old, new pairs).
func pol(t *testing.T, repl ...string) *policy.Policy {
	t.Helper()
	y := basePolicy
	for i := 0; i < len(repl); i += 2 {
		if !strings.Contains(y, repl[i]) {
			t.Fatalf("policy template lacks %q", repl[i])
		}
		y = strings.Replace(y, repl[i], repl[i+1], 1)
	}
	p, err := policy.Parse([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) broker(test bool) (*Broker, *source.Manager) {
	e.save()
	m := source.NewManager(source.NewStatic(e.file), source.Options{})
	b := New(Options{Sources: m, Test: test, RootCAs: e.pool, UserAgent: "TestUA/1.0", Timeout: 10 * time.Second})
	return b, m
}

func (e *env) do(b *Broker, p *policy.Policy, method, u string, hdrs []api.Header, body string) (*Response, error) {
	var bb []byte
	if body != "" {
		bb = []byte(body)
	}
	// basePolicy's rule allows POST, so it is write-scoped and the daemon
	// would already have required a write grant.
	return b.Do(context.Background(), p, Request{Method: method, URL: u, Headers: hdrs, Body: bb, Scopes: []string{"read", "write"}})
}

func hdr(kv ...string) []api.Header {
	var out []api.Header
	for i := 0; i < len(kv); i += 2 {
		out = append(out, api.Header{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func mustOK(t *testing.T, r *Response, err error) *Response {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return r
}

func hasHeader(r *Response, name string) bool {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}

func TestBasicCookieAndHeaders(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	p := pol(t)
	e.handle(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) })
	resp, err := e.do(b, p, "GET", e.url("app.example.com", "/api/x?q=1"), hdr(
		"Cookie", "evil=1", "Authorization", "Bearer evil", "Host", "evil.example.org",
		"X-CSRF-Token", "csrf1", "X-Evil", "nope", "Accept", "application/json", "User-Agent", "Evil/9"), "")
	mustOK(t, resp, err)
	if resp.Status != 200 || string(resp.Body) != "hello" {
		t.Fatalf("%+v", resp)
	}
	rs := e.recs()
	if len(rs) != 1 {
		t.Fatal(len(rs))
	}
	g := rs[0]
	if g.Host != "app.example.com" || g.Cookie != "session="+secretSession || g.Auth != "Bearer "+secretToken {
		t.Fatalf("%+v", g)
	}
	if g.Header.Get("X-Evil") != "" || g.Header.Get("X-Csrf-Token") != "csrf1" || g.Header.Get("Accept") != "application/json" {
		t.Fatalf("headers %v", g.Header)
	}
	if g.Header.Get("User-Agent") != "TestUA/1.0" {
		t.Fatalf("UA %q", g.Header.Get("User-Agent"))
	}
	if g.Header.Get("Accept-Language") == "" {
		t.Fatal("no default Accept-Language")
	}
	if g.RawQuery != "q=1" {
		t.Fatal(g.RawQuery)
	}
	if strings.Join(resp.CookiesSent, ",") != "session" || strings.Join(resp.InjectedHeaders, ",") != "Authorization" {
		t.Fatalf("%v %v", resp.CookiesSent, resp.InjectedHeaders)
	}
	// default Accept
	e.reset()
	if _, err := e.do(b, p, "GET", e.url("app.example.com", "/"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.recs()[0].Header.Get("Accept"); got != "*/*" {
		t.Fatalf("default accept %q", got)
	}
}

func TestPlan(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	p := pol(t)
	pl, err := b.Plan(context.Background(), p, Request{Method: "GET", URL: e.url("app.example.com", "/x"),
		Headers: hdr("Cookie", "x=1", "X-CSRF-Token", "a", "X-Evil", "b", "Accept-Encoding", "br")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pl.Cookies, ",") != "session" || strings.Join(pl.Injected, ",") != "Authorization" {
		t.Fatalf("%+v", pl)
	}
	if strings.Join(pl.KeptHeaders, ",") != "X-CSRF-Token" || len(pl.DroppedHeaders) != 3 {
		t.Fatalf("%+v", pl)
	}
	if len(e.recs()) != 0 {
		t.Fatal("Plan must not send anything")
	}
}

func TestGzipTransparent(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Write([]byte("plain"))
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("zipped body"))
		gz.Close()
	})
	resp, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/"), hdr("Accept-Encoding", "br"), "")
	mustOK(t, resp, err)
	if string(resp.Body) != "zipped body" || hasHeader(resp, "Content-Encoding") || hasHeader(resp, "Content-Length") {
		t.Fatalf("%q %+v", resp.Body, resp.Headers)
	}
}

func TestCookieMatching(t *testing.T) {
	e := newEnv(t)
	e.static.Cookies = []source.StaticCookie{
		{Name: "hostonly", Value: "h", Domain: "app.example.com"},
		{Name: "dom", Value: "d", Domain: ".example.net"},
		{Name: "api", Value: "p", Domain: "app.example.com", Path: "/api"},
		{Name: "sec", Value: "s", Domain: "app.example.com", Secure: true},
		{Name: "sibling", Value: "x", Domain: "other.example.net"},
		{Name: "expired", Value: "x", Domain: "app.example.com", Expires: time.Now().Add(-time.Hour)},
		{Name: "tracking", Value: "t", Domain: "app.example.com"},
	}
	b, _ := e.broker(true)
	p := pol(t, "hosts: [app.example.com]", "hosts: [app.example.com, other.example.net, a.example.net]",
		"credentials:\n", "credentials:\n  cookies: [hostonly, dom, api, sec, sibling, expired]\n")
	get := func(u string) string {
		t.Helper()
		e.reset()
		resp, err := e.do(b, p, "GET", u, nil, "")
		mustOK(t, resp, err)
		return e.recs()[0].Cookie
	}
	if got := get(e.url("app.example.com", "/")); got != "hostonly=h; sec=s" {
		t.Fatalf("root: %q", got)
	}
	if got := get(e.url("app.example.com", "/api/v1")); got != "api=p; hostonly=h; sec=s" {
		t.Fatalf("api: %q", got)
	}
	if got := get(e.url("app.example.com", "/apix")); got != "hostonly=h; sec=s" {
		t.Fatalf("apix (path prefix must respect boundary): %q", got)
	}
	// domain cookie goes to subdomains but not host-only/sibling cookies.
	if got := get(e.url("other.example.net", "/")); got != "dom=d; sibling=x" {
		t.Fatalf("other: %q", got)
	}
	if got := get(e.url("a.example.net", "/")); got != "dom=d" {
		t.Fatalf("a: %q", got)
	}
	// Secure cookies are not sent over plain http.
	if got := get(e.purl("app.example.com", "/")); got != "hostonly=h" {
		t.Fatalf("http: %q", got)
	}
	// cookie name allowlist: tracking is never sent even if the source had it.
	if strings.Contains(get(e.url("app.example.com", "/")), "tracking") {
		t.Fatal("tracking sent")
	}
}

func TestExplicitWildcardHosts(t *testing.T) {
	e := newEnv(t)
	e.static.Cookies = []source.StaticCookie{{Name: "session", Value: secretSession, Domain: ".example.net"}}
	b, _ := e.broker(true)
	p := pol(t, "hosts: [app.example.com]", "hosts: ['*.example.net']")
	resp, err := e.do(b, p, "GET", e.url("a.example.net", "/"), nil, "")
	mustOK(t, resp, err)
	if e.recs()[0].Cookie != "session="+secretSession {
		t.Fatal("cookie missing on wildcard subdomain")
	}
	e.reset()
	for _, h := range []string{"example.net", "app.example.com", "a.example.net.evil.org", "xexample.net"} {
		_, err := e.do(b, p, "GET", e.url(h, "/"), nil, "")
		if apierr.CodeOf(err) != apierr.DeniedHost {
			t.Fatalf("%s: %v", h, err)
		}
	}
	if len(e.recs()) != 0 {
		t.Fatal("requests leaked")
	}
}

func TestRedirects(t *testing.T) {
	t.Run("same-host followed with creds", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/a" {
				http.Redirect(w, r, "/b?x=1", 302)
				return
			}
			w.Write([]byte("final"))
		})
		resp, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/a"), nil, "")
		mustOK(t, resp, err)
		rs := e.recs()
		if len(rs) != 2 || rs[1].Path != "/b" || rs[1].Cookie != "session="+secretSession || rs[1].Auth == "" {
			t.Fatalf("%+v", rs)
		}
		if resp.Hops != 1 || string(resp.Body) != "final" || !strings.HasSuffix(resp.URL, "/b?x=1") || resp.RedirectBlocked != "" {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("unmatched host not followed", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, e.url("evil.example.org", "/steal"), 302)
		})
		for _, mode := range []string{"same-host-only", "policy-hosts"} {
			e.reset()
			p := pol(t, "request:", "redirects: "+mode+"\nrequest:")
			resp, err := e.do(b, p, "GET", e.url("app.example.com", "/a"), nil, "")
			mustOK(t, resp, err)
			if resp.Status != 302 || resp.RedirectBlocked == "" || resp.Hops != 0 {
				t.Fatalf("%s: %+v", mode, resp)
			}
			for _, r := range e.recs() {
				if r.Host == "evil.example.org" {
					t.Fatalf("%s: request reached unmatched host: %+v", mode, r)
				}
			}
			if len(e.recs()) != 1 {
				t.Fatal(len(e.recs()))
			}
		}
	})
	t.Run("none", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", 302) })
		resp, err := e.do(b, pol(t, "request:", "redirects: none\nrequest:"), "GET", e.url("app.example.com", "/a"), nil, "")
		mustOK(t, resp, err)
		if resp.Status != 302 || resp.RedirectBlocked == "" || len(e.recs()) != 1 {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("policy-hosts follows other policy host with recomputed cookies", func(t *testing.T) {
		e := newEnv(t)
		e.static.Cookies = []source.StaticCookie{
			{Name: "session", Value: secretSession, Domain: "app.example.com"},
			{Name: "osess", Value: secretOther, Domain: "other.example.net"},
		}
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) {
			if r.Host[:3] == "app" {
				http.Redirect(w, r, e.url("other.example.net", "/in"), 302)
				return
			}
			w.Write([]byte("other"))
		})
		p := pol(t, "hosts: [app.example.com]", "hosts: [app.example.com, other.example.net]", "request:", "redirects: policy-hosts\nrequest:")
		resp, err := e.do(b, p, "GET", e.url("app.example.com", "/a"), nil, "")
		mustOK(t, resp, err)
		rs := e.recs()
		if len(rs) != 2 || rs[1].Host != "other.example.net" || rs[1].Cookie != "osess="+secretOther {
			t.Fatalf("%+v", rs)
		}
		// Injected authorization is origin scoped: not sent to the other origin.
		if rs[1].Auth != "" || len(resp.InjectedHeaders) != 0 {
			t.Fatalf("auth leaked to other origin: %+v", rs[1])
		}
		if resp.Hops != 1 || strings.Join(resp.CookiesSent, ",") != "osess" {
			t.Fatalf("%+v", resp)
		}
		// same-host-only refuses the same redirect
		e.reset()
		p2 := pol(t, "hosts: [app.example.com]", "hosts: [app.example.com, other.example.net]")
		resp, _ = e.do(b, p2, "GET", e.url("app.example.com", "/a"), nil, "")
		if resp.RedirectBlocked == "" || len(e.recs()) != 1 {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("hop re-checked against policy paths", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", 302) })
		p := pol(t, "paths: ['^/.*$']", "paths: ['^/api/.*$']")
		resp, err := e.do(b, p, "GET", e.url("app.example.com", "/api/a"), nil, "")
		mustOK(t, resp, err)
		if resp.Status != 302 || !strings.Contains(resp.RedirectBlocked, apierr.DeniedPath) || len(e.recs()) != 1 {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("method changes", func(t *testing.T) {
		for _, tc := range []struct {
			code       int
			wantMethod string
			wantBody   string
		}{{303, "GET", ""}, {302, "GET", ""}, {301, "GET", ""}, {307, "POST", "payload"}, {308, "POST", "payload"}} {
			e := newEnv(t)
			b, _ := e.broker(true)
			code := tc.code
			e.handle(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/next", code)
					return
				}
				w.WriteHeader(200)
			})
			resp, err := e.do(b, pol(t), "POST", e.url("app.example.com", "/start"), hdr("Content-Type", "text/plain"), "payload")
			mustOK(t, resp, err)
			rs := e.recs()
			if len(rs) != 2 {
				t.Fatal(len(rs))
			}
			if rs[1].Method != tc.wantMethod || rs[1].Body != tc.wantBody {
				t.Fatalf("%d: %+v", tc.code, rs[1])
			}
			if tc.wantBody == "" && rs[1].Header.Get("Content-Type") != "" {
				t.Fatalf("%d: content-type kept on body-less hop", tc.code)
			}
			if tc.wantBody != "" && rs[1].Header.Get("Content-Type") != "text/plain" {
				t.Fatalf("%d: content-type lost", tc.code)
			}
		}
	})
	t.Run("too many hops", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 302) })
		resp, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/loop"), nil, "")
		mustOK(t, resp, err)
		if resp.Hops != 10 || resp.RedirectBlocked == "" || resp.Status != 302 {
			t.Fatalf("%+v", resp)
		}
		if len(e.recs()) != 11 {
			t.Fatal(len(e.recs()))
		}
	})
	t.Run("unsupported scheme not followed", func(t *testing.T) {
		e := newEnv(t)
		b, _ := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "ftp://app.example.com/x", 302) })
		resp, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/a"), nil, "")
		mustOK(t, resp, err)
		if resp.RedirectBlocked == "" {
			t.Fatal("ftp redirect followed")
		}
	})
}

func TestReloadOn401(t *testing.T) {
	e := newEnv(t)
	b, m := e.broker(true)
	p := pol(t)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "fresh") {
			w.Write([]byte("ok"))
			return
		}
		// the user "logs in again" in Chrome while we are being refused
		e.static.Cookies[0].Value = "fresh-login"
		if err := source.WriteStaticFile(e.file, e.static); err != nil {
			t.Error(err)
		}
		w.WriteHeader(401)
	})
	resp, err := e.do(b, p, "GET", e.url("app.example.com", "/x"), nil, "")
	mustOK(t, resp, err)
	if resp.Status != 200 || !resp.Retried || len(e.recs()) != 2 || m.Loads("dash") != 2 {
		t.Fatalf("%+v loads=%d reqs=%d", resp, m.Loads("dash"), len(e.recs()))
	}
	if e.recs()[1].Cookie != "session=fresh-login" {
		t.Fatalf("%q", e.recs()[1].Cookie)
	}
	// next request does not retry
	e.reset()
	resp, err = e.do(b, p, "GET", e.url("app.example.com", "/x"), nil, "")
	mustOK(t, resp, err)
	if resp.Retried || len(e.recs()) != 1 {
		t.Fatal("unexpected retry")
	}
}

func TestAuthExpired(t *testing.T) {
	for _, code := range []int{401, 403} {
		e := newEnv(t)
		b, m := e.broker(true)
		e.handle(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		_, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/x"), nil, "")
		ae := apierr.As(err)
		if ae.Code != apierr.AuthExpired {
			t.Fatalf("%v", err)
		}
		if !strings.Contains(ae.Hint, "log into app.example.com in Chrome") || ae.Data["status"] != code {
			t.Fatalf("%+v", ae)
		}
		if len(e.recs()) != 2 || m.Loads("dash") != 2 {
			t.Fatalf("expected exactly one retry: reqs=%d loads=%d", len(e.recs()), m.Loads("dash"))
		}
	}
}

func TestRetryResendsBody(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	n := 0
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	})
	resp, err := e.do(b, pol(t), "POST", e.url("app.example.com", "/x"), hdr("Content-Type", "text/plain"), "the-body")
	mustOK(t, resp, err)
	rs := e.recs()
	if len(rs) != 2 || rs[1].Body != "the-body" || rs[1].Method != "POST" {
		t.Fatalf("%+v", rs)
	}
}

func TestSetCookieAppliedAndStripped(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "rotated", Path: "/", Secure: true, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: "extra", Value: "1", Path: "/"})
			w.Header().Set("X-Secret", "internal")
			w.Header().Set("X-Keep", "yes")
			w.Write([]byte("ok"))
		case "/hop":
			http.SetCookie(w, &http.Cookie{Name: "hopc", Value: "hv", Path: "/"})
			http.Redirect(w, r, "/after", 302)
		default:
			w.Write([]byte("ok"))
		}
	})
	p := pol(t, "request:", "response:\n  strip_headers: [x-secret]\nrequest:")
	resp, err := e.do(b, p, "GET", e.url("app.example.com", "/login"), nil, "")
	mustOK(t, resp, err)
	if hasHeader(resp, "Set-Cookie") || hasHeader(resp, "X-Secret") || !hasHeader(resp, "X-Keep") {
		t.Fatalf("%+v", resp.Headers)
	}
	e.reset()
	resp, err = e.do(b, p, "GET", e.url("app.example.com", "/next"), nil, "")
	mustOK(t, resp, err)
	got := e.recs()[0].Cookie
	if !strings.Contains(got, "session=rotated") || strings.Contains(got, secretSession) || !strings.Contains(got, "extra=1") {
		t.Fatalf("%q", got)
	}
	// Set-Cookie on a redirect hop applies before the next hop.
	e.reset()
	resp, err = e.do(b, p, "GET", e.url("app.example.com", "/hop"), nil, "")
	mustOK(t, resp, err)
	rs := e.recs()
	if len(rs) != 2 || !strings.Contains(rs[1].Cookie, "hopc=hv") {
		t.Fatalf("%+v", rs)
	}
}

func TestSetCookieSurvivesReload(t *testing.T) {
	e := newEnv(t)
	b, m := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "rotated", Path: "/"})
		}
		w.WriteHeader(200)
	})
	p := pol(t)
	e.do(b, p, "GET", e.url("app.example.com", "/login"), nil, "")
	if _, err := m.Get(context.Background(), p, true); err != nil {
		t.Fatal(err)
	}
	e.reset()
	e.do(b, p, "GET", e.url("app.example.com", "/x"), nil, "")
	if e.recs()[0].Cookie != "session=rotated" {
		t.Fatalf("%q", e.recs()[0].Cookie)
	}
}

func TestResponseCapsAndRedact(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 100)))
	})
	p := pol(t, "request:", "response:\n  max_body_bytes: 10\nrequest:")
	resp, err := e.do(b, p, "GET", e.url("app.example.com", "/"), nil, "")
	mustOK(t, resp, err)
	if len(resp.Body) != 10 || !resp.Truncated {
		t.Fatalf("%d %v", len(resp.Body), resp.Truncated)
	}
	e.handle(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("a", 10))) })
	resp, _ = e.do(b, p, "GET", e.url("app.example.com", "/"), nil, "")
	if len(resp.Body) != 10 || resp.Truncated {
		t.Fatalf("exact size must not be truncated: %d %v", len(resp.Body), resp.Truncated)
	}
	e.handle(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"k":"sk-abc123","n":1}`)) })
	p = pol(t, "request:", "response:\n  redact: ['sk-[a-z0-9]+']\nrequest:")
	resp, _ = e.do(b, p, "GET", e.url("app.example.com", "/"), nil, "")
	if string(resp.Body) != `{"k":"[REDACTED]","n":1}` {
		t.Fatalf("%s", resp.Body)
	}
}

func TestRequestBodyCap(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	p := pol(t, "request:", "request:\n  max_body_bytes: 5")
	_, err := e.do(b, p, "POST", e.url("app.example.com", "/"), nil, "123456")
	if apierr.CodeOf(err) != apierr.DeniedBodySize {
		t.Fatalf("%v", err)
	}
	if _, err := e.do(b, p, "POST", e.url("app.example.com", "/"), nil, "12345"); err != nil {
		t.Fatal(err)
	}
	if len(e.recs()) != 1 {
		t.Fatal("oversize body was sent")
	}
}

func TestHTTPRefusedOutsideTestMode(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(false)
	_, err := e.do(b, pol(t), "GET", e.purl("app.example.com", "/"), nil, "")
	ae := apierr.As(err)
	if ae.Code != apierr.InvalidRequest || !strings.Contains(ae.Hint, "https") {
		t.Fatalf("%v", err)
	}
	if len(e.recs()) != 0 {
		t.Fatal("request sent")
	}
	// allowed in test mode
	bt, _ := e.broker(true)
	resp, err := e.do(bt, pol(t), "GET", e.purl("app.example.com", "/"), nil, "")
	mustOK(t, resp, err)
	rs := e.recs()
	if len(rs) != 1 || rs[0].Cookie != "session="+secretSession {
		t.Fatalf("%+v", rs)
	}
}

func TestHostMapIgnoredOutsideTestMode(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(false)
	p := pol(t)
	if b.hostMap(p) != nil {
		t.Fatal("hostMap must be nil outside test mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, err := b.Do(ctx, p, Request{Method: "GET", URL: e.url("app.example.com", "/")})
	if apierr.CodeOf(err) != apierr.UpstreamError {
		t.Fatalf("expected upstream_error, got %v", err)
	}
	if len(e.recs()) != 0 {
		t.Fatal("host_map was honored outside test mode")
	}
}

func TestUntrustedCertificate(t *testing.T) {
	e := newEnv(t)
	e.save()
	m := source.NewManager(source.NewStatic(e.file), source.Options{})
	b := New(Options{Sources: m, Test: true, UserAgent: "x"}) // no RootCAs
	_, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/"), nil, "")
	ae := apierr.As(err)
	if ae.Code != apierr.UpstreamError || !strings.Contains(ae.Hint, "certificate") {
		t.Fatalf("%v", err)
	}
	if len(e.recs()) != 0 {
		t.Fatal("request reached server")
	}
}

func TestURLValidation(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	p := pol(t)
	cases := map[string]string{
		"https://user:pw@app.example.com/": apierr.InvalidRequest,
		"ftp://app.example.com/":           apierr.InvalidRequest,
		"/relative":                        apierr.InvalidRequest,
		"":                                 apierr.InvalidRequest,
		"https://evil.example.org/":        apierr.DeniedHost,
	}
	for u, want := range cases {
		_, err := b.Do(context.Background(), p, Request{Method: "GET", URL: u})
		if apierr.CodeOf(err) != want {
			t.Errorf("%q: got %v, want %s", u, err, want)
		}
	}
}

// TestNoSecretsInErrors drives many failure paths and asserts no credential
// value appears in any error or in response metadata.
func TestNoSecretsInErrors(t *testing.T) {
	secrets := []string{secretSession, secretToken, secretOther, "fresh-login"}
	e := newEnv(t)
	e.static.Cookies = append(e.static.Cookies, source.StaticCookie{Name: "osess", Value: secretOther, Domain: "other.example.net"})
	b, _ := e.broker(true)
	p := pol(t, "hosts: [app.example.com]", "hosts: [app.example.com, other.example.net]")
	var errs []error
	var metas []string
	add := func(r *Response, err error) {
		if err != nil {
			errs = append(errs, err)
			errs = append(errs, apierr.As(err))
		}
		if r != nil {
			metas = append(metas, fmt.Sprintf("%v|%v|%v|%v|%v|%v|%v", r.URL, r.RedirectBlocked, r.CookiesSent, r.InjectedHeaders, r.Hops, r.Status, r.Retried))
		}
	}
	u := func(path string) string { return e.url("app.example.com", path) }

	// auth expired
	e.handle(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	add(e.do(b, p, "GET", u("/?token="+"q"), nil, ""))
	// denied host / scheme / userinfo / body size
	add(e.do(b, p, "GET", "https://evil.example.org/", nil, ""))
	add(e.do(b, p, "GET", "https://u:p@app.example.com/", nil, ""))
	add(e.do(b, pol(t, "request:", "request:\n  max_body_bytes: 1"), "POST", u("/"), nil, "xx"))
	// blocked redirect carrying credentials in the target query
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, e.url("evil.example.org", "/x"), 302)
	})
	add(e.do(b, p, "GET", u("/"), nil, ""))
	// abrupt close
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		hj := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
	})
	add(e.do(b, p, "GET", u("/"), nil, ""))
	// unreachable port
	add(b.Do(context.Background(), p, Request{Method: "GET", URL: "https://app.example.com:1/"}))
	// source error whose underlying file contains secrets
	os.WriteFile(e.file, []byte("cookies:\n  - name: s\n    value: "+secretSession+"\n    bogus: "+secretToken+"\n"), 0o600)
	bad := source.NewManager(source.NewStatic(e.file), source.Options{})
	b2 := New(Options{Sources: bad, Test: true, RootCAs: e.pool})
	add(e.do(b2, p, "GET", u("/"), nil, ""))
	_, perr := b2.Plan(context.Background(), p, Request{Method: "GET", URL: u("/")})
	add(nil, perr)

	if len(errs) < 8 {
		t.Fatalf("only %d errors collected", len(errs))
	}
	for _, err := range errs {
		s := err.Error()
		if j, ok := err.(*apierr.Error); ok {
			s += fmt.Sprintf("%+v", j.Data) + j.Hint + j.Message
		}
		for _, sec := range secrets {
			if strings.Contains(s, sec) {
				t.Errorf("error leaks %q: %s", sec, s)
			}
		}
	}
	for _, m := range metas {
		for _, sec := range secrets {
			if strings.Contains(m, sec) {
				t.Errorf("response metadata leaks %q: %s", sec, m)
			}
		}
	}
	// the cookie header actually carried the secret somewhere (sanity)
	found := false
	for _, r := range e.recs() {
		if strings.Contains(r.Cookie, secretSession) {
			found = true
		}
	}
	if !found {
		t.Fatal("sanity: secret was never sent")
	}
}

func TestRedirectHopNeedsGrantedScope(t *testing.T) {
	const y = `
name: dash
match:
  hosts: [app.example.com]
allow:
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
  - methods: [POST]
    paths: ['^/api/delete$']
  - methods: [GET]
    paths: ['^/read/.*$']
test:
  host_map:
    app.example.com: 127.0.0.1
`
	p, err := policy.Parse([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"query":"{ me }"}`)
	e := newEnv(t)
	b, _ := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/graphql":
			http.Redirect(w, r, "/api/delete", http.StatusTemporaryRedirect)
		case "/read/a":
			http.Redirect(w, r, "/read/b", http.StatusFound)
		default:
			w.Write([]byte("done"))
		}
	})
	for _, scopes := range [][]string{nil, {"read"}} {
		e.reset()
		resp, err := b.Do(context.Background(), p, Request{Method: "POST", URL: e.url("app.example.com", "/graphql"),
			Headers: hdr("Content-Type", "application/json"), Body: body, Scopes: scopes})
		mustOK(t, resp, err)
		if resp.Status != 307 || !strings.Contains(resp.RedirectBlocked, "write scope") {
			t.Fatalf("scopes %v: read grant followed redirect into write rule: %+v", scopes, resp)
		}
		if rs := e.recs(); len(rs) != 1 {
			t.Fatalf("scopes %v: write endpoint was called: %+v", scopes, rs)
		}
	}
	// A write grant may follow it.
	e.reset()
	resp, err := b.Do(context.Background(), p, Request{Method: "POST", URL: e.url("app.example.com", "/graphql"),
		Headers: hdr("Content-Type", "application/json"), Body: body, Scopes: []string{"read", "write"}})
	mustOK(t, resp, err)
	if resp.Status != 200 || resp.RedirectBlocked != "" || len(e.recs()) != 2 {
		t.Fatalf("write grant: %+v", resp)
	}
	// A read hop under a read grant is still followed.
	resp, err = b.Do(context.Background(), p, Request{Method: "GET", URL: e.url("app.example.com", "/read/a")})
	mustOK(t, resp, err)
	if resp.Status != 200 || resp.Hops != 1 {
		t.Fatalf("read hop: %+v", resp)
	}
}

func TestResponseHeldValuesRedacted(t *testing.T) {
	e := newEnv(t)
	b, _ := e.broker(true)
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			w.Header().Set("Location", "/x?c="+url.QueryEscape(r.Header.Get("Cookie")))
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("X-Echo-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("X-Echo-Auth", r.Header.Get("Authorization"))
		w.Write([]byte("cookie=" + r.Header.Get("Cookie") + " auth=" + r.Header.Get("Authorization") +
			" json=" + strings.ReplaceAll(secretToken, "T", `\u0054`)))
	})
	resp, err := e.do(b, pol(t), "GET", e.url("app.example.com", "/echo"), nil, "")
	mustOK(t, resp, err)
	all := string(resp.Body) + fmt.Sprint(resp.Headers) + resp.URL
	for _, sec := range []string{secretSession, secretToken} {
		if strings.Contains(all, sec) {
			t.Fatalf("held value %q returned: %s", sec, all)
		}
	}
	if !strings.Contains(string(resp.Body), "{cookie:session}") || !strings.Contains(string(resp.Body), "{ls:https://app.example.com:authToken}") {
		t.Fatalf("placeholders missing: %s", resp.Body)
	}
	// Redirect blocked (none): the returned Location must not carry it.
	resp, err = e.do(b, pol(t, "request:", "redirects: none\nrequest:"), "GET", e.url("app.example.com", "/redir"), nil, "")
	mustOK(t, resp, err)
	if strings.Contains(fmt.Sprint(resp.Headers), secretSession) {
		t.Fatalf("Location leak: %v", resp.Headers)
	}
	// A held value cut by the size cap is not partially returned.
	e.handle(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("xxxxxxxx" + secretSession))
	})
	resp, err = e.do(b, pol(t, "request:", "response:\n  max_body_bytes: 14\nrequest:"), "GET", e.url("app.example.com", "/cap"), nil, "")
	mustOK(t, resp, err)
	if strings.Contains(string(resp.Body), secretSession[:6]) {
		t.Fatalf("partial held value at cap: %q", resp.Body)
	}
}
