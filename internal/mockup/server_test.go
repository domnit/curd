package mockup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
)

type env struct {
	s   *Server
	c   *http.Client
	tls string // port
}

func newEnv(t *testing.T) *env {
	t.Helper()
	s, err := Start(Options{CertDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d := &net.Dialer{}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: s.CertPool()},
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return d.DialContext(ctx, n, "127.0.0.1:"+p)
		},
	}
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{s: s, c: c, tls: fmt.Sprint(s.TLSPort())}
}

func (e *env) do(t *testing.T, method, host, path string, hdr map[string]string, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://"+host+":"+e.tls+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func sess(v string) map[string]string { return map[string]string{"Cookie": "session=" + v} }

func TestAuthAndRecording(t *testing.T) {
	e := newEnv(t)
	r, _ := e.do(t, "GET", HostApp, "/api/me", nil, "")
	if r.StatusCode != 401 {
		t.Fatalf("got %d", r.StatusCode)
	}
	r, b := e.do(t, "GET", HostApp, "/api/me", sess(SessionCookie), "")
	if r.StatusCode != 200 || !strings.Contains(b, `"alice"`) {
		t.Fatalf("got %d %s", r.StatusCode, b)
	}
	reqs := e.s.Requests()
	if len(reqs) != 2 || reqs[1].Cookies["session"] != SessionCookie || reqs[1].Host != HostApp || !reqs[1].TLS || reqs[1].Seq != 2 {
		t.Fatalf("bad records: %+v", reqs)
	}
	for _, p := range []string{"/api/items/123", "/api/items/123e4567-e89b-12d3-a456-426614174000"} {
		if r, _ := e.do(t, "GET", HostApp, p, nil, ""); r.StatusCode != 200 || r.Header.Get("Content-Type") == "" {
			t.Fatal(p, r.StatusCode)
		}
	}
	if r, _ := e.do(t, "GET", "nope.example.com", "/", nil, ""); r.StatusCode != 404 {
		t.Fatal("unknown host", r.StatusCode)
	}
	if _, b := e.do(t, "GET", HostApp, "/api/big", nil, ""); len(b) < 2<<20 {
		t.Fatal("big too small", len(b))
	}
	e.s.Reset()
	if len(e.s.Requests()) != 0 {
		t.Fatal("reset")
	}
}

func TestRotate(t *testing.T) {
	e := newEnv(t)
	r, _ := e.do(t, "GET", HostApp, "/api/rotate", sess(SessionCookie), "")
	sc := r.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "SECRET") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "HttpOnly") {
		t.Fatal(sc)
	}
	if r, _ := e.do(t, "GET", HostApp, "/api/me", sess(SessionCookie), ""); r.StatusCode != 401 {
		t.Fatal("old cookie still valid")
	}
	if r, _ := e.do(t, "GET", HostApp, "/api/me", sess(RotatedCookie), ""); r.StatusCode != 200 {
		t.Fatal("rotated cookie rejected")
	}
}

func TestFlakyAndState(t *testing.T) {
	e := newEnv(t)
	for i, want := range []int{401, 200, 200} {
		if r, _ := e.do(t, "GET", HostApp, "/api/flaky-auth", nil, ""); r.StatusCode != want {
			t.Fatalf("call %d got %d", i, r.StatusCode)
		}
	}
	e.s.Reset()
	if r, _ := e.do(t, "GET", HostApp, "/api/flaky-auth", nil, ""); r.StatusCode != 401 {
		t.Fatal("reset should re-arm")
	}
	if r, _ := e.do(t, "GET", HostApp, "/api/always-401", nil, ""); r.StatusCode != 401 {
		t.Fatal()
	}
	resp, err := http.Post(e.s.ControlURL()+"/state", "application/json", strings.NewReader(`{"valid_session":"x-SECRET"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	if r, _ := e.do(t, "GET", HostApp, "/api/me", sess("x-SECRET"), ""); r.StatusCode != 200 {
		t.Fatal("state not applied")
	}
}

func TestRedirects(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{
		"/redirect/same":  "/api/me",
		"/redirect/other": "https://other.example.net:" + e.tls + "/collect",
		"/redirect/api":   "https://api.example.com:" + e.tls + "/v1/ping",
	}
	for p, want := range cases {
		r, _ := e.do(t, "GET", HostApp, p, nil, "")
		if r.StatusCode != 302 || r.Header.Get("Location") != want {
			t.Fatalf("%s: %d %q", p, r.StatusCode, r.Header.Get("Location"))
		}
	}
	if r, b := e.do(t, "GET", HostOther, "/collect", nil, ""); r.StatusCode != 200 || b != "collected" {
		t.Fatal(r.StatusCode, b)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	post := func(tok string) int {
		h := sess(SessionCookie)
		h["Content-Type"] = "application/json"
		if tok != "" {
			h["X-CSRF-Token"] = tok
		}
		r, _ := e.do(t, "POST", HostApp, "/api/settings", h, `{"theme":"dark"}`)
		return r.StatusCode
	}
	_, page := e.do(t, "GET", HostApp, "/settings", sess(SessionCookie), "")
	i := strings.Index(page, `content="csrf-`)
	if i < 0 {
		t.Fatal(page)
	}
	tok := page[i+len(`content="`):]
	tok = tok[:strings.Index(tok, `"`)]
	if strings.Contains(tok, "SECRET") {
		t.Fatal("csrf token must not contain SECRET")
	}
	if post("") != 403 || post("csrf-wrong") != 403 {
		t.Fatal("csrf not enforced")
	}
	if post(tok) != 200 {
		t.Fatal("valid token rejected")
	}
	_, page2 := e.do(t, "GET", HostApp, "/settings", sess(SessionCookie), "")
	if page2 == page || post(tok) != 403 {
		t.Fatal("token should be fresh per load")
	}
	if r, _ := e.do(t, "POST", HostApp, "/api/settings", map[string]string{"X-CSRF-Token": tok}, "{}"); r.StatusCode != 401 {
		t.Fatal("unauth should be 401")
	}
	if _, b := e.do(t, "GET", HostApp, "/api/settings", sess(SessionCookie), ""); !strings.Contains(b, "dark") {
		t.Fatal(b)
	}
}

func TestLoginAndPages(t *testing.T) {
	e := newEnv(t)
	jar, _ := cookiejar.New(nil)
	e.c.Jar = jar
	_, b := e.do(t, "GET", HostApp, "/", nil, "")
	if !strings.Contains(b, "Mock Dashboard") || strings.Contains(b, `id="greeting"`) || !strings.Contains(b, "/login") {
		t.Fatal(b)
	}
	if _, b := e.do(t, "GET", HostApp, "/login", nil, ""); !strings.Contains(b, `id="login-button"`) {
		t.Fatal(b)
	}
	r, _ := e.do(t, "POST", HostApp, "/login", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "username=a&password=b")
	if r.StatusCode != 302 || r.Header.Get("Location") != "/" || !strings.Contains(r.Header.Get("Set-Cookie"), "session=") {
		t.Fatal(r.StatusCode, r.Header)
	}
	if _, b := e.do(t, "GET", HostApp, "/", sess(SessionCookie), ""); !strings.Contains(b, `<h1 id="greeting">Hello alice</h1>`) || !strings.Contains(b, `id="items-link"`) {
		t.Fatal(b)
	}
	if _, b := e.do(t, "GET", HostApp, "/ls", nil, ""); !strings.Contains(b, "api.example.com:"+e.tls) {
		t.Fatal(b)
	}
}

func TestAPIHost(t *testing.T) {
	e := newEnv(t)
	bearer := map[string]string{"Authorization": "Bearer " + AuthToken, "Content-Type": "application/json"}
	if r, _ := e.do(t, "GET", HostAPI, "/v1/me", nil, ""); r.StatusCode != 401 {
		t.Fatal()
	}
	if r, _ := e.do(t, "GET", HostAPI, "/v1/me", bearer, ""); r.StatusCode != 200 {
		t.Fatal()
	}
	if r, _ := e.do(t, "GET", HostAPI, "/v1/ping", bearer, ""); r.StatusCode != 200 {
		t.Fatal()
	}
	gql := func(body string) string { _, b := e.do(t, "POST", HostAPI, "/graphql", bearer, body); return b }
	if b := gql(`{"query":"{ viewer { login } }"}`); !strings.Contains(b, `"login":"alice"`) {
		t.Fatal(b)
	}
	if b := gql(`{"query":"query Builds { builds { id status } }","operationName":"Builds"}`); !strings.Contains(b, `"status":"passed"`) {
		t.Fatal(b)
	}
	if b := gql(`{"query":"mutation DeleteBuild { deleteBuild(id: 1) { id } }","operationName":"DeleteBuild"}`); !strings.Contains(b, "deleteBuild") {
		t.Fatal(b)
	}
	r, _ := e.do(t, "OPTIONS", HostAPI, "/v1/me", map[string]string{
		"Origin": "https://app.example.com:" + e.tls, "Access-Control-Request-Method": "GET",
		"Access-Control-Request-Headers": "authorization"}, "")
	if r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com:"+e.tls ||
		!strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatal(r.StatusCode, r.Header)
	}
}

func TestWritesRecorded(t *testing.T) {
	e := newEnv(t)
	e.do(t, "POST", HostApp, "/api/upload", nil, "payload")
	e.do(t, "DELETE", HostApp, "/api/items/123", nil, "")
	reqs := e.s.Requests()
	if len(reqs) != 2 || reqs[0].Body != "payload" || reqs[1].Method != "DELETE" {
		t.Fatalf("%+v", reqs)
	}
}

func TestControlAPIAndPlainHTTP(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/api/me", HostApp, e.s.HTTPPort()), nil)
	req.Header.Set("Cookie", "session="+SessionCookie)
	resp, err := e.c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err, resp)
	}
	resp.Body.Close()
	e.do(t, "GET", HostOther, "/collect", nil, "")
	get := func(q string) []Recorded {
		r, err := http.Get(e.s.ControlURL() + "/requests" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out []Recorded
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	all := get("")
	if len(all) != 2 || all[0].TLS || !all[1].TLS {
		t.Fatalf("%+v", all)
	}
	if f := get("?host=" + HostOther + "&path=/collect"); len(f) != 1 || f[0].Host != HostOther {
		t.Fatalf("%+v", f)
	}
	if r, _ := http.Get(e.s.ControlURL() + "/health"); r.StatusCode != 200 {
		t.Fatal()
	}
	http.Post(e.s.ControlURL()+"/reset", "", nil)
	if len(get("")) != 0 {
		t.Fatal("reset via control failed")
	}
}

func TestCertSANsAndInfo(t *testing.T) {
	dir := t.TempDir()
	s, err := Start(Options{CertDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.TLSPort()), &tls.Config{RootCAs: s.CertPool(), ServerName: "foo.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	for _, h := range []string{HostApp, HostAPI, HostOther, "localhost", "127.0.0.1", "x.example.com"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore).Hours(); d > 26 {
		t.Errorf("validity %v", d)
	}
	p := filepath.Join(dir, "info.json")
	in := Info{TLSPort: s.TLSPort(), HTTPPort: s.HTTPPort(), ControlURL: s.ControlURL(), CertFile: filepath.Join(dir, "cert.pem"), PID: 7}
	if err := WriteInfo(p, in); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadInfo(p); err != nil || got != in {
		t.Fatal(got, err)
	}
}
