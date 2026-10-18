package daemon_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/daemon"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/rpc"
	"github.com/domnit/curd/internal/source"
	"github.com/domnit/curd/internal/testenv"
)

// tenv is an in-process test-mode daemon with a mock upstream.
type tenv struct {
	t      *testing.T
	dir    string
	mock   *mockup.Server
	d      *daemon.Daemon
	cl     *rpc.Client
	done   chan error
	cancel context.CancelFunc
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func newTenv(t *testing.T, consentSpec string) *tenv {
	t.Helper()
	dir := shortDir(t)
	m, err := mockup.Start(mockup.Options{CertDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if err := testenv.WritePolicies(config.TestPaths(dir).PolicyDir, m.TLSPort()); err != nil {
		t.Fatal(err)
	}
	fix := filepath.Join(dir, "fixture.yaml")
	if err := source.WriteStaticFile(fix, testenv.StaticFixture(m.TLSPort())); err != nil {
		t.Fatal(err)
	}
	tc := &daemon.TestConfig{
		Dir: dir, Consent: consentSpec, CACert: filepath.Join(dir, "cert.pem"),
		Source: daemon.TestSource{Kind: daemon.SourceStatic, File: fix},
	}
	d, err := daemon.New(daemon.Config{Mode: config.ModeTest, Paths: config.TestPaths(dir), Test: tc, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &tenv{t: t, dir: dir, mock: m, d: d, done: make(chan error, 1), cancel: cancel}
	go func() { e.done <- d.Run(ctx) }()
	sock := config.TestPaths(dir).Socket
	for i := 0; i < 200; i++ {
		if e.cl, err = rpc.Dial(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.cl == nil {
		t.Fatalf("daemon did not start: %v", err)
	}
	t.Cleanup(func() {
		e.cl.Close()
		cancel()
		select {
		case <-e.done:
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	return e
}

func (e *tenv) url(host, path string) string {
	return fmt.Sprintf("https://%s:%d%s", host, e.mock.TLSPort(), path)
}

func (e *tenv) fetch(p api.FetchParams) (*api.FetchResult, error) {
	e.t.Helper()
	if p.Method == "" {
		p.Method = "GET"
	}
	var res api.FetchResult
	err := e.cl.Call(context.Background(), api.MethodFetch, p, &res)
	return &res, err
}

func caller(key string) api.Caller { return api.Caller{SessionKey: key, SessionKeySource: "env"} }

func wantCode(t *testing.T, err error, code string) *apierr.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %s, got success", code)
	}
	ae := apierr.As(err)
	if ae.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return ae
}

func TestFetchConsentAndReuse(t *testing.T) {
	e := newTenv(t, "allow-all")
	res, err := e.fetch(api.FetchParams{Caller: caller("k1"), URL: e.url("app.example.com", "/api/me")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.NewToken == "" || res.Granted == nil || res.Granted.Mode != "session" || res.Policy != "app" {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(string(res.Body), "SECRET") {
		t.Fatalf("credential in body")
	}
	// Same session key reuses the grant silently.
	res2, err := e.fetch(api.FetchParams{Caller: caller("k1"), URL: e.url("app.example.com", "/api/me")})
	if err != nil || res2.NewToken != "" || res2.GrantID != res.GrantID {
		t.Fatalf("%+v %v", res2, err)
	}
	// A different key is a different session: prompts again.
	res3, err := e.fetch(api.FetchParams{Caller: caller("k2"), URL: e.url("app.example.com", "/api/me")})
	if err != nil || res3.NewToken == "" || res3.GrantID == res.GrantID {
		t.Fatalf("%+v %v", res3, err)
	}
	// The mock saw the session cookie and nothing else for app.
	rs := e.mock.Requests()
	if len(rs) != 3 || rs[0].Cookies["session"] != mockup.SessionCookie || len(rs[0].Cookies) != 1 {
		t.Fatalf("%+v", rs)
	}
	// An explicit token is honored regardless of the key.
	res4, err := e.fetch(api.FetchParams{Caller: api.Caller{Token: res.NewToken}, URL: e.url("app.example.com", "/api/me")})
	if err != nil || res4.GrantID != res.GrantID {
		t.Fatalf("%+v %v", res4, err)
	}
	// Bad token: invalid_token, no prompt.
	_, err = e.fetch(api.FetchParams{Caller: api.Caller{Token: "crd_" + strings.Repeat("a", 32)}, URL: e.url("app.example.com", "/api/me")})
	wantCode(t, err, apierr.InvalidToken)
}

func TestFetchDenials(t *testing.T) {
	e := newTenv(t, "allow-all")
	c := caller("k")
	_, err := e.fetch(api.FetchParams{Caller: c, URL: "https://unknown.example.org/x"})
	ae := wantCode(t, err, apierr.DeniedNoPolicy)
	if !strings.Contains(ae.Hint, "curd policies new") || !strings.Contains(ae.Hint, "app") {
		t.Fatalf("hint: %q", ae.Hint)
	}
	_, err = e.fetch(api.FetchParams{Caller: c, Policy: "nope", URL: e.url("app.example.com", "/api/me")})
	wantCode(t, err, apierr.DeniedNoPolicy)
	_, err = e.fetch(api.FetchParams{Caller: c, Policy: "app", URL: e.url("api.example.com", "/v1/me")})
	ae = wantCode(t, err, apierr.DeniedHost)
	if !strings.Contains(ae.Hint, "app.example.com") {
		t.Fatalf("hint: %q", ae.Hint)
	}
	_, err = e.fetch(api.FetchParams{Caller: c, URL: e.url("app.example.com", "/secret")})
	ae = wantCode(t, err, apierr.DeniedPath)
	if !strings.Contains(ae.Hint, "^/api/.*$") {
		t.Fatalf("hint: %q", ae.Hint)
	}
	_, err = e.fetch(api.FetchParams{Caller: c, Method: "PUT", URL: e.url("app.example.com", "/api/me")})
	wantCode(t, err, apierr.DeniedMethod)
	_, err = e.fetch(api.FetchParams{Caller: c, URL: "http://app.example.com/api/me"})
	_ = err // plain http is allowed in test mode; the connection simply fails
	_, err = e.fetch(api.FetchParams{Caller: c, URL: "not a url"})
	wantCode(t, err, apierr.InvalidRequest)
	if n := len(e.mock.Requests()); n != 0 {
		t.Fatalf("denied requests reached the mock: %d", n)
	}
}

func TestNoPromptAndExplain(t *testing.T) {
	e := newTenv(t, "allow-all")
	c := caller("k")
	c.NoPrompt = true
	_, err := e.fetch(api.FetchParams{Caller: c, URL: e.url("app.example.com", "/api/me")})
	ae := wantCode(t, err, apierr.DeniedNoGrant)
	if !strings.Contains(ae.Hint, "curd grants request app") {
		t.Fatalf("hint %q", ae.Hint)
	}
	c.NoPrompt = false
	res, err := e.fetch(api.FetchParams{Caller: c, Explain: true, URL: e.url("app.example.com", "/api/me")})
	if err != nil || res.Explain == nil || res.Explain.Allowed || res.Explain.Code != apierr.DeniedNoGrant ||
		!strings.Contains(res.Explain.Reason, "consent dialog would be shown") {
		t.Fatalf("%+v %v", res.Explain, err)
	}
	if _, err := e.fetch(api.FetchParams{Caller: c, URL: e.url("app.example.com", "/api/me")}); err != nil {
		t.Fatal(err)
	}
	before := len(e.mock.Requests())
	res, err = e.fetch(api.FetchParams{Caller: c, Explain: true, URL: e.url("app.example.com", "/api/me")})
	if err != nil || res.Explain == nil || !res.Explain.Allowed || len(res.Explain.Cookies) != 1 || res.Explain.Cookies[0] != "session" {
		t.Fatalf("%+v %v", res.Explain, err)
	}
	res, err = e.fetch(api.FetchParams{Caller: c, Explain: true, URL: e.url("app.example.com", "/nope")})
	if err != nil || res.Explain == nil || res.Explain.Allowed || res.Explain.Code != apierr.DeniedPath {
		t.Fatalf("%+v %v", res.Explain, err)
	}
	if len(e.mock.Requests()) != before {
		t.Fatalf("explain sent a request")
	}
}

func writeScript(t *testing.T, body string) string {
	p := filepath.Join(shortDir(t), "script.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return "script:" + p
}

func failures(t *testing.T, e *tenv) daemon.ConsentFailuresResult {
	t.Helper()
	var r daemon.ConsentFailuresResult
	if err := e.cl.Call(context.Background(), daemon.MethodTestConsentFailures, nil, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScriptedModesAndWrite(t *testing.T) {
	e := newTenv(t, writeScript(t, `
prompts:
  - {expect: {kind: grant, policies: [app], scope: read}, answer: once}
  - {expect: {kind: grant, policies: [app], scope: read}, answer: session}
  - {expect: {kind: grant, policies: [app], scope: write}, answer: deny}
  - {expect: {kind: grant, policies: [app], scope: write}, answer: session}
`))
	c := caller("k")
	get := func() (*api.FetchResult, error) {
		return e.fetch(api.FetchParams{Caller: c, URL: e.url("app.example.com", "/api/me")})
	}
	r1, err := get() // once: consumed
	if err != nil || r1.Granted.Mode != "once" {
		t.Fatalf("%+v %v", r1, err)
	}
	if _, err := get(); err != nil { // prompts again -> session
		t.Fatal(err)
	}
	if _, err := get(); err != nil { // reuses the session grant
		t.Fatal(err)
	}
	post := func() (*api.FetchResult, error) {
		return e.fetch(api.FetchParams{Caller: c, Method: "POST", Body: []byte("x"), URL: e.url("app.example.com", "/api/upload")})
	}
	_, err = post() // write prompt, denied
	ae := wantCode(t, err, apierr.DeniedMethod)
	if !strings.Contains(ae.Hint, "curd grants request app --write") {
		t.Fatalf("hint %q", ae.Hint)
	}
	r, err := post() // write prompt again, session
	if err != nil || r.Status != 200 {
		t.Fatalf("%+v %v", r, err)
	}
	// Revoke everything: next read prompts (script exhausted -> deny + failure).
	var rv api.GrantsRevokeResult
	if err := e.cl.Call(context.Background(), api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: "all"}, &rv); err != nil || len(rv.Revoked) < 2 {
		t.Fatalf("%v %v", rv, err)
	}
	_, err = get()
	wantCode(t, err, apierr.DeniedNoGrant)
	if f := failures(t, e); len(f.Failures) != 1 || !strings.Contains(f.Failures[0], "unexpected prompt") {
		t.Fatalf("%+v", f)
	}
}

func TestConcurrentPromptsCoalesce(t *testing.T) {
	e := newTenv(t, writeScript(t, `
prompts:
  - {expect: {kind: grant, policies: [app], scope: read}, answer: session}
`))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.fetch(api.FetchParams{Caller: caller("same"), URL: e.url("app.example.com", "/api/me")})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f := failures(t, e); len(f.Failures) != 0 || f.Remaining != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestGrantsRequestListRevoke(t *testing.T) {
	e := newTenv(t, "allow-all")
	var rr api.GrantsRequestResult
	err := e.cl.Call(context.Background(), api.MethodGrantsRequest,
		api.GrantsRequestParams{Caller: caller("k"), Policies: []string{"app", "api"}, Scopes: []string{"read", "write"}, TTL: "2h", Purpose: "curd run -- x"}, &rr)
	if err != nil || !strings.HasPrefix(rr.Token, "crd_") || len(rr.Grant.Policies) != 2 || rr.Grant.Scopes[1] != "write" {
		t.Fatalf("%+v %v", rr, err)
	}
	if d := time.Until(rr.Grant.ExpiresAt); d < 119*time.Minute || d > 121*time.Minute {
		t.Fatalf("ttl %v", d)
	}
	err = e.cl.Call(context.Background(), api.MethodGrantsRequest, api.GrantsRequestParams{Policies: []string{"ghost"}}, &rr)
	wantCode(t, err, apierr.DeniedNoPolicy)
	var gl api.GrantsListResult
	if err := e.cl.Call(context.Background(), api.MethodGrantsList, api.GrantsListParams{}, &gl); err != nil || len(gl.Grants) != 1 {
		t.Fatalf("%+v %v", gl, err)
	}
	if err := e.cl.Call(context.Background(), api.MethodGrantsList, api.GrantsListParams{Caller: api.Caller{Token: rr.Token}}, &gl); err != nil || len(gl.Grants) != 1 {
		t.Fatalf("%+v %v", gl, err)
	}
	var rv api.GrantsRevokeResult
	if err := e.cl.Call(context.Background(), api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: rr.Token}, &rv); err != nil || len(rv.Revoked) != 1 {
		t.Fatalf("%+v %v", rv, err)
	}
	err = e.cl.Call(context.Background(), api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: "gr_nothere"}, &rv)
	wantCode(t, err, apierr.NotFound)
	err = e.cl.Call(context.Background(), api.MethodGrantsDerive, map[string]string{}, nil)
	ae := wantCode(t, err, apierr.NotAvailable)
	if !strings.Contains(ae.Hint, "post-v1") {
		t.Fatalf("%v", ae)
	}
	// Browser sessions, capture and distill are wired: with empty params they
	// reject the request instead of answering not_available.
	for m, want := range map[string]string{
		api.MethodOpenSession: apierr.InvalidRequest, api.MethodBrowse: apierr.InvalidRequest,
		api.MethodCaptureList: apierr.NotFound, api.MethodDistillDraft: apierr.InvalidRequest,
	} {
		wantCode(t, e.cl.Call(context.Background(), m, map[string]string{}, nil), want)
	}
}

func TestPolicyReloadAndApprove(t *testing.T) {
	e := newTenv(t, "allow-all")
	pdir := config.TestPaths(e.dir).PolicyDir
	// A new policy file takes effect without a restart.
	extra := testenv.ExtraPolicies(e.mock.TLSPort())
	if err := testenv.WritePolicyFiles(pdir, map[string]string{"app-all.yaml": extra["app-all.yaml"]}); err != nil {
		t.Fatal(err)
	}
	res, err := e.fetch(api.FetchParams{Caller: caller("k"), Policy: "app-all", URL: e.url("app.example.com", "/api/me")})
	if err != nil || res.Policy != "app-all" {
		t.Fatalf("%+v %v", res, err)
	}
	_, err = e.fetch(api.FetchParams{Caller: caller("k"), URL: e.url("app.example.com", "/api/me")})
	wantCode(t, err, apierr.InvalidRequest) // app and app-all now both cover the host

	// Drafts are inert until approved.
	draft := strings.Replace(extra["app-follow.yaml"], "name: app-follow", "name: app-follow\nstatus: draft", 1)
	if err := os.WriteFile(filepath.Join(pdir, "app-follow.draft.yaml"), []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = e.fetch(api.FetchParams{Caller: caller("k"), Policy: "app-follow", URL: e.url("app.example.com", "/api/me")})
	ae := wantCode(t, err, apierr.DeniedNoPolicy)
	if !strings.Contains(ae.Hint, "curd policies approve app-follow") {
		t.Fatalf("hint %q", ae.Hint)
	}
	var st api.PolicyStatus
	if err := e.cl.Call(context.Background(), api.MethodPolicyApprove, api.PolicyApproveParams{Name: "app-follow"}, &st); err != nil || st.Status != "active" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(pdir, "app-follow.draft.yaml")); !os.IsNotExist(err) {
		t.Fatalf("draft file still there")
	}
	var show api.PoliciesShowResult
	if err := e.cl.Call(context.Background(), api.MethodPoliciesShow, api.PoliciesShowParams{Name: "app-follow"}, &show); err != nil ||
		strings.Contains(show.YAML, "status: draft") || show.Status.Status != "active" {
		t.Fatalf("%+v %v", show, err)
	}
	if _, err := e.fetch(api.FetchParams{Caller: caller("k"), Policy: "app-follow", URL: e.url("app.example.com", "/api/me")}); err != nil {
		t.Fatal(err)
	}
	err = e.cl.Call(context.Background(), api.MethodPolicyApprove, api.PolicyApproveParams{Name: "app-follow"}, &st)
	wantCode(t, err, apierr.InvalidRequest)
	err = e.cl.Call(context.Background(), api.MethodPolicyApprove, api.PolicyApproveParams{Name: "../x"}, &st)
	wantCode(t, err, apierr.InvalidRequest)
}

func TestDeniedApproval(t *testing.T) {
	e := newTenv(t, "deny-all")
	pdir := config.TestPaths(e.dir).PolicyDir
	draft := strings.Replace(testenv.ExtraPolicies(e.mock.TLSPort())["app-follow.yaml"], "name: app-follow", "name: app-follow\nstatus: draft", 1)
	os.WriteFile(filepath.Join(pdir, "app-follow.draft.yaml"), []byte(draft), 0o600)
	var st api.PolicyStatus
	err := e.cl.Call(context.Background(), api.MethodPolicyApprove, api.PolicyApproveParams{Name: "app-follow"}, &st)
	wantCode(t, err, apierr.DeniedNoGrant)
	if _, err := os.Stat(filepath.Join(pdir, "app-follow.draft.yaml")); err != nil {
		t.Fatal("draft must stay")
	}
}

func TestStatusAuditAndShutdown(t *testing.T) {
	e := newTenv(t, "allow-all")
	if _, err := e.fetch(api.FetchParams{Caller: caller("k"), URL: e.url("app.example.com", "/api/me")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.fetch(api.FetchParams{Caller: caller("k"), URL: e.url("app.example.com", "/nope")}); err == nil {
		t.Fatal("want denial")
	}
	var st api.StatusResult
	if err := e.cl.Call(context.Background(), api.MethodStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != "test" || st.Grants != 1 || len(st.Policies) != 2 || len(st.Sources) != 1 || st.Sources[0].Cookies != 1 {
		t.Fatalf("%+v", st)
	}
	var at api.AuditTailResult
	if err := e.cl.Call(context.Background(), api.MethodAuditTail, api.AuditTailParams{N: 50}, &at); err != nil {
		t.Fatal(err)
	}
	var sawAllow, sawDeny, sawConsent bool
	for _, r := range at.Records {
		if r["test"] != true {
			t.Fatalf("record not tagged test: %v", r)
		}
		switch {
		case r["event"] == "fetch" && r["decision"] == "allow":
			sawAllow = r["path"] == "/api/me" && r["policy"] == "app" && r["token_hash"] != nil && r["grant_id"] != nil
		case r["event"] == "fetch" && r["decision"] == "deny":
			sawDeny = r["code"] == "denied_path"
		case r["event"] == "consent":
			sawConsent = true
		}
	}
	if !sawAllow || !sawDeny || !sawConsent {
		t.Fatalf("audit records: %v", at.Records)
	}
	b, _ := os.ReadFile(config.TestPaths(e.dir).AuditLog)
	for _, s := range []string{"SECRET", "crd_"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("audit log contains %q:\n%s", s, b)
		}
	}
	if err := e.cl.Call(context.Background(), api.MethodShutdown, nil, nil); err != nil {
		t.Fatal(err)
	}
	var sawShutdown bool
	al, _ := os.ReadFile(config.TestPaths(e.dir).AuditLog)
	for _, ln := range strings.Split(string(al), "\n") {
		if strings.Contains(ln, `"event":"shutdown"`) && strings.Contains(ln, fmt.Sprintf(`"client_pid":%d`, os.Getpid())) {
			sawShutdown = true
		}
	}
	if !sawShutdown {
		t.Fatalf("shutdown not audited with the caller's pid:\n%s", al)
	}
	select {
	case err := <-e.done:
		if err != nil {
			t.Fatal(err)
		}
		e.done <- nil // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
}

func TestHooks(t *testing.T) {
	e := newTenv(t, "allow-all")
	revoked := make(chan string, 4)
	e.d.OnGrantRevoked(func(g *grants.Grant) { revoked <- g.ID })
	shut := make(chan struct{})
	e.d.OnShutdown(func() { close(shut) })
	res, err := e.fetch(api.FetchParams{Caller: caller("k"), URL: e.url("app.example.com", "/api/me")})
	if err != nil {
		t.Fatal(err)
	}
	var rv api.GrantsRevokeResult
	e.cl.Call(context.Background(), api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: res.GrantID}, &rv)
	select {
	case id := <-revoked:
		if id != res.GrantID {
			t.Fatalf("%s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no revoke hook")
	}
	e.cancel()
	e.d.Stop()
	select {
	case <-shut:
	case <-time.After(3 * time.Second):
		t.Fatal("no shutdown hook")
	}
}
