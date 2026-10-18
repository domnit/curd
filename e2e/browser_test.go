package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/testenv"
)

// loginPolicy covers the mock app for interactive login: no cookies are ever
// hoisted from the fixture (so the default seed is "login"). The policy has
// no write rule: the login form's POST goes through only during the
// session's login phase.
const loginPolicy = `
name: applogin
match:
  hosts: [app.example.com]
credentials:
  cookies: [no-such-cookie]
allow:
  - methods: [GET]
    paths: ['^/.*$']
test:
  host_map: {app.example.com: 127.0.0.1}
`

func needChrome(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("launches Chrome")
	}
	if _, err := chrome.FindBinary(); err != nil {
		t.Skipf("no Chrome/Chromium: %v", err)
	}
}

// bcurd runs curd and fails the test if anything it printed holds a mock
// credential: every browse/capture/distill output must be redacted.
func (e *env) bcurd(args ...string) result {
	e.t.Helper()
	r := e.curd(args...)
	if strings.Contains(r.stdout, "SECRET") || strings.Contains(r.stderr, "SECRET") {
		e.t.Errorf("curd %v printed a credential:\n%s", args, r)
	}
	return r
}

// openSession runs `curd session open` and returns the session id.
func (e *env) openSession(args ...string) string {
	e.t.Helper()
	r := e.bcurd(append([]string{"session", "open"}, args...)...)
	wantCode(e.t, r, 0)
	id := strings.Fields(r.stdout)[0]
	if !strings.HasPrefix(id, "bs_") {
		e.t.Fatalf("no session id in %q", r.stdout)
	}
	return id
}

func (e *env) browse(args ...string) result {
	e.t.Helper()
	return e.bcurd(append([]string{"browse"}, args...)...)
}

// text runs `browse text <sel>` and returns the trimmed output.
func (e *env) text(sel string) string {
	e.t.Helper()
	r := e.browse("text", sel)
	wantCode(e.t, r, 0)
	return strings.TrimSpace(r.stdout)
}

func (e *env) captures(args ...string) []api.CaptureSummary {
	e.t.Helper()
	r := e.bcurd(append([]string{"--json", "browse", "capture", "list"}, args...)...)
	wantCode(e.t, r, 0)
	var res api.CaptureListResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil {
		e.t.Fatalf("capture list --json: %v\n%s", err, r.stdout)
	}
	return res.Entries
}

// capID returns the id of the last capture of method with a URL ending in suffix.
func capID(t *testing.T, es []api.CaptureSummary, method, suffix string) string {
	t.Helper()
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Method == method && strings.HasSuffix(es[i].URL, suffix) {
			return es[i].ID
		}
	}
	t.Fatalf("no %s ...%s in captures: %+v", method, suffix, es)
	return ""
}

func (e *env) mockPosts(path string) []string {
	var out []string
	for _, r := range e.seen("app.example.com", path) {
		if r.Method == "POST" {
			out = append(out, r.Headers["X-Csrf-Token"]...)
			if len(r.Headers["X-Csrf-Token"]) == 0 {
				out = append(out, "")
			}
		}
	}
	return out
}

func (e *env) profileDirs() []string {
	m, _ := filepath.Glob(filepath.Join(e.dir, "tmp", "curd-browser-*"))
	return m
}

func TestBrowserSessions(t *testing.T) {
	needChrome(t)
	e := newEnv(t)
	e.installPolicies(map[string]string{"applogin.yaml": loginPolicy})

	// Spec 9.2 / 15.6: hoisted cookies and localStorage seed the browser.
	t.Run("hoist seeding", func(t *testing.T) {
		e.resetMock()
		id := e.openSession("app", "api")
		defer e.curd("session", "close", id)
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		if g := e.text("#greeting"); g != "Hello alice" {
			t.Fatalf("greeting = %q", g)
		}
		wantCode(t, e.browse("open", e.base()+"/ls"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		out := e.text("#out")
		wantContains(t, "#out", out, `200 {"id":42,"user":"alice"}`)
		// The page sent the seeded localStorage token to the api origin.
		rs := e.seen("api.example.com", "/v1/me")
		var sent bool
		for _, r := range rs {
			if r.Method == "GET" && len(r.Headers["Authorization"]) == 1 && r.Headers["Authorization"][0] == "Bearer lsauth-test-SECRET-2" {
				sent = true
			}
		}
		if !sent {
			t.Fatalf("api never saw the seeded bearer token: %+v", rs)
		}
		ls := e.bcurd("session", "ls")
		wantContains(t, "session ls", ls.stdout, id, "app,api", "hoist")
		// The session works from a later call that shares only the session key.
		wantContains(t, "url", e.browse("url").stdout, "/ls")
	})

	// Spec 9.3: the origin allowlist.
	t.Run("origin allowlist", func(t *testing.T) {
		e.resetMock()
		e.openSession("app", "api")
		defer e.curd("session", "close")
		r := e.browse("open", e.url("other.example.net", "/collect"))
		wantCode(t, r, 2)
		wantContains(t, "denied", r.stderr, "denied_host", "app.example.com", "api.example.com", "hint:")
		if rs := e.seen("other.example.net", ""); len(rs) != 0 {
			t.Fatalf("mock saw requests to other.example.net: %+v", rs)
		}
	})

	// Spec 16.5: writes are blocked unless the session is a write session.
	t.Run("writes blocked unless granted", func(t *testing.T) {
		e.resetMock()
		e.openSession("app")
		wantCode(t, e.browse("open", e.base()+"/settings"), 0)
		wantCode(t, e.browse("click", "#save"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		wantContains(t, "#result", e.text("#result"), "failed")
		es := e.captures("--method", "POST")
		if len(es) != 1 || !es[0].BlockedWrite || !strings.HasSuffix(es[0].URL, "/api/settings") {
			t.Fatalf("POST captures: %+v", es)
		}
		wantContains(t, "capture table", e.bcurd("browse", "capture", "list", "--method", "POST").stdout, "blocked_write")
		if p := e.mockPosts("/api/settings"); len(p) != 0 {
			t.Fatalf("the mock saw a blocked POST: %v", p)
		}
		wantCode(t, e.curd("session", "close"), 0)

		e.openSession("app", "--write")
		wantCode(t, e.browse("open", e.base()+"/settings"), 0)
		wantCode(t, e.browse("click", "#save"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		wantContains(t, "#result", e.text("#result"), "200", `"saved":true`)
		p := e.mockPosts("/api/settings")
		if len(p) != 1 || !strings.HasPrefix(p[0], "csrf-") {
			t.Fatalf("mock POSTs (csrf header values) = %v", p)
		}
		es = e.captures("--method", "POST")
		if len(es) != 1 || es[0].BlockedWrite || es[0].Status != 200 {
			t.Fatalf("POST captures: %+v", es)
		}
		wantCode(t, e.curd("session", "close"), 0)
	})

	// Spec 16.2: redaction on everything the agent can read.
	t.Run("redaction", func(t *testing.T) {
		e.resetMock()
		e.openSession("app", "api")
		defer e.curd("session", "close")
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		wantCode(t, e.browse("open", e.base()+"/ls"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		es := e.captures()
		me := e.bcurd("browse", "capture", "get", capID(t, es, "GET", "/api/me"))
		wantCode(t, me, 0)
		wantContains(t, "capture get /api/me", me.stdout, "Cookie: session={cookie:session}")
		v1 := e.bcurd("browse", "capture", "get", capID(t, es, "GET", "/v1/me"))
		wantCode(t, v1, 0)
		wantContains(t, "capture get /v1/me", v1.stdout, "Authorization: Bearer {")
		for _, args := range [][]string{
			{"browse", "html", "body"}, {"browse", "capture", "export"}, {"--json", "browse", "capture", "get", capID(t, es, "GET", "/api/me")},
			{"browse", "capture", "find-source", "alice"}, {"browse", "pages"}, {"browse", "url"}, {"browse", "title"},
		} {
			wantCode(t, e.bcurd(args...), 0)
		}
		// A held credential cannot be searched for or learned through find-source.
		r := e.bcurd("browse", "capture", "find-source", "sess-test-SECRET-1")
		wantCode(t, r, 1)
		wantContains(t, "find-source credential", r.stderr, "invalid_request", "held credential")
		png := filepath.Join(e.home, "shot.png")
		wantCode(t, e.bcurd("browse", "screenshot", "-o", png), 0)
		if b, err := os.ReadFile(png); err != nil || len(b) < 100 || string(b[1:4]) != "PNG" {
			t.Fatalf("screenshot: %v (%d bytes)", err, len(b))
		}
	})

	// Spec 16.8: the CSRF flow, from exploration to an approved policy.
	t.Run("explore capture distill verify approve", func(t *testing.T) {
		e.resetMock()
		id := e.openSession("app", "--explore")
		defer e.curd("session", "close")
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		wantCode(t, e.browse("open", e.base()+"/settings"), 0)
		r := e.browse("html", "meta[name=csrf-token]")
		wantCode(t, r, 0)
		token := regexp.MustCompile(`csrf-[0-9a-f]+`).FindString(r.stdout)
		if token == "" {
			t.Fatalf("no csrf token in %q", r.stdout)
		}
		wantCode(t, e.browse("click", "#save"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		wantCode(t, e.browse("open", e.base()+"/api/settings"), 0)

		es := e.captures()
		page := capID(t, es, "GET", e.base()+"/settings")
		src := e.bcurd("browse", "capture", "find-source", token)
		wantCode(t, src, 0)
		wantContains(t, "find-source", src.stdout, page+"  response_body")
		if strings.Contains(src.stdout, capID(t, es, "POST", "/api/settings")+"  response") {
			t.Fatalf("the blocked POST has no response that could have produced the token:\n%s", src.stdout)
		}
		ids := []string{capID(t, es, "GET", "/api/me"), capID(t, es, "GET", "/api/settings"), capID(t, es, "POST", "/api/settings")}

		d := e.bcurd(append([]string{"distill", "draft", "settings"}, ids...)...)
		wantCode(t, d, 0)
		wantContains(t, "draft", d.stdout, "status: draft", "disabled: true", "- POST", "- session", "curd fetch")
		if _, err := os.Stat(filepath.Join(e.dir, "policies", "settings.draft.yaml")); err != nil {
			t.Fatal(err)
		}
		// An inert draft is not usable yet.
		wantCode(t, e.fetch("settings", e.base()+"/api/settings"), 2)

		v := e.bcurd("distill", "verify", "settings", "--minimize")
		wantCode(t, v, 0)
		wantContains(t, "verify", v.stdout, ids[0]+" GET", "ok (captured 200, replay 200)", "skipped: write rule is disabled")
		if p := e.mockPosts("/api/settings"); len(p) != 0 {
			t.Fatalf("verify executed the disabled write: %v", p)
		}

		// The draft is inert until the user approves it (scripted: allow-all).
		wantCode(t, e.bcurd("policies", "approve", "settings"), 0)
		ls := e.bcurd("policies", "ls")
		wantContains(t, "policies ls", ls.stdout, "settings  [active]")
		if _, err := os.Stat(filepath.Join(e.dir, "policies", "settings.draft.yaml")); !os.IsNotExist(err) {
			t.Fatalf("draft file still there: %v", err)
		}
		f := e.fetch("settings", e.base()+"/api/settings")
		wantCode(t, f, 0)
		wantContains(t, "fetch settings", f.stdout, `"theme":"light"`)
		f = e.fetch("settings", e.base()+"/api/me")
		wantCode(t, f, 0)
		wantContains(t, "fetch me", f.stdout, `"user":"alice"`)
		// The write stayed disabled in the approved policy.
		wantCode(t, e.fetch("settings", "-X", "POST", "-d", "{}", e.base()+"/api/settings"), 2)

		var tagged bool
		for _, rec := range e.auditRecords() {
			if rec["event"] == "session_open" && rec["session_id"] == id {
				if tags, _ := rec["tags"].([]any); len(tags) > 0 && tags[0] == "explore" {
					tagged = true
				}
			}
		}
		if !tagged {
			t.Fatal("session_open audit record is not tagged explore")
		}
	})

	// Verify sends credentials to the draft's hosts: the caller's session must cover them.
	t.Run("verify needs coverage", func(t *testing.T) {
		e.resetMock()
		e.installPolicies(map[string]string{"extra.draft.yaml": `
name: extra
status: draft
match:
  hosts: [api.example.com]
allow:
  - methods: [GET]
    paths: ['^/v1/.*$']
`})
		e.openSession("app")
		defer e.curd("session", "close")
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		r := e.bcurd("distill", "verify", "extra", "c1")
		wantCode(t, r, 2)
		wantContains(t, "verify", r.stderr, "denied_no_grant", "api.example.com", "curd session open")
		wantCode(t, e.bcurd("distill", "verify", "nosuch"), 1)
		wantCode(t, e.bcurd("distill", "draft", "app", "c1"), 1) // an active policy has that name
	})

	// Spec 9.2: interactive login mints the session inside the browser.
	t.Run("interactive login", func(t *testing.T) {
		e.resetMock()
		// No hoistable credentials for this policy: the default seed is login.
		r := e.bcurd("session", "open", "applogin", "--login-url", e.base()+"/login")
		wantCode(t, r, 0)
		wantContains(t, "open", r.stdout, "seed login")
		wantContains(t, "open", r.stderr, "browse type")
		defer e.curd("session", "close")
		wantCode(t, e.browse("type", "#username", "alice"), 0)
		wantCode(t, e.browse("type", "#password", "correct horse"), 0)
		wantCode(t, e.browse("click", "#login-button"), 0)
		wantCode(t, e.browse("waitidle"), 0)
		if g := e.text("#greeting"); g != "Hello alice" {
			t.Fatalf("greeting after login = %q", g)
		}
		// The cookie the site minted is now known to the redactor.
		es := e.captures()
		id := capID(t, es, "GET", "/api/me")
		wantContains(t, "capture get", e.bcurd("browse", "capture", "get", id).stdout, "Cookie: session={cookie:session}")
		for _, args := range [][]string{{"browse", "html", "body"}, {"browse", "capture", "export"}} {
			wantCode(t, e.bcurd(args...), 0)
		}
		// The typed password never reaches the capture API: not in the
		// export, the listing, or the login POST's own entry.
		for _, args := range [][]string{{"browse", "capture", "export"}, {"browse", "capture", "get", capID(t, es, "POST", "/login")}, {"browse", "capture", "list"}} {
			if r := e.bcurd(args...); strings.Contains(r.stdout+r.stderr, "horse") {
				t.Fatalf("login password reached %v:\n%s", args, r)
			}
		}
		// Nothing was hoisted: the mock saw no cookie before the login.
		rs := e.seen("app.example.com", "/login")
		if len(rs) == 0 || rs[0].Cookies["session"] != "" {
			t.Fatalf("login page request carried a session cookie: %+v", rs)
		}
		posts := func() (n int) {
			for _, r := range e.seen("app.example.com", "/login") {
				if r.Method == "POST" {
					n++
				}
			}
			return n
		}
		if posts() != 1 {
			t.Fatalf("login POST during the login phase: saw %d", posts())
		}
		wantContains(t, "audit", e.curd("audit", "tail", "-n", "50").stdout, "login_post")
		// Once the login phase ends the session is read-only again.
		wantContains(t, "login done", e.browse("login", "done").stdout, "login phase: closed")
		wantCode(t, e.browse("open", e.base()+"/login"), 0)
		e.browse("click", "#login-button")
		e.browse("waitidle")
		if posts() != 1 {
			t.Fatalf("form POST went through after `login done`: saw %d", posts())
		}
	})

	// A session belongs to the grant that opened it.
	t.Run("ownership", func(t *testing.T) {
		e.resetMock()
		id := e.openSession("app")
		defer e.curd("session", "close")
		r := e.curdKey("someone-else", "browse", "url")
		wantCode(t, r, 1)
		wantContains(t, "other caller", r.stderr, "not_found", "curd session open")
		r = e.curdKey("someone-else", "browse", "--session", id, "url")
		wantCode(t, r, 1)
		wantContains(t, "other caller, explicit id", r.stderr, "not_found")
		wantContains(t, "session ls", e.curdKey("someone-else", "session", "ls").stdout, "no open sessions")
		r = e.curdKey("someone-else", "--token", "crd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "browse", "url")
		wantCode(t, r, 2)
		wantContains(t, "bogus token", r.stderr, "invalid_token")
		wantCode(t, e.browse("url"), 0)
	})

	// Spec 9.4: lifetime.
	t.Run("lifetime", func(t *testing.T) {
		e.resetMock()
		e.openSession("app")
		if n := len(e.profileDirs()); n != 1 {
			t.Fatalf("want one temp profile while the session is open, have %v", e.profileDirs())
		}
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		wantCode(t, e.curd("session", "close"), 0)
		if d := e.profileDirs(); len(d) != 0 {
			t.Fatalf("temp profile survived session close: %v", d)
		}
		r := e.browse("text", "h1")
		wantCode(t, r, 1)
		wantContains(t, "browse after close", r.stderr, "not_found", "curd session open")
		// Captures are dropped with the session.
		wantCode(t, e.browse("capture", "get", "c1"), 1)

		// Revoking the grant closes the session.
		e.openSession("app")
		wantCode(t, e.browse("open", e.base()+"/"), 0)
		wantCode(t, e.bcurd("grants", "revoke", "all"), 0)
		r = e.browse("url")
		if r.code == 0 {
			t.Fatalf("browse worked after the grant was revoked: %s", r)
		}
		if d := e.profileDirs(); len(d) != 0 {
			t.Fatalf("temp profile survived grant revocation: %v", d)
		}
		res, err := testenv.ConsentFailures(e.vars["CURD_SOCKET"])
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Leaks) != 0 || len(res.Failures) != 0 {
			t.Fatalf("leaks %v, consent failures %v", res.Leaks, res.Failures)
		}
	})
}
