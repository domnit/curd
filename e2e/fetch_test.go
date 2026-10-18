package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/testenv"
)

// The fast core: runs under -short.
func TestSmoke(t *testing.T) {
	e := newEnv(t)
	r := e.fetch(e.base() + "/api/me")
	wantCode(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"user":"alice"`)
	wantContains(t, "stderr", r.stderr, "curd: granted read access to app", "token: crd_", "reuse")
	rs := e.seen("app.example.com", "/api/me")
	if len(rs) != 1 || rs[0].Cookies["session"] != mockup.SessionCookie {
		t.Fatalf("mock saw %+v", rs)
	}
	st := e.curd("status")
	wantCode(t, st, 0)
	wantContains(t, "status", st.stdout, "test mode", "app [active]", "api [active]")
	r = e.fetch(e.base() + "/api/nothing-here")
	wantCode(t, r, 0)
	r = e.fetch(e.base() + "/private")
	wantCode(t, r, 2)
	wantContains(t, "stderr", r.stderr, "curd: denied_path:", "hint:")
}

func TestPolicyEnforcement(t *testing.T) {
	e := newEnv(t)
	// denied_path lists the allowed paths.
	r := e.fetch(e.base() + "/private")
	wantCode(t, r, 2)
	wantContains(t, "denied_path", r.stderr, "denied_path", "^/api/.*$", "^/redirect/.*$")
	// denied_method says a write needs a write rule and grant.
	r = e.fetch("-X", "PUT", e.base()+"/api/me")
	wantCode(t, r, 2)
	wantContains(t, "denied_method", r.stderr, "denied_method", "write grant")
	// POST to a path no write rule allows is denied_path, not sent.
	r = e.fetch("-X", "POST", e.base()+"/api/me", "-d", "x")
	wantCode(t, r, 2)
	wantContains(t, "post denied", r.stderr, "denied_path")
	// No policy for the host.
	r = e.fetch("https://unknown.example.org/x")
	wantCode(t, r, 2)
	wantContains(t, "denied_no_policy", r.stderr, "denied_no_policy", "curd policies ls", "curd policies new <name> --host unknown.example.org")
	r = e.fetch("nosuch", e.base()+"/api/me")
	wantCode(t, r, 2)
	wantContains(t, "unknown policy", r.stderr, "denied_no_policy", "available policies: api, app")
	// The URL must match the named policy.
	r = e.fetch("app", e.api()+"/v1/me")
	wantCode(t, r, 2)
	wantContains(t, "denied_host", r.stderr, "denied_host", "app.example.com")
	// GraphQL: query passes, mutation never reaches the mock.
	r = e.fetch("api", e.api()+"/graphql", "--json-body", `{"query":"query { viewer { login } }"}`)
	wantCode(t, r, 0)
	wantContains(t, "graphql query", r.stdout, `"login":"alice"`)
	r = e.fetch("api", e.api()+"/graphql", "--json-body", `{"query":"mutation DeleteBuild { deleteBuild(id: 1) { id } }","operationName":"DeleteBuild"}`)
	wantCode(t, r, 2)
	wantContains(t, "denied_inspector", r.stderr, "denied_inspector", "graphql_query_only", "hint:")
	if n := len(e.seen("api.example.com", "/graphql")); n != 1 {
		t.Fatalf("the mock saw %d graphql requests; only the query may arrive", n)
	}
	if n := len(e.seen("app.example.com", "/private")) + len(e.seen("unknown.example.org", "")); n != 0 {
		t.Fatalf("denied requests reached the mock")
	}
	// Drafts are inert.
	draft := `name: newsite
status: draft
match: {hosts: [app.example.com]}
allow:
  - {methods: [GET], paths: ['^/api/.*$']}
`
	if err := os.WriteFile(filepath.Join(e.dir, "policies", "newsite.draft.yaml"), []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	r = e.fetch("newsite", e.base()+"/api/me")
	wantCode(t, r, 2)
	wantContains(t, "draft", r.stderr, "denied_no_policy", "curd policies approve newsite")
}

func TestInjectionAndCallerHeaders(t *testing.T) {
	e := newEnv(t)
	// localStorage token injected as Authorization; caller's values dropped.
	r := e.fetch("api", e.api()+"/v1/me", "-H", "Authorization: Bearer evil", "-H", "Cookie: evil=1", "-H", "Host: evil.example.org", "-H", "X-Extra: 1")
	wantCode(t, r, 0)
	wantContains(t, "stdout", r.stdout, `"user":"alice"`)
	rs := e.seen("api.example.com", "/v1/me")
	if len(rs) != 1 {
		t.Fatalf("%+v", rs)
	}
	if got := rs[0].Headers["Authorization"]; len(got) != 1 || got[0] != "Bearer "+mockup.AuthToken {
		t.Fatalf("Authorization = %v", got)
	}
	if len(rs[0].Cookies) != 0 {
		t.Fatalf("api policy must send no cookies, sent %v", rs[0].Cookies)
	}
	if rs[0].Headers["X-Extra"] != nil {
		t.Fatalf("header outside the allowlist was forwarded")
	}
	// Cookie from the fixture; caller cookie dropped on the cookie site too.
	r = e.fetch(e.base()+"/api/me", "-H", "Cookie: session=evil", "-H", "Authorization: Bearer evil")
	wantCode(t, r, 0)
	rs = e.seen("app.example.com", "/api/me")
	if len(rs) != 1 || rs[0].Cookies["session"] != mockup.SessionCookie || len(rs[0].Cookies) != 1 || rs[0].Headers["Authorization"] != nil {
		t.Fatalf("%+v", rs)
	}
	// Browser-like User-Agent, not Go's.
	if ua := rs[0].Headers["User-Agent"]; len(ua) != 1 || !strings.Contains(ua[0], "Chrome/") {
		t.Fatalf("User-Agent = %v", ua)
	}
}

func TestCookieMatchingAndWildcards(t *testing.T) {
	e := newEnv(t)
	e.installPolicies(testenv.ExtraPolicies(portOf(e)))
	// app-all has no cookie allowlist: domain/path/Secure matching decides.
	r := e.fetch("app-all", e.base()+"/api/me")
	wantCode(t, r, 0)
	rs := e.seen("app.example.com", "/api/me")
	if len(rs) != 1 {
		t.Fatalf("%+v", rs)
	}
	c := rs[0].Cookies
	if c["session"] == "" || c["wide"] == "" {
		t.Fatalf("host-only and .example.com domain cookies must be sent: %v", c)
	}
	if _, ok := c["adminonly"]; ok {
		t.Fatalf("path /admin cookie sent to /api/me: %v", c)
	}
	if _, ok := c["elsewhere"]; ok {
		t.Fatalf("cookie of another site sent: %v", c)
	}
	r = e.fetch("app-all", e.base()+"/admin/panel")
	wantCode(t, r, 0)
	rs = e.seen("app.example.com", "/admin/panel")
	if len(rs) != 1 || rs[0].Cookies["adminonly"] == "" {
		t.Fatalf("path cookie not sent under /admin: %+v", rs)
	}
	// Explicit wildcard: subdomains yes; the bare domain and other TLDs no.
	r = e.fetch("wild", e.base()+"/api/me")
	wantCode(t, r, 0)
	r = e.fetch("wild", e.url("example.com", "/api/me"))
	wantCode(t, r, 2)
	wantContains(t, "bare domain", r.stderr, "denied_host", "*.example.com")
	r = e.fetch("wild", e.url("other.example.net", "/collect"))
	wantCode(t, r, 2)
	wantContains(t, "other tld", r.stderr, "denied_host")
	if n := len(e.seen("other.example.net", "")) + len(e.seen("example.com", "")); n != 0 {
		t.Fatalf("hosts outside the wildcard were contacted")
	}
}

func TestRedirects(t *testing.T) {
	e := newEnv(t)
	// Same host: followed, credentials re-applied.
	r := e.fetch(e.base() + "/redirect/same")
	wantCode(t, r, 0)
	wantContains(t, "followed", r.stdout, `"user":"alice"`)
	if rs := e.seen("app.example.com", "/api/me"); len(rs) != 1 || rs[0].Cookies["session"] == "" {
		t.Fatalf("%+v", rs)
	}
	// Another host: not followed; the 302 is shown and nothing is sent there.
	r = e.fetch("-i", e.base()+"/redirect/other")
	wantCode(t, r, 0)
	wantContains(t, "blocked redirect", r.stdout, "HTTP/1.1 302", "Location: ")
	wantContains(t, "note", r.stderr, "redirect not followed", "same-host")
	if n := len(e.seen("other.example.net", "")); n != 0 {
		t.Fatalf("a redirect to another host was followed: the mock saw %d requests", n)
	}
	// policy-hosts: followed to another host of the same policy, with that
	// host's credentials only.
	e.installPolicies(testenv.ExtraPolicies(portOf(e)))
	e.resetMock()
	r = e.fetch("app-follow", e.base()+"/redirect/api")
	wantCode(t, r, 0)
	wantContains(t, "policy-hosts", r.stdout, `"pong":true`)
	rs := e.seen("api.example.com", "/v1/ping")
	if len(rs) != 1 || len(rs[0].Cookies) != 0 || rs[0].Headers["Authorization"][0] != "Bearer "+mockup.AuthToken {
		t.Fatalf("%+v", rs)
	}
	// ... but not to a host outside the policy.
	r = e.fetch("app-follow", e.base()+"/redirect/other")
	wantCode(t, r, 0)
	wantContains(t, "outside policy", r.stderr, "redirect not followed")
	if n := len(e.seen("other.example.net", "")); n != 0 {
		t.Fatalf("followed a redirect to a host outside the policy")
	}
}

func TestAuthRetryAndExpiry(t *testing.T) {
	e := newEnv(t)
	// Flaky: 401 once, then fine after a credential reload.
	r := e.fetch("--json", e.base()+"/api/flaky-auth")
	wantCode(t, r, 0)
	var j struct {
		Status   int    `json:"status"`
		Retried  bool   `json:"retried"`
		BodyText string `json:"body_text"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &j); err != nil {
		t.Fatal(err)
	}
	if j.Status != 200 || !j.Retried || j.BodyText != `{"ok":true}` {
		t.Fatalf("%+v", j)
	}
	if n := len(e.seen("app.example.com", "/api/flaky-auth")); n != 2 {
		t.Fatalf("expected one retry (2 requests), mock saw %d", n)
	}
	// Always 401: auth_expired with a hint, exit 2, exactly one retry.
	r = e.fetch(e.base() + "/api/always-401")
	wantCode(t, r, 2)
	wantContains(t, "auth_expired", r.stderr, "curd: auth_expired:", "log into app.example.com in Chrome")
	if n := len(e.seen("app.example.com", "/api/always-401")); n != 2 {
		t.Fatalf("expected exactly one retry, mock saw %d", n)
	}
}

func TestSetCookieRotation(t *testing.T) {
	e := newEnv(t)
	r := e.fetch("-i", e.base()+"/api/rotate")
	wantCode(t, r, 0)
	wantContains(t, "rotate", r.stdout, `"rotated":true`)
	if strings.Contains(strings.ToLower(r.stdout), "set-cookie") {
		t.Fatalf("Set-Cookie leaked into the output:\n%s", r.stdout)
	}
	// The rotated cookie is now the one in use: /api/me still authenticates
	// even though the mock only accepts the new value.
	r = e.fetch(e.base() + "/api/me")
	wantCode(t, r, 0)
	wantContains(t, "after rotation", r.stdout, `"user":"alice"`)
	rs := e.seen("app.example.com", "/api/me")
	if len(rs) != 1 || rs[0].Cookies["session"] != mockup.RotatedCookie {
		t.Fatalf("rotated cookie not used: %+v", rs)
	}
}

func TestFetchFlags(t *testing.T) {
	e := newEnv(t)
	dir := e.home
	// -o writes the body to a file, nothing to stdout.
	out := filepath.Join(dir, "me.json")
	r := e.fetch("-o", out, e.base()+"/api/me")
	wantCode(t, r, 0)
	if r.stdout != "" {
		t.Fatalf("stdout: %q", r.stdout)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "alice") {
		t.Fatalf("%q", b)
	}
	// -f: exit 22, no body.
	r = e.fetch("-f", e.base()+"/api/missing")
	wantCode(t, r, 22)
	if r.stdout != "" || !strings.Contains(r.stderr, "404") {
		t.Fatalf("%s", r)
	}
	r = e.fetch(e.base() + "/api/missing")
	wantCode(t, r, 0)
	wantContains(t, "404 body", r.stdout, "not found")
	// --json: structured result with body_text and no credentials.
	r = e.fetch("--json", e.base()+"/api/me")
	var j map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &j); err != nil || j["status"].(float64) != 200 || j["policy"] != "app" || !strings.Contains(j["body_text"].(string), "alice") {
		t.Fatalf("%v %s", err, r.stdout)
	}
	// Queries are redacted in the audit log.
	r = e.fetch(e.base() + "/api/items/5?apikey=hunter2")
	wantCode(t, r, 0)
	var sawRedacted bool
	for _, rec := range e.auditRecords() {
		if rec["event"] == "fetch" && rec["path"] == "/api/items/5?<redacted>" {
			sawRedacted = true
		}
		if b, _ := json.Marshal(rec); strings.Contains(string(b), "hunter2") {
			t.Fatalf("query leaked into the audit log: %s", b)
		}
	}
	if !sawRedacted {
		t.Fatal("no redacted audit path")
	}
	// Bad usage.
	r = e.curd("fetch", "not-a-url")
	wantCode(t, r, 1)
	wantContains(t, "usage", r.stderr, "absolute URL")
	r = e.fetch(e.base()+"/api/me", "-H", "broken")
	wantCode(t, r, 1)
}

func TestExplain(t *testing.T) {
	e := newEnv(t)
	// No grant yet: says a dialog would be shown; sends nothing and prompts nothing.
	r := e.fetch("--explain", e.base()+"/api/me")
	wantCode(t, r, 0)
	wantContains(t, "explain", r.stdout, "policy:   app", "scope:    read", "allowed:  no (denied_no_grant)", "consent dialog would be shown", "nothing was sent")
	if n := len(e.seen("", "")); n != 0 {
		t.Fatalf("explain sent %d requests", n)
	}
	if g := e.curd("grants", "ls"); !strings.Contains(g.stdout, "no active grants") {
		t.Fatalf("explain minted a grant: %s", g)
	}
	// Denied by policy.
	r = e.fetch("--explain", e.base()+"/private")
	wantCode(t, r, 0)
	wantContains(t, "explain denied", r.stdout, "allowed:  no (denied_path)", "hint:")
	// With a grant: allowed, names the cookies that would be sent.
	wantCode(t, e.fetch(e.base()+"/api/me"), 0)
	e.resetMock()
	r = e.fetch("--explain", e.base()+"/api/me")
	wantContains(t, "explain allowed", r.stdout, "allowed:  yes", "cookies:  session (names only)", "grant:    gr_")
	if strings.Contains(r.stdout, "SECRET") {
		t.Fatal("explain printed a value")
	}
	r = e.fetch("--explain", "--json", "api", e.api()+"/v1/me")
	var ex struct {
		Allowed  bool     `json:"allowed"`
		Code     string   `json:"code"`
		Injected []string `json:"injected"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &ex); err != nil || ex.Allowed || ex.Code != "denied_no_grant" {
		t.Fatalf("%v %s", err, r.stdout)
	}
	// A write needs its own grant: explain reports that.
	r = e.fetch("--explain", "-X", "POST", e.base()+"/api/upload", "-d", "x")
	wantContains(t, "explain write", r.stdout, "scope:    write", "denied_no_grant")
	if n := len(e.seen("", "")); n != 0 {
		t.Fatalf("explain sent %d requests", n)
	}
}

func TestWriteBody(t *testing.T) {
	e := newEnv(t)
	body := filepath.Join(e.home, "f.bin")
	os.WriteFile(body, []byte("hello upload"), 0o600)
	r := e.fetch("--write", "-X", "POST", e.base()+"/api/upload", "--data-binary", "@"+body)
	wantCode(t, r, 0)
	wantContains(t, "upload", r.stdout, `"uploaded":true`, `"bytes":12`)
	wantContains(t, "granted write", r.stderr, "granted write access to app")
	rs := e.seen("app.example.com", "/api/upload")
	if len(rs) != 1 || rs[0].Body != "hello upload" || rs[0].Method != "POST" {
		t.Fatalf("%+v", rs)
	}
	// stdin body, DELETE needs the write grant that now exists.
	r = e.fetch("-X", "DELETE", e.base()+"/api/items/7")
	wantCode(t, r, 0)
	wantContains(t, "delete", r.stdout, `"deleted":"7"`)
	r = e.exec(nil, "payload from stdin", "fetch", "-X", "POST", e.base()+"/api/upload", "--data-binary", "@-")
	wantCode(t, r, 0)
	wantContains(t, "stdin", r.stdout, `"bytes":18`)
}

func portOf(e *env) int {
	var p int
	for _, c := range e.port {
		p = p*10 + int(c-'0')
	}
	return p
}
