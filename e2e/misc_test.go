package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/chrome"
)

func TestHelpTeachesTheFlow(t *testing.T) {
	e := newEnv(t)
	r := e.curd("--help")
	wantCode(t, r, 0)
	wantContains(t, "root help", strings.ToLower(r.stdout),
		"consent", "read-only", "write grant", "explore", "capture", "distill", "verify", "approve",
		"curd guide", "never", "hint", "fetch", "policies", "exit codes")
	for _, sub := range [][]string{
		{"fetch"}, {"grants"}, {"grants", "request"}, {"grants", "revoke"}, {"policies"}, {"policies", "new"},
		{"policies", "approve"}, {"audit", "tail"}, {"run"}, {"setup"}, {"daemon"}, {"session"}, {"session", "open"},
		{"browse"}, {"browse", "capture"}, {"distill"}, {"distill", "draft"}, {"distill", "verify"}, {"test-env"},
	} {
		r := e.curd(append(sub, "--help")...)
		if r.code != 0 || len(r.stdout) < 150 {
			t.Errorf("curd %s --help is too thin (exit %d):\n%s", strings.Join(sub, " "), r.code, r.stdout)
		}
	}
	// The fetch help documents the flow and the flags an agent will reach for.
	r = e.curd("fetch", "--help")
	wantContains(t, "fetch help", r.stdout, "consent dialog", "write grant", "--explain", "--no-prompt", "--write", "-H", "--data-binary", "auth_expired", "log into")
	// Browse verbs are documented in the help even though they need a session.
	r = e.curd("browse", "--help")
	wantContains(t, "browse help", r.stdout, "click", "type", "screenshot", "waitstable", "capture", "blocked_write", "never expose")
	r = e.curd("distill", "--help")
	wantContains(t, "distill help", r.stdout, "draft", "verify", "status: draft", "approve")
	r = e.curd("browse", "screenshot", "--help")
	wantContains(t, "screenshot help", r.stdout, "-o")
	r = e.curd("test-env", "--help")
	wantContains(t, "test-env help", r.stdout, "CURD_SOCKET", "CURD_TEST_BASE", "allow-all", "script:")
}

func TestGuide(t *testing.T) {
	e := newEnv(t)
	r := e.curd("guide")
	wantCode(t, r, 0)
	if len(r.stdout) < 3000 {
		t.Fatalf("guide is only %d bytes", len(r.stdout))
	}
	wantContains(t, "guide", r.stdout,
		"never", "policy", "grant", "consent", "read", "write", "once", "session", "CURD_SESSION_KEY", "--no-prompt", "--explain",
		"curd run", "curd session open", "curd browse", "capture", "distill", "verify", "approve", "test-env",
		"denied_no_policy", "denied_no_grant", "denied_method", "denied_path", "denied_inspector", "auth_expired", "invalid_token",
		"log into the site in Chrome")
	if strings.Contains(r.stdout, "SECRET") {
		t.Fatal("guide mentions test secrets")
	}
}

func TestErrorsNameTheFix(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name string
		args []string
		code string
		fix  []string
	}{
		{"no policy", []string{"fetch", "https://nobody.example.org/"}, "denied_no_policy", []string{"curd policies new", "curd policies ls"}},
		{"path", []string{"fetch", e.base() + "/zzz"}, "denied_path", []string{"^/api/.*$"}},
		{"method", []string{"fetch", "-X", "PATCH", e.base() + "/api/me"}, "denied_method", []string{"write grant"}},
		{"host", []string{"fetch", "api", e.base() + "/api/me"}, "denied_host", []string{"api.example.com"}},
	}
	for _, c := range cases {
		r := e.curd(c.args...)
		wantCode(t, r, 2)
		wantContains(t, c.name, r.stderr, append([]string{"curd: " + c.code + ":", "hint:"}, c.fix...)...)
	}
	// denied_no_grant: both flavours name `curd grants request`.
	r := e.curd("--no-prompt", "fetch", e.base()+"/api/me")
	wantContains(t, "no grant", r.stderr, "denied_no_grant", "curd grants request app")
	r = e.curd("--no-prompt", "fetch", "--write", e.base()+"/api/upload")
	wantCode(t, r, 2)
	wantContains(t, "no write grant", r.stderr, "curd grants request app --write")
	// Unreachable daemon: exit 3.
	r = e.exec([]string{"CURD_SOCKET=" + filepath.Join(e.home, "nope.sock")}, "", "status")
	wantCode(t, r, 3)
	wantContains(t, "daemon down", r.stderr, "daemon_unreachable", "hint:", "curd daemon")
	// not_available features say what to do.
	r = e.curd("grants", "ls", "--bogus")
	wantCode(t, r, 1)
	wantContains(t, "bad flag", r.stderr, "unknown flag", "hint:")
}

func TestPoliciesCLI(t *testing.T) {
	e := newEnv(t)
	r := e.curd("policies", "ls")
	wantCode(t, r, 0)
	wantContains(t, "ls", r.stdout, "app  [active]  app.example.com", "allow GET,HEAD", "[write]", "inspect=graphql_query_only")
	r = e.curd("policies", "show", "api")
	wantCode(t, r, 0)
	wantContains(t, "show", r.stdout, "name: api", "inject_as", "graphql_query_only")
	if strings.Contains(r.stdout, "SECRET") {
		t.Fatal("policy shows a value")
	}
	r = e.curd("policies", "show", "ghost")
	wantCode(t, r, 1)
	wantContains(t, "show ghost", r.stderr, "not_found", "curd policies ls")

	// new: writes into the test daemon's policy dir, hot-reloaded.
	r = e.curd("policies", "new", "mysite", "--host", "app.example.com", "--host", "*.example.net")
	wantCode(t, r, 0)
	path := strings.TrimSpace(r.stdout)
	if filepath.Dir(path) != filepath.Join(e.dir, "policies") {
		t.Fatalf("policy written to %q", path)
	}
	r = e.curd("policies", "new", "mysite", "--host", "app.example.com")
	wantCode(t, r, 1)
	wantContains(t, "overwrite", r.stderr, "already exists")
	r = e.curd("policies", "validate", path)
	wantCode(t, r, 0)
	wantContains(t, "validate", r.stdout, `ok: policy "mysite"`, "allow GET,HEAD")
	r = e.curd("policies", "ls")
	wantContains(t, "reloaded", r.stdout, "mysite  [active]")
	// Two policies on one host: the caller must name one.
	r = e.fetch(e.base() + "/api/me")
	wantCode(t, r, 1)
	wantContains(t, "ambiguous", r.stderr, "invalid_request", "several policies", "curd fetch <policy> <url>")
	// A broken file shows up as an error, not a crash.
	os.WriteFile(filepath.Join(e.dir, "policies", "broken.yaml"), []byte("name: broken\nmatch: {hosts: []}\n"), 0o600)
	r = e.curd("policies", "ls")
	wantContains(t, "broken", r.stdout, "broken  [error]", "match.hosts")
	r = e.curd("policies", "validate", filepath.Join(e.dir, "policies", "broken.yaml"))
	wantCode(t, r, 1)

	// approve: a draft becomes active only through the (scripted) dialog.
	draft := "name: shiny\nstatus: draft\nmatch: {hosts: [api.example.com]}\nallow:\n  - {methods: [GET], paths: ['^/v1/.*$']}\n"
	os.WriteFile(filepath.Join(e.dir, "policies", "shiny.draft.yaml"), []byte(draft), 0o600)
	r = e.curd("policies", "ls")
	wantContains(t, "draft listed", r.stdout, "shiny  [draft]", "curd policies approve shiny")
	r = e.curd("policies", "approve", "shiny")
	wantCode(t, r, 0)
	wantContains(t, "approved", r.stdout, "approved")
	if _, err := os.Stat(filepath.Join(e.dir, "policies", "shiny.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "policies", "shiny.draft.yaml")); err == nil {
		t.Fatal("draft file not removed")
	}
	r = e.curd("policies", "approve", "shiny")
	wantCode(t, r, 1)
	wantContains(t, "approve twice", r.stderr, "already active")
}

func TestApproveDenied(t *testing.T) {
	e := newEnv(t, "--consent", "deny-all")
	draft := "name: shiny\nstatus: draft\nmatch: {hosts: [api.example.com]}\nallow:\n  - {methods: [GET], paths: ['^/v1/.*$']}\n"
	os.WriteFile(filepath.Join(e.dir, "policies", "shiny.draft.yaml"), []byte(draft), 0o600)
	r := e.curd("policies", "approve", "shiny")
	wantCode(t, r, 2)
	wantContains(t, "denied", r.stderr, "declined")
	if _, err := os.Stat(filepath.Join(e.dir, "policies", "shiny.yaml")); err == nil {
		t.Fatal("policy activated without approval")
	}
}

func TestAuditCLIAndTestTag(t *testing.T) {
	e := newEnv(t)
	e.fetch(e.base() + "/api/me")
	e.fetch(e.base() + "/private")
	r := e.curd("audit", "tail", "-n", "10")
	wantCode(t, r, 0)
	wantContains(t, "audit", r.stdout, "fetch allow app GET app.example.com /api/me status=200", "fetch deny app GET app.example.com /private code=denied_path", "consent allow", "[test]")
	r = e.curd("--json", "audit", "tail", "-n", "100")
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if m["test"] != true {
			t.Fatalf("record not tagged test: %s", line)
		}
		n++
	}
	if n < 4 {
		t.Fatalf("only %d records", n)
	}
	for _, rec := range e.auditRecords() {
		if rec["event"] != "fetch" {
			continue
		}
		for _, k := range []string{"client_pid", "decision", "policy", "method", "host", "path"} {
			if rec[k] == nil {
				t.Errorf("fetch record lacks %s: %v", k, rec)
			}
		}
		for _, bad := range []string{"headers", "body", "cookie", "token"} {
			if _, ok := rec[bad]; ok {
				t.Errorf("audit record has a %s field: %v", bad, rec)
			}
		}
	}
}

func TestIsolation(t *testing.T) {
	e := newEnv(t)
	// A test-mode daemon needs a test config.
	r := e.exec([]string{"CURD_SOCKET="}, "", "daemon", "--test")
	wantCode(t, r, 1)
	wantContains(t, "no config", r.stderr, "--test-config")
	// A production daemon refuses test configuration.
	r = e.exec(nil, "", "daemon", "--test-config", filepath.Join(e.dir, "testenv.yaml"))
	wantCode(t, r, 1)
	wantContains(t, "prod refuses", r.stderr, "only valid together with --test")
	// A test config that points at production locations or a real keychain is refused.
	bad := filepath.Join(e.home, "bad.yaml")
	os.WriteFile(bad, []byte("dir: "+e.home+"/d\nconsent: allow-all\nsource: {kind: chrome, user_data_dir: "+e.home+"/p, key_provider: keychain}\n"), 0o600)
	r = e.exec(nil, "", "daemon", "--test", "--test-config", bad)
	wantCode(t, r, 1)
	wantContains(t, "bad config", r.stderr, "mock")
	// A second daemon on the same socket does not start.
	r = e.exec(nil, "", "daemon", "--test", "--test-config", filepath.Join(e.dir, "testenv.yaml"))
	wantCode(t, r, 1)
	wantContains(t, "second daemon", r.stderr, "another daemon is running")
	// The test daemon is tagged test in status.
	wantContains(t, "status", e.curd("status").stdout, "test mode")
}

func TestDaemonStop(t *testing.T) {
	e := newEnv(t)
	wantCode(t, e.fetch(e.base()+"/api/me"), 0)
	r := e.curd("daemon", "stop")
	wantCode(t, r, 0)
	wantContains(t, "stop", r.stdout, "stopped")
	r = e.curd("status")
	wantCode(t, r, 3)
	r = e.curd("daemon", "stop")
	wantCode(t, r, 0)
	wantContains(t, "stop again", r.stdout, "not running")
	// Credentials and grants died with the daemon; the audit log has the shutdown.
	b, _ := os.ReadFile(filepath.Join(e.dir, "state", "audit.jsonl"))
	wantContains(t, "audit", string(b), `"event":"daemon_stop"`)
}

func TestBrowserCommandsExist(t *testing.T) {
	e := newEnv(t)
	// Until the browser is wired these answer not_available; once wired they
	// need a real session. Either way they must not crash and must not claim
	// to be unknown commands.
	for _, args := range [][]string{
		{"session", "open", "app"}, {"browse", "open", e.base() + "/"}, {"browse", "capture", "list"},
		{"distill", "draft", "x", "c1"}, {"session", "close"},
	} {
		r := e.curd(args...)
		if strings.Contains(r.stderr, "unknown command") {
			t.Errorf("curd %v: %s", args, r)
		}
		if r.code != 0 && !strings.Contains(r.stderr, "curd: ") {
			t.Errorf("curd %v: error without the standard format: %s", args, r)
		}
	}
}

func TestChromeFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("launches Chrome")
	}
	if _, err := chrome.FindBinary(); err != nil {
		t.Skipf("no Chrome/Chromium: %v", err)
	}
	e := newEnv(t, "--fixture", "chrome")
	// Cookies decrypted from a real Chromium profile (mock keychain)...
	r := e.fetch(e.base() + "/api/me")
	wantCode(t, r, 0)
	wantContains(t, "chrome cookies", r.stdout, `"user":"alice"`)
	rs := e.seen("app.example.com", "/api/me")
	if len(rs) != 1 || rs[0].Cookies["session"] != "sess-test-SECRET-1" {
		t.Fatalf("%+v", rs)
	}
	// ... and localStorage read from the LevelDB.
	r = e.fetch("api", e.api()+"/v1/me")
	wantCode(t, r, 0)
	wantContains(t, "chrome localStorage", r.stdout, `"user":"alice"`)
	rs = e.seen("api.example.com", "/v1/me")
	if len(rs) != 1 || rs[0].Headers["Authorization"][0] != "Bearer lsauth-test-SECRET-2" {
		t.Fatalf("%+v", rs)
	}
	st := e.curd("status")
	wantContains(t, "status", st.stdout, "source app: ok")
}
