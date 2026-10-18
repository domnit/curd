package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

func consentLines(e *env) []map[string]any {
	var out []map[string]any
	for _, r := range e.auditRecords() {
		if r["event"] == "consent" {
			out = append(out, r)
		}
	}
	return out
}

func TestGrantModesViaScriptedConsent(t *testing.T) {
	script := `
prompts:
  - {expect: {kind: grant, policies: [app], scope: read, session_key: k-once}, answer: once}
  - {expect: {kind: grant, policies: [app], scope: read, session_key: k-once}, answer: session}
  - {expect: {kind: grant, policies: [app], scope: read, session_key: k-two}, answer: session}
  - {expect: {kind: grant, policies: [app], scope: write, session_key: k-two}, answer: deny}
  - {expect: {kind: grant, policies: [app], scope: write, session_key: k-two}, answer: session}
  - {expect: {kind: grant, policies: [app], scope: read, session_key: k-two}, answer: session}
`
	e2 := newEnvWithScript(t, script)
	get := func(key string) result { return e2.curdKey(key, "fetch", e2.base()+"/api/me") }

	// once: this request only; the next call prompts again.
	r := get("k-once")
	wantCode(t, r, 0)
	wantContains(t, "once", r.stderr, "granted read access to app", "once: this request only")
	if strings.Contains(r.stderr, "token:") {
		t.Fatalf("a once grant must not advertise a token: %s", r.stderr)
	}
	r = get("k-once") // second prompt: session
	wantCode(t, r, 0)
	wantContains(t, "session", r.stderr, "session", "token: crd_")
	// The session grant is reused silently by later calls with the same key...
	r = get("k-once")
	wantCode(t, r, 0)
	if strings.Contains(r.stderr, "granted") {
		t.Fatalf("reuse must not prompt or announce a grant: %s", r.stderr)
	}
	// ... but not by a different key.
	r = get("k-two")
	wantCode(t, r, 0)
	wantContains(t, "second key", r.stderr, "granted read access")
	// A write needs a separate prompt, even with a read grant.
	post := func() result {
		return e2.curdKey("k-two", "fetch", "-X", "POST", e2.base()+"/api/upload", "-d", "x")
	}
	r = post()
	wantCode(t, r, 2)
	wantContains(t, "write denied", r.stderr, "denied_method", "curd grants request app --write")
	if n := len(e2.seen("app.example.com", "/api/upload")); n != 0 {
		t.Fatalf("a denied write reached the mock")
	}
	r = post()
	wantCode(t, r, 0)
	wantContains(t, "write granted", r.stderr, "granted write access")
	// Revoke: the next call prompts again (the last scripted prompt).
	r = e2.curdKey("k-two", "grants", "revoke", "all")
	wantCode(t, r, 0)
	wantContains(t, "revoke", r.stdout, "revoked gr_")
	r = get("k-two")
	wantCode(t, r, 0)
	wantContains(t, "after revoke", r.stderr, "granted read access")

	// Every prompt was consumed exactly as scripted: the audit log has them.
	if n := len(consentLines(e2)); n != 6 {
		t.Fatalf("expected 6 consent outcomes, got %d", n)
	}
}

func newEnvWithScript(t *testing.T, script string) *env {
	t.Helper()
	// The script file must exist before `up`, so it lives in a separate dir.
	dir := tempDir(t, "cs")
	p := dir + "/s.yaml"
	if err := writeFile(p, script); err != nil {
		t.Fatal(err)
	}
	return newEnv(t, "--consent", "script:"+p)
}

func TestDenyAndNoPrompt(t *testing.T) {
	e := newEnv(t, "--consent", "deny-all")
	r := e.fetch(e.base() + "/api/me")
	wantCode(t, r, 2)
	wantContains(t, "deny", r.stderr, "curd: denied_no_grant:", "hint:", "curd grants request app")
	if n := len(e.seen("", "")); n != 0 {
		t.Fatal("request sent without a grant")
	}
	r = e.curd("--no-prompt", "fetch", e.base()+"/api/me")
	wantCode(t, r, 2)
	wantContains(t, "no-prompt", r.stderr, "denied_no_grant", "--no-prompt", "curd grants request app")
	r = e.curd("--no-prompt", "grants", "request", "app")
	wantCode(t, r, 2)
	wantContains(t, "grants request", r.stderr, "denied_no_grant")
	// --json errors are objects.
	r = e.curd("--json", "fetch", e.base()+"/api/me")
	wantCode(t, r, 2)
	var ae struct{ Code, Message, Hint string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.stderr)), &ae); err != nil || ae.Code != "denied_no_grant" || ae.Hint == "" {
		t.Fatalf("%v: %q", err, r.stderr)
	}
	// Nothing was ever consented to.
	if g := e.curd("grants", "ls"); !strings.Contains(g.stdout, "no active grants") {
		t.Fatal(g.stdout)
	}
}

func TestTokensAndNoPromptWithGrant(t *testing.T) {
	e := newEnv(t)
	r := e.curdKey("k-a", "grants", "request", "app", "--ttl", "2h")
	wantCode(t, r, 0)
	tok := strings.TrimSpace(r.stdout)
	if !strings.HasPrefix(tok, "crd_") || strings.Contains(tok, "\n") {
		t.Fatalf("stdout must be the bare token: %q", r.stdout)
	}
	wantContains(t, "stderr", r.stderr, "granted read access to app", "--token")
	// Another session key can use the grant explicitly, with --token or CURD_TOKEN.
	r = e.curdKey("k-b", "--no-prompt", "fetch", "--token", tok, e.base()+"/api/me")
	wantCode(t, r, 0)
	r = e.exec([]string{"CURD_SESSION_KEY=k-c", "CURD_TOKEN=" + tok}, "", "--no-prompt", "fetch", e.base()+"/api/me")
	wantCode(t, r, 0)
	// ... but without it that key has no grant.
	r = e.curdKey("k-c", "--no-prompt", "fetch", e.base()+"/api/me")
	wantCode(t, r, 2)
	// The token does not cover an unrelated policy.
	r = e.curdKey("k-b", "--token", tok, "--no-prompt", "fetch", e.api()+"/v1/me")
	wantCode(t, r, 2)
	wantContains(t, "uncovered", r.stderr, "denied_no_grant", "curd grants request api")
	// grants ls shows the grant but never the token.
	g := e.curd("grants", "ls")
	wantContains(t, "grants ls", g.stdout, "gr_", "app", "k-a (env)", "session")
	if strings.Contains(g.stdout, tok) || strings.Contains(g.stdout, "crd_") {
		t.Fatalf("grants ls printed a token:\n%s", g.stdout)
	}
	g = e.curd("--json", "grants", "ls", "--token", tok)
	var gl struct {
		Grants []struct {
			ID       string
			Policies []string
		}
	}
	if err := json.Unmarshal([]byte(g.stdout), &gl); err != nil || len(gl.Grants) != 1 {
		t.Fatalf("%v %s", err, g.stdout)
	}
	// Revoke by token; the token is then invalid_token (not a new prompt).
	r = e.curd("grants", "revoke", tok)
	wantCode(t, r, 0)
	r = e.curdKey("k-b", "fetch", "--token", tok, e.base()+"/api/me")
	wantCode(t, r, 2)
	wantContains(t, "revoked token", r.stderr, "invalid_token", "hint:")
	r = e.curd("grants", "revoke", "gr_doesnotexist")
	wantCode(t, r, 1)
	wantContains(t, "revoke unknown", r.stderr, "not_found", "curd grants ls")
}

func TestRunCommand(t *testing.T) {
	e := newEnv(t)
	r := e.curd("run", "--policy", "app", "--", "sh", "-c",
		`echo "token=$CURD_TOKEN"; curd_bin="$0"; "$0" --no-prompt fetch "$CURD_TEST_BASE/api/me"; exit 7`, curdBin)
	// sh -c script receives curdBin as $0.
	if r.code != 7 {
		t.Fatalf("curd run must exit with the child's code: %s", r)
	}
	wantContains(t, "child", r.stdout, "token=crd_", `"user":"alice"`)
	// The grant was revoked when the command ended.
	g := e.curd("grants", "ls")
	if !strings.Contains(g.stdout, "no active grants") {
		t.Fatalf("grant outlived curd run:\n%s", g.stdout)
	}
	// Without a policy it explains itself.
	r = e.curd("run", "--", "true")
	wantCode(t, r, 1)
	wantContains(t, "run usage", r.stderr, "--policy")
	r = e.curd("run", "--policy", "app")
	wantCode(t, r, 1)
	wantContains(t, "run dash", r.stderr, "after --")
	// A run grant is not shared with other processes through the session key.
	r = e.curd("run", "--policy", "app", "--", "sh", "-c", `"$0" --no-prompt fetch "$CURD_TEST_BASE/api/me" -s >/dev/null; echo done`, curdBin)
	wantCode(t, r, 0)
}

func TestTestEnvRunReportsScriptViolations(t *testing.T) {
	e := newEnv(t) // just for the harness; test-env run makes its own env
	dir := tempDir(t, "cr")
	script := dir + "/s.yaml"
	if err := writeFile(script, "prompts: []\n"); err != nil {
		t.Fatal(err)
	}
	// The command makes a fetch that prompts; the script allows no prompts.
	r := e.exec([]string{"CURD_TEST_DIR="}, "", "test-env", "run", "--dir", dir+"/t", "--consent", "script:"+script, "--",
		"sh", "-c", `"$0" fetch "$CURD_TEST_BASE/api/me" >/dev/null 2>&1; echo child-done`, curdBin)
	if r.code == 0 {
		t.Fatalf("a violated consent script must fail the run: %s", r)
	}
	wantContains(t, "violation", r.stderr, "consent script was violated", "unexpected prompt")
	wantContains(t, "child ran", r.stdout, "child-done")
	// Success path: the child's code is returned and the env is gone.
	r = e.exec(nil, "", "test-env", "run", "--dir", dir+"/t2", "--", "sh", "-c", `"$0" fetch "$CURD_TEST_BASE/api/me" && exit 3`, curdBin)
	wantCode(t, r, 3)
	wantContains(t, "run output", r.stdout, `"user":"alice"`)
	if _, err := statDir(dir + "/t2"); err == nil {
		t.Fatal("test-env run left its directory behind")
	}
}
