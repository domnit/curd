package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/policy"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Run(context.Background(), args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestRootHelpExplainsTheFlow(t *testing.T) {
	code, out, _ := run(t, "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"consent", "read-only", "write grant", "explore", "capture", "distill", "verify", "approve",
		"never", "curd guide", "hint", "policy", "fetch", "denied"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("root help lacks %q", want)
		}
	}
}

func TestEverySubcommandHasLongHelp(t *testing.T) {
	root := newRoot(&globals{})
	var check func(c *cobra.Command, path string)
	check = func(c *cobra.Command, path string) {
		if !c.Hidden && c.Short == "" {
			t.Errorf("%s: no Short", path)
		}
		if !c.Hidden && len(c.Long) < 20 {
			t.Errorf("%s: no Long description", path)
		}
		for _, s := range c.Commands() {
			check(s, path+" "+s.Name())
		}
	}
	for _, c := range root.Commands() {
		check(c, c.Name())
	}
}

func TestGuideMentionsKeyConcepts(t *testing.T) {
	code, out, _ := run(t, "guide")
	if code != 0 || len(out) < 2000 {
		t.Fatalf("guide too short (%d bytes, exit %d)", len(out), code)
	}
	for _, want := range []string{"POLICY", "GRANT", "write", "once", "session key", "CURD_SESSION_KEY", "--no-prompt", "--explain",
		"explore", "capture", "distill", "verify", "approve", "denied_no_grant", "denied_method", "denied_path", "denied_inspector",
		"auth_expired", "log into", "test-env", "browse", "curd run"} {
		if !strings.Contains(out, want) {
			t.Errorf("guide lacks %q", want)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	code, _, errs := run(t, "fetch")
	if code != ExitError || !strings.Contains(errs, "usage") {
		t.Fatalf("%d %q", code, errs)
	}
	code, _, errs = run(t, "nope")
	if code != ExitError || !strings.Contains(errs, "hint:") {
		t.Fatalf("%d %q", code, errs)
	}
	code, _, errs = run(t, "--json", "fetch")
	if code != ExitError || !strings.HasPrefix(errs, "{") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestExitCodes(t *testing.T) {
	for code, want := range map[string]int{
		apierr.DeniedNoGrant: ExitDenied, apierr.DeniedPath: ExitDenied, apierr.InvalidToken: ExitDenied,
		apierr.AuthExpired: ExitDenied, apierr.DaemonDown: ExitUnreachable, apierr.UpstreamError: ExitError,
		apierr.NotAvailable: ExitError,
	} {
		if got := codeFor(apierr.New(code, "m", "")); got != want {
			t.Errorf("%s: %d want %d", code, got, want)
		}
	}
	if codeFor(errors.New("x")) != ExitError {
		t.Error("plain errors exit 1")
	}
}

func TestPrintError(t *testing.T) {
	var b bytes.Buffer
	printError(&b, apierr.New(apierr.DeniedPath, "nope", "try /api"), false)
	if b.String() != "curd: denied_path: nope\nhint: try /api\n" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	printError(&b, apierr.New(apierr.DeniedPath, "nope", "try /api"), true)
	if !strings.Contains(b.String(), `"code":"denied_path"`) || !strings.Contains(b.String(), `"hint":"try /api"`) {
		t.Fatalf("%q", b.String())
	}
}

func TestSessionKeyOrder(t *testing.T) {
	t.Chdir(t.TempDir()) // not inside a git repository
	t.Setenv("CURD_SESSION_KEY", "")
	if k, s := resolveSessionKey(""); s == "git" {
		t.Fatalf("unexpected git key %q", k)
	}
	if k, s := resolveSessionKey("flagval"); k != "flagval" || s != "flag" {
		t.Fatalf("%q %q", k, s)
	}
	t.Setenv("CURD_SESSION_KEY", "envval")
	if k, s := resolveSessionKey("flagval"); k != "envval" || s != "env" {
		t.Fatalf("env must beat the flag: %q %q", k, s)
	}
}

func TestPolicyTemplateIsValidAndReadOnly(t *testing.T) {
	p, err := policy.Parse([]byte(policyTemplate("demo", []string{"app.example.com", "*.example.org"})), "demo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) != 1 || p.Allow[0].EffectiveScope() != "read" || strings.Join(p.Allow[0].Methods, ",") != "GET,HEAD" {
		t.Fatalf("%+v", p.Allow)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings: %v", p.Warnings)
	}
}

func TestPoliciesNewRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := run(t, "policies", "new", "demo", "--host", "app.example.com", "--dir", dir)
	if code != 0 || !strings.HasSuffix(strings.TrimSpace(out), "demo.yaml") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, _, errs = run(t, "policies", "new", "demo", "--host", "app.example.com", "--dir", dir)
	if code == 0 || !strings.Contains(errs, "already exists") {
		t.Fatalf("%d %q", code, errs)
	}
	code, out, _ = run(t, "policies", "validate", strings.TrimSpace(strings.Split(out, "\n")[0]))
	if code != 0 || !strings.Contains(out, "ok: policy") {
		t.Fatalf("%d %q", code, out)
	}
	code, _, errs = run(t, "policies", "new", "bad", "--host", "http://nope", "--dir", dir)
	if code == 0 {
		t.Fatalf("invalid host accepted: %q", errs)
	}
}

func TestParseHeadersAndBody(t *testing.T) {
	hs, err := parseHeaders([]string{"Accept: application/json", "X-A:b"})
	if err != nil || len(hs) != 2 || hs[1].Name != "X-A" || hs[1].Value != "b" {
		t.Fatalf("%+v %v", hs, err)
	}
	if _, err := parseHeaders([]string{"nocolon"}); err == nil {
		t.Fatal("want error")
	}
}
