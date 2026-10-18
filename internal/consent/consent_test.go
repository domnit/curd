package consent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScriptEscapingInjection(t *testing.T) {
	evil := "x\" & (do shell script \"touch /tmp/pwn\") & \"\nEvil: line\\"
	s := BuildScript(Prompt{
		Kind: KindGrant, Policies: []string{"p"}, Hosts: []string{"a.example"}, Scope: "write",
		ClientName: evil, ClientPID: 42, SessionKey: evil, Purpose: evil, Detail: evil, Duration: time.Hour,
	})
	if strings.ContainsAny(s, "\n\r") {
		t.Fatalf("raw newline in script:\n%s", s)
	}
	// Walk the script: outside string literals only our fixed syntax may appear.
	var outside strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if in {
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				in = false
			}
			continue
		}
		if c == '"' {
			in = true
			continue
		}
		outside.WriteByte(c)
	}
	if in {
		t.Fatal("unterminated string literal")
	}
	if strings.Contains(outside.String(), "shell") || strings.Contains(outside.String(), "touch") {
		t.Fatalf("injected code outside literal: %q", outside.String())
	}
	if !strings.Contains(s, `\"`) || !strings.Contains(s, "pid 42") {
		t.Fatalf("unexpected script: %s", s)
	}
}

func TestScriptContents(t *testing.T) {
	w := BuildScript(Prompt{Kind: KindGrant, Policies: []string{"gh"}, Hosts: []string{"github.com"}, Scope: "write",
		ClientName: "claude", ClientPID: 7, Duration: 90 * time.Minute, SessionKey: "chat1", Purpose: "do it", Detail: "POST /x (4 bytes)"})
	for _, want := range []string{"github.com", "gh", "claude (pid 7)", "Scope: WRITE", "WARNING", `{"Deny", "Allow once", "Allow for 1h30m"}`,
		`default button "Deny"`, `cancel button "Deny"`, "with icon caution", "giving up after 300", "chat1", "do it", "POST /x"} {
		if !strings.Contains(w, want) {
			t.Errorf("missing %q in %s", want, w)
		}
	}
	r := BuildScript(Prompt{Kind: KindGrant, Scope: "read", Duration: time.Hour})
	if strings.Contains(r, "caution") || strings.Contains(r, "WARNING") || !strings.Contains(r, "Scope: read") {
		t.Errorf("read dialog: %s", r)
	}
	a := BuildScript(Prompt{Kind: KindApprovePolicy, Policies: []string{"gh"}})
	if !strings.Contains(a, `{"Cancel", "Approve"}`) {
		t.Errorf("approve dialog: %s", a)
	}
}

func TestSanitizeTruncates(t *testing.T) {
	got := sanitize(strings.Repeat("a", 500)+"\n", 80)
	if len([]rune(got)) > 83 || strings.ContainsAny(got, "\n") {
		t.Fatalf("%q", got)
	}
	if got := sanitize("a\x00b\tc d", 80); got != "a b c d" {
		t.Fatalf("%q", got)
	}
}

func TestParseOutput(t *testing.T) {
	for in, want := range map[string]Answer{
		"button returned:Allow once, gave up:false\n": Once,
		"button returned:Allow for 1h, gave up:false": Session,
		"button returned:Deny, gave up:false":         Deny,
		"button returned:, gave up:true":              Deny,
		"button returned:Allow once, gave up:true":    Deny,
		"button returned:Approve, gave up:false":      Approve,
		"button returned:Cancel, gave up:false":       Deny,
		"garbage":                                     Deny,
	} {
		if got := ParseOutput(in); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}

func TestScriptedModes(t *testing.T) {
	a, err := NewScripted("allow-all")
	if err != nil {
		t.Fatal(err)
	}
	if ans, _ := a.Ask(context.Background(), Prompt{Kind: KindGrant}); ans != Session {
		t.Fatal(ans)
	}
	if ans, _ := a.Ask(context.Background(), Prompt{Kind: KindApprovePolicy}); ans != Approve {
		t.Fatal(ans)
	}
	d, _ := NewScripted("deny-all")
	if ans, _ := d.Ask(context.Background(), Prompt{}); ans != Deny {
		t.Fatal(ans)
	}
	for _, bad := range []string{"", "allow", "script:/nonexistent/x.yaml"} {
		if _, err := NewScripted(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func writeScript(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return "script:" + p
}

func TestScriptFile(t *testing.T) {
	s, err := NewScripted(writeScript(t, `
prompts:
  - expect: {kind: grant, policies: [b, a], scope: write}
    answer: once
  - expect: {kind: approve_policy}
    answer: approve
  - answer: deny
  - expect: {scope: read}
    answer: session
`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if s.Remaining() != 4 {
		t.Fatal(s.Remaining())
	}
	if ans, _ := s.Ask(ctx, Prompt{Kind: KindGrant, Policies: []string{"a", "b"}, Scope: "write"}); ans != Once {
		t.Fatal(ans)
	}
	if ans, _ := s.Ask(ctx, Prompt{Kind: KindApprovePolicy}); ans != Approve {
		t.Fatal(ans)
	}
	if ans, _ := s.Ask(ctx, Prompt{Kind: KindGrant, Scope: "read"}); ans != Deny {
		t.Fatal(ans)
	}
	if len(s.Failures()) != 0 || s.Remaining() != 1 {
		t.Fatalf("failures %v remaining %d", s.Failures(), s.Remaining())
	}
	// Mismatch: expected read, got write -> deny + failure.
	if ans, _ := s.Ask(ctx, Prompt{Kind: KindGrant, Scope: "write", Policies: []string{"x"}}); ans != Deny {
		t.Fatal(ans)
	}
	if f := s.Failures(); len(f) != 1 || !strings.Contains(f[0], "scope") {
		t.Fatalf("%v", f)
	}
	// Exhausted script.
	if ans, _ := s.Ask(ctx, Prompt{Kind: KindGrant}); ans != Deny {
		t.Fatal(ans)
	}
	if f := s.Failures(); len(f) != 2 || !strings.Contains(f[1], "no more prompts") {
		t.Fatalf("%v", f)
	}
	if s.Remaining() != 0 {
		t.Fatal(s.Remaining())
	}
}

func TestScriptFileInvalid(t *testing.T) {
	for _, body := range []string{
		"prompts:\n  - answer: maybe\n",
		"prompts:\n  - expect: {kind: bogus}\n    answer: once\n",
		"prompts:\n  - expect: {nope: 1}\n    answer: once\n",
	} {
		if _, err := NewScripted(writeScript(t, body)); err == nil {
			t.Errorf("should reject %q", body)
		}
	}
}

func TestScriptedConcurrent(t *testing.T) {
	s, _ := NewScripted(writeScript(t, "prompts:\n"+strings.Repeat("  - answer: once\n", 10)))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Ask(context.Background(), Prompt{}) }()
	}
	wg.Wait()
	if len(s.Failures()) != 10 || s.Remaining() != 0 {
		t.Fatalf("failures %d remaining %d", len(s.Failures()), s.Remaining())
	}
}

func TestNativeNonDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("would show a real dialog")
	}
	ans, err := NewNative().Ask(context.Background(), Prompt{Kind: KindGrant})
	if ans != Deny || err == nil {
		t.Fatalf("%s %v", ans, err)
	}
}
