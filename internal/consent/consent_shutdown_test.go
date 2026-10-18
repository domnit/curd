package consent

import (
	"context"
	"strings"
	"testing"
)

func TestShutdownPrompt(t *testing.T) {
	s := BuildScript(Prompt{Kind: KindShutdown, ClientName: `evil" & do shell script "x`, ClientPID: 7})
	if !strings.Contains(s, "Stop the curd daemon?") || !strings.Contains(s, `{"Cancel", "Approve"}`) {
		t.Fatalf("script: %s", s)
	}
	if strings.Contains(s, `evil" &`) {
		t.Fatalf("client name not escaped: %s", s)
	}
	allow, _ := NewScripted("allow-all")
	if a, _ := allow.Ask(context.Background(), Prompt{Kind: KindShutdown}); a != Approve {
		t.Fatalf("allow-all answered %q", a)
	}
}
