// Package consent asks the human for permission (spec section 10): a native
// macOS dialog in production and a scripted responder in test mode
// (section 15.4). Dialogs are owned by the daemon so callers cannot drive
// them.
package consent

import (
	"context"
	"time"
)

// Kind identifies what is being asked.
type Kind string

const (
	// KindGrant asks whether to grant a client access to policies.
	KindGrant Kind = "grant"
	// KindApprovePolicy asks whether to accept a new or changed policy.
	KindApprovePolicy Kind = "approve_policy"
)

// Prompt is everything a dialog may show. Fields influenced by callers
// (ClientName, SessionKey, Purpose, Detail) are sanitized before display.
type Prompt struct {
	Kind       Kind
	Policies   []string
	Hosts      []string
	Scope      string // "read" or "write"
	ClientName string
	ClientPID  int
	Duration   time.Duration
	SessionKey string
	Purpose    string
	Detail     string // e.g. "POST /api/upload (412 bytes)"
}

// Answer is the human's decision.
type Answer string

// Possible answers.
const (
	Deny    Answer = "deny"
	Once    Answer = "once"
	Session Answer = "session"
	Approve Answer = "approve"
)

// Prompter shows a prompt and waits for an answer. Implementations return
// Deny together with a non-nil error when no decision could be obtained.
type Prompter interface {
	Ask(ctx context.Context, p Prompt) (Answer, error)
}
