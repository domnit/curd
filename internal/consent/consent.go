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
	// KindShutdown asks whether to stop the production daemon, which ends
	// every grant and browser session.
	KindShutdown Kind = "shutdown"
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
	// Policy describes the policy being approved (KindApprovePolicy).
	Policy *PolicySummary
}

// PolicySummary is what an approve dialog shows about a policy: everything
// that widens what curd may send on the user's behalf.
type PolicySummary struct {
	Rules []string // one summary per allow rule
	// Cookies lists the allowed cookie-name patterns; empty with
	// CookiesNone false means all cookies for the policy's hosts.
	Cookies     []string
	CookiesNone bool
	// LocalStorage lists localStorage items used, e.g.
	// "https://app.example.com authToken -> header Authorization".
	LocalStorage    []string
	Redirects       string
	HeaderAllowlist []string // empty means the default allowlist
	DefaultHeaders  []string // the default allowlist, shown when HeaderAllowlist is empty
	ExecInspectors  []string // absolute paths of exec: inspectors
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
