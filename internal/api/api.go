// Package api defines the JSON-RPC 2.0 method names and parameter/result
// types shared by the curd daemon and its clients (spec section 7.2).
//
// No type in this package may carry a credential value. Session tokens
// (crd_...) are socket capabilities, not site credentials, and may appear.
package api

import "time"

// Method names.
const (
	MethodStatus        = "status"
	MethodFetch         = "fetch"
	MethodGrantsRequest = "grants.request"
	MethodGrantsList    = "grants.list"
	MethodGrantsRevoke  = "grants.revoke"
	MethodGrantsDerive  = "grants.derive" // post-v1: returns not_available
	MethodPoliciesList  = "policies.list"
	MethodPoliciesShow  = "policies.show"
	MethodPolicyApprove = "policies.approve"
	MethodAuditTail     = "audit.tail"
	MethodOpenSession   = "open_session"
	MethodCloseSession  = "close_session"
	MethodBrowse        = "browse"
	MethodCaptureList   = "capture.list"
	MethodCaptureGet    = "capture.get"
	MethodCaptureFind   = "capture.find_source"
	MethodCaptureExport = "capture.export"
	MethodDistillDraft  = "distill.draft"
	MethodDistillVerify = "distill.verify"
	MethodShutdown      = "shutdown" // test mode and `curd daemon stop`
)

// Caller identifies who a call is for. The daemon adds the peer pid/uid from
// the socket itself; nothing here is trusted for authorization except Token,
// which is looked up server-side.
type Caller struct {
	Token      string `json:"token,omitempty"`       // crd_...; from --token or CURD_TOKEN
	SessionKey string `json:"session_key,omitempty"` // grouping label (spec 6.3); "" means uid-global
	// SessionKeySource says how the client derived SessionKey: "env",
	// "flag", "git", "tty" or "" (none). Shown in consent and grants ls.
	SessionKeySource string `json:"session_key_source,omitempty"`
	// NoPrompt makes a call fail with denied_no_grant instead of opening a
	// consent dialog.
	NoPrompt bool `json:"no_prompt,omitempty"`
}

// Header is one request or response header line. A list keeps order and
// duplicates.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// FetchParams: fetch(token, policy, method, url, headers?, body?).
type FetchParams struct {
	Caller
	Policy  string   `json:"policy,omitempty"` // optional; resolved by host if empty
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []Header `json:"headers,omitempty"`
	Body    []byte   `json:"body,omitempty"`
	Explain bool     `json:"explain,omitempty"` // dry run: decide, do not send
	Write   bool     `json:"write,omitempty"`   // caller asks for write scope up front
}

// FetchResult is {status, headers, body, truncated} plus curd metadata.
type FetchResult struct {
	Status    int      `json:"status"`
	Headers   []Header `json:"headers"`
	Body      []byte   `json:"body"`
	Truncated bool     `json:"truncated"`
	URL       string   `json:"url"` // final URL after allowed redirects
	Policy    string   `json:"policy"`
	GrantID   string   `json:"grant_id"`
	// NewToken is set when this call ran consent and minted a grant.
	NewToken string   `json:"new_token,omitempty"`
	Explain  *Explain `json:"explain,omitempty"`
}

// Explain is the dry-run report for fetch --explain.
type Explain struct {
	Policy   string   `json:"policy"`
	Rule     string   `json:"rule,omitempty"` // which allow rule matched, e.g. "allow[1] POST ^/graphql$"
	Scope    string   `json:"scope"`          // read or write
	GrantID  string   `json:"grant_id,omitempty"`
	Allowed  bool     `json:"allowed"`
	Code     string   `json:"code,omitempty"` // denial code if not allowed
	Reason   string   `json:"reason"`
	Hint     string   `json:"hint,omitempty"`
	Cookies  []string `json:"cookies,omitempty"`  // names that would be injected
	Injected []string `json:"injected,omitempty"` // header names that would be injected
}

// GrantsRequestParams: grants.request(policy[], scopes, ttl).
type GrantsRequestParams struct {
	Caller
	Policies []string `json:"policies"`
	Scopes   []string `json:"scopes"`            // "read", "write"; default read
	TTL      string   `json:"ttl,omitempty"`     // Go duration; default policy ttl_default
	Mode     string   `json:"mode,omitempty"`    // "once" or "session"; default session
	Purpose  string   `json:"purpose,omitempty"` // shown in the dialog, e.g. "curd run -- make test"
}

// GrantsRequestResult returns the new token. The token is shown once.
type GrantsRequestResult struct {
	Token string    `json:"token"`
	Grant GrantInfo `json:"grant"`
}

// GrantInfo describes a grant without its token.
type GrantInfo struct {
	ID               string    `json:"id"` // gr_...; safe to show, used by revoke
	TokenHash        string    `json:"token_hash"`
	Policies         []string  `json:"policies"`
	Scopes           []string  `json:"scopes"`
	Mode             string    `json:"mode"`
	SessionKey       string    `json:"session_key,omitempty"`
	SessionKeySource string    `json:"session_key_source,omitempty"`
	ClientPID        int       `json:"client_pid,omitempty"`
	ClientExe        string    `json:"client_exe,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`      // absolute max
	IdleExpiresAt    time.Time `json:"idle_expires_at"` // extended on each use
	Uses             int       `json:"uses"`
	Test             bool      `json:"test,omitempty"`
}

// GrantsListParams: grants.list(token?). With no token, lists all grants for
// this uid.
type GrantsListParams struct {
	Caller
}

// GrantsListResult lists grants.
type GrantsListResult struct {
	Grants []GrantInfo `json:"grants"`
}

// GrantsRevokeParams: grants.revoke(token_or_id). "all" revokes every grant.
type GrantsRevokeParams struct {
	TokenOrID string `json:"token_or_id"`
}

// GrantsRevokeResult reports how many grants were revoked.
type GrantsRevokeResult struct {
	Revoked []string `json:"revoked"` // grant ids
}

// StatusResult: status(). Policy names only, never values.
type StatusResult struct {
	Version  string         `json:"version"`
	Mode     string         `json:"mode"` // prod or test
	PID      int            `json:"pid"`
	Socket   string         `json:"socket"`
	Started  time.Time      `json:"started"`
	Policies []PolicyStatus `json:"policies"`
	Sources  []SourceStatus `json:"sources"`
	Grants   int            `json:"grants"`
	Sessions int            `json:"sessions"`
	Keychain string         `json:"keychain,omitempty"` // prompt, always-allow, strict, mock, static
}

// PolicyStatus summarizes one policy file.
type PolicyStatus struct {
	Name   string   `json:"name"`
	File   string   `json:"file"`
	Status string   `json:"status"` // active, draft, error
	Hosts  []string `json:"hosts,omitempty"`
	Rules  []string `json:"rules,omitempty"` // e.g. "GET,HEAD ^/api/.*", "POST ^/graphql$ [graphql_query_only]"
	Error  string   `json:"error,omitempty"`
}

// SourceStatus summarizes a credential source.
type SourceStatus struct {
	Name     string    `json:"name"`
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	LastLoad time.Time `json:"last_load,omitempty"`
	Profile  string    `json:"profile,omitempty"`
	// Counts only, never values.
	Cookies      int `json:"cookies"`
	LocalStorage int `json:"local_storage"`
}

// PoliciesListResult lists policies, including drafts.
type PoliciesListResult struct {
	Policies []PolicyStatus `json:"policies"`
}

// PoliciesShowParams names a policy.
type PoliciesShowParams struct {
	Name string `json:"name"`
}

// PoliciesShowResult returns a policy's YAML source.
type PoliciesShowResult struct {
	Status PolicyStatus `json:"status"`
	YAML   string       `json:"yaml"`
}

// PolicyApproveParams activates a draft after native confirmation.
type PolicyApproveParams struct {
	Name string `json:"name"`
}

// AuditTailParams asks for the last N audit records.
type AuditTailParams struct {
	N int `json:"n"`
}

// AuditTailResult returns raw audit records.
type AuditTailResult struct {
	Records []map[string]any `json:"records"`
}

// OpenSessionParams: open_session(token, policy[], ttl, allow_writes?).
type OpenSessionParams struct {
	Caller
	Policies    []string `json:"policies"`
	TTL         string   `json:"ttl,omitempty"`
	AllowWrites bool     `json:"allow_writes,omitempty"`
	// Seed is "login" (interactive login, preferred) or "hoist" (seed from
	// credential sources). Default "hoist" when a profile has credentials
	// for the policy, else "login".
	Seed     string `json:"seed,omitempty"`
	LoginURL string `json:"login_url,omitempty"` // first page for interactive login
	Explore  bool   `json:"explore,omitempty"`   // tag audit records "explore"
}

// OpenSessionResult returns {session_id, expires_at}. No CDP endpoint.
type OpenSessionResult struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Seed      string    `json:"seed"`
	NewToken  string    `json:"new_token,omitempty"`
}

// CloseSessionParams: close_session(token, session_id). Empty SessionID
// closes the caller's most recent session.
type CloseSessionParams struct {
	Caller
	SessionID string `json:"session_id,omitempty"`
}

// BrowseParams: browse(token, verb, args).
type BrowseParams struct {
	Caller
	SessionID string   `json:"session_id,omitempty"` // default: caller's most recent session
	Verb      string   `json:"verb"`
	Args      []string `json:"args,omitempty"`
}

// BrowseResult is a verb's output, already redacted. Text is the primary
// human-readable output; Data is structured output for --json; PNG is set by
// screenshot.
type BrowseResult struct {
	Text string `json:"text,omitempty"`
	Data any    `json:"data,omitempty"`
	PNG  []byte `json:"png,omitempty"`
}

// CaptureFilter narrows capture.list.
type CaptureFilter struct {
	Method      string `json:"method,omitempty"`
	URLContains string `json:"url_contains,omitempty"`
	Type        string `json:"type,omitempty"` // resource type: Document, XHR, Fetch, Script...
	Host        string `json:"host,omitempty"`
	Status      int    `json:"status,omitempty"`
}

// CaptureListParams: capture.list(session_id, filter?).
type CaptureListParams struct {
	Caller
	SessionID string        `json:"session_id,omitempty"`
	Filter    CaptureFilter `json:"filter"`
}

// CaptureSummary is one row of capture.list.
type CaptureSummary struct {
	ID           string `json:"id"` // c<N>, unique within the daemon
	Method       string `json:"method"`
	URL          string `json:"url"` // redacted
	Status       int    `json:"status"`
	ResourceType string `json:"resource_type"`
	Size         int    `json:"size"`
	Initiator    string `json:"initiator,omitempty"` // "parser https://...", "script https://...:12", "other"
	BlockedWrite bool   `json:"blocked_write,omitempty"`
	Blocked      string `json:"blocked,omitempty"` // reason if curd blocked it (host, write)
}

// CaptureListResult lists captured requests.
type CaptureListResult struct {
	Entries []CaptureSummary `json:"entries"`
}

// CaptureGetParams: capture.get(id, parts?). Parts: request_headers,
// request_body, response_headers, response_body. Empty means all.
type CaptureGetParams struct {
	Caller
	ID    string   `json:"id"`
	Parts []string `json:"parts,omitempty"`
}

// CaptureDetail is one redacted request/response.
type CaptureDetail struct {
	CaptureSummary
	RequestHeaders  []Header `json:"request_headers,omitempty"`
	RequestBody     string   `json:"request_body,omitempty"`
	ResponseHeaders []Header `json:"response_headers,omitempty"`
	ResponseBody    string   `json:"response_body,omitempty"`
	BodyTruncated   bool     `json:"body_truncated,omitempty"`
	BodyBase64      bool     `json:"body_base64,omitempty"`
}

// CaptureFindParams: capture.find_source(session_id, value).
type CaptureFindParams struct {
	Caller
	SessionID string `json:"session_id,omitempty"`
	Value     string `json:"value"`
}

// CaptureSource is one place a value appeared.
type CaptureSource struct {
	ID       string `json:"id"`
	Location string `json:"location"` // response_body, response_header:<name>, url, request_body, page
	Context  string `json:"context"`  // short redacted snippet around the match
}

// CaptureFindResult lists sources, earliest first.
type CaptureFindResult struct {
	Sources []CaptureSource `json:"sources"`
}

// CaptureExportParams: capture.export(session_id, ids[]). Empty ids = all.
type CaptureExportParams struct {
	Caller
	SessionID string   `json:"session_id,omitempty"`
	IDs       []string `json:"ids,omitempty"`
}

// CaptureExportResult is a redacted HAR 1.2 document.
type CaptureExportResult struct {
	HAR map[string]any `json:"har"`
}

// DistillDraftParams: distill.draft(session_id, ids[]).
type DistillDraftParams struct {
	Caller
	SessionID string   `json:"session_id,omitempty"`
	IDs       []string `json:"ids"`
	Name      string   `json:"name"` // policy name for the draft
}

// DistillDraftResult returns the draft policy and curd fetch commands. The
// draft is saved to <policy dir>/<name>.draft.yaml with status: draft.
type DistillDraftResult struct {
	Name     string   `json:"name"`
	Path     string   `json:"path"`
	YAML     string   `json:"yaml"`
	Commands []string `json:"commands"`
}

// DistillVerifyParams: distill.verify(draft, capture_id).
type DistillVerifyParams struct {
	Caller
	Draft    string   `json:"draft"`              // draft policy name
	IDs      []string `json:"ids,omitempty"`      // capture ids; default: the ones the draft came from
	Minimize bool     `json:"minimize,omitempty"` // drop headers one at a time to find the minimum allowlist
}

// VerifyItem is the replay result for one captured request.
type VerifyItem struct {
	ID             string   `json:"id"`
	Method         string   `json:"method"`
	URL            string   `json:"url"`
	OK             bool     `json:"ok"`
	Skipped        string   `json:"skipped,omitempty"` // e.g. "write entry disabled"
	CapturedStatus int      `json:"captured_status"`
	ReplayStatus   int      `json:"replay_status"`
	Error          string   `json:"error,omitempty"` // error code from the broker
	ShapeDiff      []string `json:"shape_diff,omitempty"`
	NeededHeaders  []string `json:"needed_headers,omitempty"`
}

// DistillVerifyResult reports verification and the (possibly narrowed)
// draft YAML, which is saved back to the draft file.
type DistillVerifyResult struct {
	OK    bool         `json:"ok"`
	Items []VerifyItem `json:"items"`
	YAML  string       `json:"yaml"`
}
