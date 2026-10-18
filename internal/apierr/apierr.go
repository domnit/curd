// Package apierr defines curd's error codes. Every error that reaches a
// caller carries a stable Code and a Hint naming the next action (spec
// section 7.5: "errors name the fix"). Messages and hints must never contain
// credential values.
package apierr

import (
	"errors"
	"fmt"
)

// Codes from spec section 8, plus daemon-level codes.
const (
	DeniedNoPolicy  = "denied_no_policy"
	DeniedNoGrant   = "denied_no_grant"
	DeniedMethod    = "denied_method"
	DeniedPath      = "denied_path"
	DeniedInspector = "denied_inspector"
	DeniedHost      = "denied_host" // e.g. redirect or navigation to unmatched host
	DeniedHeader    = "denied_header"
	DeniedBodySize  = "denied_body_size"
	AuthExpired     = "auth_expired"
	UpstreamError   = "upstream_error"

	InvalidToken   = "invalid_token" // unknown, revoked or expired token
	InvalidRequest = "invalid_request"
	NotFound       = "not_found"
	NotAvailable   = "not_available" // feature deferred (e.g. js verb, grants.derive)
	SourceError    = "source_error"  // credential source failed (profile, keychain)
	BrowserError   = "browser_error"
	Internal       = "internal_error"
	DaemonDown     = "daemon_unreachable"
)

// Error is a curd error with a machine-readable code and a human/agent
// readable hint.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Hint    string         `json:"hint,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *Error) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s\nhint: %s", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// New builds an Error.
func New(code, msg, hint string) *Error { return &Error{Code: code, Message: msg, Hint: hint} }

// Newf builds an Error with a formatted message.
func Newf(code, hint, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Hint: hint}
}

// With returns a copy of e with a data field set.
func (e *Error) With(key string, v any) *Error {
	c := *e
	c.Data = map[string]any{}
	for k, val := range e.Data {
		c.Data[k] = val
	}
	c.Data[key] = v
	return &c
}

// As extracts an *Error from err, wrapping unknown errors as Internal.
func As(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: Internal, Message: err.Error()}
}

// CodeOf returns err's code, or "" for nil.
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	return As(err).Code
}
