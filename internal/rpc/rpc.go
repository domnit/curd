// Package rpc implements curd's newline-delimited JSON-RPC 2.0 protocol over
// a unix socket (spec section 7.1). The server verifies the peer uid on every
// connection and hands each handler best-effort peer details for auditing.
package rpc

import (
	"encoding/json"
	"fmt"

	"github.com/domnit/curd/internal/apierr"
)

// MaxLineSize bounds a single JSON line. It is generous because request and
// response bodies travel base64-encoded inside the JSON.
const MaxLineSize = 64 << 20

// JSON-RPC error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	// CodeApp is the JSON-RPC error code carrying an *apierr.Error.
	CodeApp = -32000
)

// Peer describes the process on the other end of a connection. Everything
// except UID is best effort and may be zero/empty.
type Peer struct {
	UID       int
	PID       int
	Exe       string
	ParentPID int
	ParentExe string
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// appData is the data member of a CodeApp error.
type appData struct {
	Code string         `json:"code"`
	Hint string         `json:"hint,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

type paramsError struct{ err error }

func (e *paramsError) Error() string { return "invalid params: " + e.err.Error() }
func (e *paramsError) Unwrap() error { return e.err }

// InvalidParams wraps err so the server reports it as JSON-RPC -32602.
func InvalidParams(err error) error { return &paramsError{err: err} }

// DecodeParams unmarshals raw into v (empty raw leaves v untouched) and
// returns an InvalidParams error on failure. Handlers use it for params.
func DecodeParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return InvalidParams(err)
	}
	return nil
}

func toRPCError(err error) *rpcError {
	if pe, ok := err.(*paramsError); ok {
		return &rpcError{Code: codeInvalidParams, Message: pe.Error()}
	}
	e := apierr.As(err)
	return &rpcError{Code: CodeApp, Message: e.Message, Data: appData{Code: e.Code, Hint: e.Hint, Data: e.Data}}
}

func fromRPCError(re *rpcError) error {
	switch re.Code {
	case CodeApp:
		var d appData
		if b, err := json.Marshal(re.Data); err == nil {
			_ = json.Unmarshal(b, &d)
		}
		if d.Code == "" {
			d.Code = apierr.Internal
		}
		return &apierr.Error{Code: d.Code, Message: re.Message, Hint: d.Hint, Data: d.Data}
	case codeInvalidParams, codeInvalidRequest, codeParse:
		return apierr.New(apierr.InvalidRequest, re.Message, "check the request parameters")
	default:
		return apierr.New(apierr.Internal, fmt.Sprintf("rpc error %d: %s", re.Code, re.Message), "")
	}
}
