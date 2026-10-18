// Package capture records browser network traffic for exploration sessions
// (spec 16.2, 16.3). Everything stored is redacted at capture time; outputs
// are redacted again because secrets can be learned after capture.
package capture

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/redact"
)

// BodyFetcher fetches a response body (or request post data) from the
// browser. base64 reports that the returned bytes are base64 text, as
// Network.getResponseBody returns for binary content.
type BodyFetcher func(ctx context.Context, cdpSessionID, requestID string) ([]byte, bool, error)

// BlockedRequest is the shape of a request curd failed before it left the
// browser.
type BlockedRequest struct {
	Method, URL, ResourceType string
	Headers                   []api.Header
	PostData                  []byte
}

// Options configures a Store.
type Options struct {
	MaxBodyBytes         int // default 2 MiB
	MaxEntriesPerSession int // default 5000
	Now                  func() time.Time
}

// Entry is one captured request/response. All fields are already redacted.
// When BodyBase64 is set, ResponseBody holds base64 text.
type Entry struct {
	ID, SessionID, CDPSessionID, RequestID string
	Seq                                    int
	Method, URL                            string
	RequestHeaders                         []api.Header
	RequestBody                            []byte
	Status                                 int
	StatusText                             string
	ResponseHeaders                        []api.Header
	ResponseBody                           []byte
	BodyTruncated, BodyBase64              bool
	MimeType, ResourceType, Initiator      string
	Started, Finished                      time.Time
	Size                                   int
	Blocked                                string
	BlockedWrite                           bool
	Failed                                 string
	RedirectedFrom                         string
}

type sessionData struct {
	red     *redact.Redactor
	entries []*Entry
	nextSeq int
}

// Store holds captures for all browser sessions, in memory.
type Store struct {
	mu       sync.Mutex
	opts     Options
	next     int
	byID     map[string]*Entry
	sessions map[string]*sessionData
}

// NewStore returns an empty store.
func NewStore(opts Options) *Store {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 2 << 20
	}
	if opts.MaxEntriesPerSession <= 0 {
		opts.MaxEntriesPerSession = 5000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{opts: opts, byID: map[string]*Entry{}, sessions: map[string]*sessionData{}}
}

func notFound(id string) error {
	return apierr.Newf(apierr.NotFound, "curd browse capture list", "no capture %q", id)
}

// add registers e; caller holds s.mu.
func (s *Store) add(sd *sessionData, sessionID string, e *Entry) {
	s.next++
	sd.nextSeq++
	e.ID = "c" + itoa(s.next)
	e.Seq = sd.nextSeq
	e.SessionID = sessionID
	s.byID[e.ID] = e
	sd.entries = append(sd.entries, e)
	if over := len(sd.entries) - s.opts.MaxEntriesPerSession; over > 0 {
		for _, old := range sd.entries[:over] {
			delete(s.byID, old.ID)
		}
		sd.entries = append([]*Entry(nil), sd.entries[over:]...)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// Drop discards everything captured for a session.
func (s *Store) Drop(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sd := s.sessions[sessionID]; sd != nil {
		for _, e := range sd.entries {
			delete(s.byID, e.ID)
		}
	}
	delete(s.sessions, sessionID)
}

// SessionOf returns the session that owns capture id.
func (s *Store) SessionOf(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.byID[id]; e != nil {
		return e.SessionID, true
	}
	return "", false
}

// view returns a deep copy of e with output-time redaction applied.
// Caller holds s.mu.
func (s *Store) view(e *Entry) *Entry {
	var red *redact.Redactor
	if sd := s.sessions[e.SessionID]; sd != nil {
		red = sd.red
	}
	c := *e
	c.URL = red.String(e.URL)
	c.RequestHeaders = red.Headers(e.RequestHeaders)
	c.ResponseHeaders = red.Headers(e.ResponseHeaders)
	c.RequestBody = red.Bytes(e.RequestBody)
	if e.BodyBase64 {
		c.ResponseBody = append([]byte(nil), e.ResponseBody...)
	} else {
		c.ResponseBody = red.Bytes(e.ResponseBody)
	}
	c.Initiator = red.String(e.Initiator)
	return &c
}

func summary(e *Entry) api.CaptureSummary {
	return api.CaptureSummary{
		ID: e.ID, Method: e.Method, URL: e.URL, Status: e.Status,
		ResourceType: e.ResourceType, Size: e.Size, Initiator: e.Initiator,
		BlockedWrite: e.BlockedWrite, Blocked: e.Blocked,
	}
}

func matchesFilter(e *Entry, f api.CaptureFilter) bool {
	if f.Method != "" && !strings.EqualFold(e.Method, f.Method) {
		return false
	}
	if f.URLContains != "" && !strings.Contains(e.URL, f.URLContains) {
		return false
	}
	if f.Type != "" && !strings.EqualFold(e.ResourceType, f.Type) {
		return false
	}
	if f.Status != 0 && e.Status != f.Status {
		return false
	}
	if f.Host != "" {
		u, err := url.Parse(e.URL)
		if err != nil || !(strings.EqualFold(u.Host, f.Host) || strings.EqualFold(u.Hostname(), f.Host)) {
			return false
		}
	}
	return true
}

// List returns summaries of a session's captures in request order.
func (s *Store) List(sessionID string, f api.CaptureFilter) []api.CaptureSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []api.CaptureSummary{}
	sd := s.sessions[sessionID]
	if sd == nil {
		return out
	}
	for _, e := range sd.entries {
		v := s.view(e)
		if matchesFilter(v, f) {
			out = append(out, summary(v))
		}
	}
	return out
}

// Get returns one capture; parts selects request_headers, request_body,
// response_headers, response_body (empty means all).
func (s *Store) Get(id string, parts []string) (*api.CaptureDetail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.byID[id]
	if e == nil {
		return nil, notFound(id)
	}
	want := map[string]bool{}
	for _, p := range parts {
		switch p {
		case "request_headers", "request_body", "response_headers", "response_body":
			want[p] = true
		default:
			return nil, apierr.Newf(apierr.InvalidRequest,
				"parts may be request_headers, request_body, response_headers, response_body", "unknown part %q", p)
		}
	}
	all := len(want) == 0
	v := s.view(e)
	d := &api.CaptureDetail{CaptureSummary: summary(v)}
	if all || want["request_headers"] {
		d.RequestHeaders = v.RequestHeaders
	}
	if all || want["request_body"] {
		d.RequestBody = string(v.RequestBody)
	}
	if all || want["response_headers"] {
		d.ResponseHeaders = v.ResponseHeaders
	}
	if all || want["response_body"] {
		d.ResponseBody = string(v.ResponseBody)
		d.BodyTruncated = v.BodyTruncated
		d.BodyBase64 = v.BodyBase64
	}
	return d, nil
}

// Entries returns redacted copies of the given captures (all of the
// session's if ids is empty), for distill. Unknown ids, or ids from another
// session, are NotFound.
func (s *Store) Entries(sessionID string, ids []string) ([]*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Entry
	if len(ids) == 0 {
		if sd := s.sessions[sessionID]; sd != nil {
			for _, e := range sd.entries {
				out = append(out, s.view(e))
			}
		}
		return out, nil
	}
	for _, id := range ids {
		e := s.byID[id]
		if e == nil || e.SessionID != sessionID {
			return nil, notFound(id)
		}
		out = append(out, s.view(e))
	}
	return out, nil
}

// FindSource finds the captures in which value appeared (earliest first):
// URL, request body, response header or response body. A held credential or
// empty value is refused with InvalidRequest.
func (s *Store) FindSource(sessionID, value string) ([]api.CaptureSource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sd := s.sessions[sessionID]
	if value == "" {
		return nil, apierr.New(apierr.InvalidRequest, "value is empty", "pass the value to trace, e.g. a CSRF token")
	}
	if sd != nil && sd.red.Contains(value) {
		return nil, apierr.New(apierr.InvalidRequest,
			"that value is a held credential; it is shown as a placeholder",
			"held credentials are never searched; trace a non-credential value such as a CSRF token or id")
	}
	out := []api.CaptureSource{}
	if sd == nil {
		return out, nil
	}
	snip := func(text string) (string, bool) {
		i := strings.Index(text, value)
		if i < 0 {
			return "", false
		}
		lo, hi := i-40, i+len(value)+40
		if lo < 0 {
			lo = 0
		}
		if hi > len(text) {
			hi = len(text)
		}
		return sd.red.String(text[lo:hi]), true
	}
	for _, e := range sd.entries {
		v := s.view(e)
		if c, ok := snip(v.URL); ok {
			out = append(out, api.CaptureSource{ID: e.ID, Location: "url", Context: c})
		}
		if c, ok := snip(string(v.RequestBody)); ok {
			out = append(out, api.CaptureSource{ID: e.ID, Location: "request_body", Context: c})
		}
		for _, h := range v.ResponseHeaders {
			if c, ok := snip(h.Value); ok {
				out = append(out, api.CaptureSource{ID: e.ID, Location: "response_header:" + strings.ToLower(h.Name), Context: c})
			}
		}
		if !v.BodyBase64 {
			if c, ok := snip(string(v.ResponseBody)); ok {
				out = append(out, api.CaptureSource{ID: e.ID, Location: "response_body", Context: c})
			}
		}
	}
	return out, nil
}
