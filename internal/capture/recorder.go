package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/redact"
)

// live tracks a request still receiving events.
type live struct {
	e            *Entry
	gotReqExtra  bool
	gotRespExtra bool
	fromBlock    bool // created by MarkBlocked before any Network event
}

type staged struct {
	headers []api.Header
	status  int
}

// Recorder feeds one browser session's CDP Network events into a Store.
type Recorder struct {
	s    *Store
	sid  string
	red  *redact.Redactor
	body BodyFetcher
	post BodyFetcher

	// all below guarded by s.mu
	live       map[string]*live
	awaiting   map[string]*live // redirect hops still missing their raw response headers
	stagedReq  map[string][]staged
	stagedResp map[string][]staged

	wg sync.WaitGroup
}

// NewRecorder registers a session (replacing its redactor) and returns a
// Recorder for it.
func (s *Store) NewRecorder(sessionID string, red *redact.Redactor, body BodyFetcher, postData BodyFetcher) *Recorder {
	if red == nil {
		red = redact.New()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sd := s.sessions[sessionID]
	if sd == nil {
		sd = &sessionData{}
		s.sessions[sessionID] = sd
	}
	sd.red = red
	return &Recorder{
		s: s, sid: sessionID, red: red, body: body, post: postData,
		live: map[string]*live{}, awaiting: map[string]*live{},
		stagedReq: map[string][]staged{}, stagedResp: map[string][]staged{},
	}
}

// Wait blocks until outstanding asynchronous body fetches finish.
func (r *Recorder) Wait() { r.wg.Wait() }

type cdpInitiator struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	LineNumber *int   `json:"lineNumber"`
	Stack      *struct {
		CallFrames []struct {
			URL        string `json:"url"`
			LineNumber int    `json:"lineNumber"`
		} `json:"callFrames"`
	} `json:"stack"`
}

type cdpRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	PostData    string            `json:"postData"`
	HasPostData bool              `json:"hasPostData"`
}

type cdpResponse struct {
	URL        string            `json:"url"`
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	MimeType   string            `json:"mimeType"`
}

func headerList(m map[string]string) []api.Header {
	names := make([]string, 0, len(m))
	for k := range m {
		if strings.HasPrefix(k, ":") { // HTTP/2 pseudo headers
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	var out []api.Header
	for _, k := range names {
		// CDP joins repeated headers (Set-Cookie especially) with newlines.
		for _, v := range strings.Split(m[k], "\n") {
			out = append(out, api.Header{Name: k, Value: v})
		}
	}
	return out
}

func initiatorString(i *cdpInitiator) string {
	if i == nil {
		return "other"
	}
	switch i.Type {
	case "parser":
		if i.URL != "" {
			return "parser " + i.URL
		}
		return "parser"
	case "script":
		u, line := i.URL, -1
		if i.LineNumber != nil {
			line = *i.LineNumber
		}
		if i.Stack != nil && len(i.Stack.CallFrames) > 0 {
			f := i.Stack.CallFrames[0]
			if f.URL != "" {
				u, line = f.URL, f.LineNumber
			}
		}
		if u == "" {
			return "script"
		}
		if line >= 0 {
			return fmt.Sprintf("script %s:%d", u, line+1)
		}
		return "script " + u
	}
	return "other"
}

// HandleEvent consumes one CDP event; non-Network events are ignored.
func (r *Recorder) HandleEvent(cdpSessionID string, ev cdp.Event) {
	if !strings.HasPrefix(ev.Method, "Network.") {
		return
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	switch ev.Method {
	case "Network.requestWillBeSent":
		var p struct {
			RequestID        string        `json:"requestId"`
			Request          cdpRequest    `json:"request"`
			WallTime         float64       `json:"wallTime"`
			Initiator        *cdpInitiator `json:"initiator"`
			RedirectResponse *cdpResponse  `json:"redirectResponse"`
			Type             string        `json:"type"`
		}
		if json.Unmarshal(ev.Params, &p) != nil || p.RequestID == "" {
			return
		}
		r.onRequest(cdpSessionID, p.RequestID, p.Request, p.WallTime, p.Initiator, p.RedirectResponse, p.Type)
	case "Network.requestWillBeSentExtraInfo":
		var p struct {
			RequestID string            `json:"requestId"`
			Headers   map[string]string `json:"headers"`
		}
		if json.Unmarshal(ev.Params, &p) != nil || p.RequestID == "" {
			return
		}
		hs := headerList(p.Headers)
		if lv := r.live[p.RequestID]; lv != nil && !lv.gotReqExtra {
			lv.gotReqExtra = true
			lv.e.RequestHeaders = r.red.Headers(hs)
			return
		}
		r.stagedReq[p.RequestID] = appendStaged(r.stagedReq[p.RequestID], staged{headers: hs})
	case "Network.responseReceived":
		var p struct {
			RequestID string      `json:"requestId"`
			Type      string      `json:"type"`
			Response  cdpResponse `json:"response"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		lv := r.live[p.RequestID]
		if lv == nil {
			return
		}
		e := lv.e
		e.Status, e.StatusText, e.MimeType = p.Response.Status, p.Response.StatusText, p.Response.MimeType
		if p.Type != "" {
			e.ResourceType = p.Type
		}
		if !lv.gotRespExtra {
			e.ResponseHeaders = r.red.Headers(headerList(p.Response.Headers))
		}
	case "Network.responseReceivedExtraInfo":
		var p struct {
			RequestID  string            `json:"requestId"`
			StatusCode int               `json:"statusCode"`
			Headers    map[string]string `json:"headers"`
		}
		if json.Unmarshal(ev.Params, &p) != nil || p.RequestID == "" {
			return
		}
		hs := headerList(p.Headers)
		if aw := r.awaiting[p.RequestID]; aw != nil && p.StatusCode >= 300 && p.StatusCode < 400 {
			aw.gotRespExtra = true
			aw.e.ResponseHeaders = r.red.Headers(hs)
			delete(r.awaiting, p.RequestID)
			return
		}
		if lv := r.live[p.RequestID]; lv != nil && !lv.gotRespExtra {
			lv.gotRespExtra = true
			lv.e.ResponseHeaders = r.red.Headers(hs)
			return
		}
		r.stagedResp[p.RequestID] = appendStaged(r.stagedResp[p.RequestID], staged{headers: hs, status: p.StatusCode})
	case "Network.loadingFinished":
		var p struct {
			RequestID         string  `json:"requestId"`
			EncodedDataLength float64 `json:"encodedDataLength"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		lv := r.live[p.RequestID]
		if lv == nil {
			return
		}
		e := lv.e
		e.Finished = r.s.opts.Now()
		if p.EncodedDataLength > 0 {
			e.Size = int(p.EncodedDataLength)
		}
		if r.body != nil && e.Blocked == "" && e.Failed == "" {
			r.fetchBody(e, cdpSessionID, p.RequestID)
		}
	case "Network.loadingFailed":
		var p struct {
			RequestID string `json:"requestId"`
			ErrorText string `json:"errorText"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		if lv := r.live[p.RequestID]; lv != nil {
			lv.e.Failed = p.ErrorText
			if lv.e.Failed == "" {
				lv.e.Failed = "failed"
			}
			lv.e.Finished = r.s.opts.Now()
		}
	}
}

func appendStaged(l []staged, s staged) []staged {
	if len(l) >= 8 {
		l = l[1:]
	}
	return append(l, s)
}

func (r *Recorder) sd() *sessionData { return r.s.sessions[r.sid] }

func (r *Recorder) onRequest(cdpSID, id string, req cdpRequest, wall float64, ini *cdpInitiator, redir *cdpResponse, typ string) {
	sd := r.sd()
	if sd == nil {
		return
	}
	now := r.s.opts.Now()
	prevID := ""
	lv := r.live[id]
	if redir != nil && lv != nil && !lv.fromBlock {
		e := lv.e
		e.Status, e.StatusText, e.MimeType = redir.Status, redir.StatusText, redir.MimeType
		if !lv.gotRespExtra {
			e.ResponseHeaders = r.red.Headers(headerList(redir.Headers))
			r.awaiting[id] = lv
		}
		e.Finished = now
		prevID = e.ID
		lv = nil
	}
	if lv == nil || !lv.fromBlock {
		lv = &live{e: &Entry{CDPSessionID: cdpSID, RequestID: id}}
		r.s.add(sd, r.sid, lv.e)
		r.live[id] = lv
	} else {
		lv.fromBlock = false // merge Network data into the blocked entry
	}
	e := lv.e
	e.CDPSessionID = cdpSID
	e.RedirectedFrom = prevID
	e.Method = req.Method
	e.URL = r.red.String(req.URL)
	e.ResourceType = typ
	e.Initiator = r.red.String(initiatorString(ini))
	e.Started = now
	if wall > 0 {
		e.Started = time.Unix(0, int64(wall*1e9))
	}
	if !lv.gotReqExtra {
		e.RequestHeaders = r.red.Headers(headerList(req.Headers))
	}
	switch {
	case req.PostData != "":
		e.RequestBody = r.capText([]byte(req.PostData))
	case req.HasPostData && r.post != nil:
		r.fetchPost(e, cdpSID, id)
	}
	if q := r.stagedReq[id]; len(q) > 0 && !lv.gotReqExtra {
		e.RequestHeaders = r.red.Headers(q[0].headers)
		lv.gotReqExtra = true
		r.stagedReq[id] = q[1:]
	}
	if q := r.stagedResp[id]; len(q) > 0 && !lv.gotRespExtra {
		e.ResponseHeaders = r.red.Headers(q[0].headers)
		lv.gotRespExtra = true
		r.stagedResp[id] = q[1:]
	}
}

// capText redacts then truncates text bytes. Caller holds s.mu.
func (r *Recorder) capText(b []byte) []byte {
	b = r.red.Bytes(b)
	if len(b) > r.s.opts.MaxBodyBytes {
		b = b[:r.s.opts.MaxBodyBytes]
	}
	return b
}

func (r *Recorder) fetchPost(e *Entry, cdpSID, id string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b, isB64, err := r.post(ctx, cdpSID, id)
		if err != nil {
			return
		}
		if isB64 {
			if d, err := base64.StdEncoding.DecodeString(string(b)); err == nil {
				b = d
			}
		}
		r.s.mu.Lock()
		defer r.s.mu.Unlock()
		e.RequestBody = r.capText(b)
	}()
}

func (r *Recorder) fetchBody(e *Entry, cdpSID, id string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b, isB64, err := r.body(ctx, cdpSID, id)
		if err != nil {
			return
		}
		r.s.mu.Lock()
		defer r.s.mu.Unlock()
		r.setBody(e, b, isB64)
	}()
}

const droppedNote = "[body dropped: contains a held credential]"

// setBody stores a fetched response body. Caller holds s.mu.
func (r *Recorder) setBody(e *Entry, raw []byte, isB64 bool) {
	max := r.s.opts.MaxBodyBytes
	data := raw
	if isB64 {
		d, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			d, err = base64.RawStdEncoding.DecodeString(string(raw))
		}
		if err == nil {
			data = d
		} else {
			isB64 = false
		}
	}
	if e.Size == 0 {
		e.Size = len(data)
	}
	e.BodyTruncated = len(data) > max
	if isB64 && !(utf8.Valid(data) && !containsNUL(data)) {
		// Binary: scan the whole body, keep it as base64 only if clean.
		if r.red.Contains(string(data)) {
			e.ResponseBody, e.BodyTruncated, e.BodyBase64 = []byte(droppedNote), false, false
			return
		}
		if len(data) > max {
			data = data[:max]
		}
		e.ResponseBody = []byte(base64.StdEncoding.EncodeToString(data))
		e.BodyBase64 = true
		return
	}
	// Text: redact the whole body first so a secret cut by the size cap is
	// never partially stored.
	red := r.red.Bytes(data)
	if len(red) > max {
		red = red[:max]
	}
	e.ResponseBody, e.BodyBase64 = red, false
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// MarkBlocked records a request curd failed (reason, e.g. "write" or "host").
// It creates the entry if no Network event has produced one yet, so the agent
// still learns the request's shape (spec 16.5).
func (r *Recorder) MarkBlocked(networkRequestID, reason string, blockedWrite bool, req BlockedRequest) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	sd := r.sd()
	if sd == nil {
		return
	}
	lv := r.live[networkRequestID]
	if lv == nil {
		lv = &live{e: &Entry{RequestID: networkRequestID, Started: r.s.opts.Now()}, fromBlock: true}
		r.s.add(sd, r.sid, lv.e)
		r.live[networkRequestID] = lv
	}
	e := lv.e
	e.Blocked, e.BlockedWrite = reason, blockedWrite
	if e.Method == "" {
		e.Method = req.Method
	}
	if e.URL == "" {
		e.URL = r.red.String(req.URL)
	}
	if e.ResourceType == "" {
		e.ResourceType = req.ResourceType
	}
	if len(e.RequestHeaders) == 0 {
		e.RequestHeaders = r.red.Headers(req.Headers)
	}
	if len(e.RequestBody) == 0 && len(req.PostData) > 0 {
		e.RequestBody = r.capText(req.PostData)
	}
}
