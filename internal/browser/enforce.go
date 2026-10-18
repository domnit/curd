package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/policy"
)

// Block reasons recorded with the capture and the audit log.
const (
	ReasonHostNotInPolicy = "host_not_in_policy"
	ReasonPlainHTTP       = "plain_http"
	ReasonScheme          = "scheme_not_allowed"
	ReasonPolicyDenied    = "policy_denied"
	ReasonWriteNotGranted = "write_not_granted"
	ReasonInternal        = "enforcement_error"
)

type pausedRequest struct {
	RequestID string `json:"requestId"`
	Request   struct {
		URL             string            `json:"url"`
		Method          string            `json:"method"`
		Headers         map[string]string `json:"headers"`
		PostData        string            `json:"postData"`
		HasPostData     bool              `json:"hasPostData"`
		PostDataEntries []struct {
			Bytes string `json:"bytes"`
		} `json:"postDataEntries"`
	} `json:"request"`
	FrameID      string `json:"frameId"`
	ResourceType string `json:"resourceType"`
	NetworkID    string `json:"networkId"`
}

// verdict is the outcome of checking one paused request.
type verdict struct {
	allow        bool
	reason       string
	blockedWrite bool
	err          *apierr.Error // what a navigation waiter should report
	body         []byte
}

// onPaused handles Fetch.requestPaused. Every paused request is continued or
// failed exactly once; any error on a policy host fails closed.
func (s *Session) onPaused(ev cdp.Event) {
	var p pausedRequest
	if err := json.Unmarshal(ev.Params, &p); err != nil || p.RequestID == "" {
		// Without a request id nothing can be resolved; try to find one.
		var probe struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(ev.Params, &probe) == nil && probe.RequestID != "" {
			s.fail(ev.SessionID, probe.RequestID)
		}
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()

	var v verdict
	func() {
		defer func() {
			if r := recover(); r != nil {
				v = verdict{reason: ReasonInternal, blockedWrite: true}
			}
		}()
		v = s.decide(ctx, ev.SessionID, &p)
	}()

	if v.allow {
		if err := s.call(ctx, ev.SessionID, "Fetch.continueRequest", map[string]any{"requestId": p.RequestID}, nil); err != nil && !isGone(err) {
			// Could not continue: make sure it does not hang.
			_ = s.call(ctx, ev.SessionID, "Fetch.failRequest", map[string]any{"requestId": p.RequestID, "errorReason": "BlockedByClient"}, nil)
		}
		return
	}

	u, _ := url.Parse(p.Request.URL)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	isMainDoc := p.ResourceType == "Document" && p.FrameID != "" && s.isMainFrame(ev.SessionID, p.FrameID)
	s.mu.Lock()
	s.blockSeq++
	if t := s.targets[ev.SessionID]; t != nil && t.pg != nil && isMainDoc {
		e := v.err
		if e == nil {
			e = apierr.Newf(apierr.DeniedHost, "", "navigation blocked (%s)", v.reason)
		}
		rec := &blockRec{seq: s.blockSeq, err: e, reason: v.reason, host: host}
		t.pg.block = rec
		s.lastDocBlock = rec
	}
	delete(s.inflight, ev.SessionID+"|"+p.NetworkID)
	s.bumpLocked()
	s.mu.Unlock()

	if s.rec != nil {
		s.rec.MarkBlocked(p.NetworkID, v.reason, v.blockedWrite, BlockedRequest{
			Method:       p.Request.Method,
			URL:          p.Request.URL,
			ResourceType: p.ResourceType,
			Headers:      headersFromMap(p.Request.Headers),
			PostData:     v.body,
		})
	}
	s.emit(SessionEvent{
		Type: "blocked", Method: p.Request.Method, URL: s.red.String(p.Request.URL),
		Host: host, Reason: v.reason, BlockedWrite: v.blockedWrite,
	})
	s.fail(ev.SessionID, p.RequestID)
	s.bump()
}

func (s *Session) fail(sid, requestID string) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	_ = s.call(ctx, sid, "Fetch.failRequest", map[string]any{"requestId": requestID, "errorReason": "BlockedByClient"}, nil)
}

func (s *Session) isMainFrame(sid, frameID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.targets[sid]
	return t != nil && t.pg != nil && t.pg.targetID == frameID
}

func (s *Session) decide(ctx context.Context, sid string, p *pausedRequest) verdict {
	u, err := url.Parse(p.Request.URL)
	if err != nil {
		return verdict{reason: ReasonInternal, blockedWrite: true}
	}
	isDoc := p.ResourceType == "Document"
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		switch scheme {
		case "data", "about", "blob":
			return verdict{allow: true}
		}
		if isDoc {
			return verdict{reason: ReasonScheme, err: apierr.Newf(apierr.DeniedHost, "only http(s) pages on policy hosts can be opened", "navigation to a %s: URL is blocked", scheme)}
		}
		return verdict{allow: true}
	}
	host := u.Hostname()
	pols := s.policiesFor(host)

	if isDoc {
		if len(pols) == 0 {
			return verdict{reason: ReasonHostNotInPolicy, err: s.hostDenied(host)}
		}
		if scheme == "http" && !s.opts.Test {
			return verdict{reason: ReasonPlainHTTP, err: apierr.Newf(apierr.DeniedHost, "use an https:// URL", "plain-http navigation to %q is blocked", host)}
		}
	}
	if len(pols) == 0 {
		return verdict{allow: true} // subresource to a non-policy host: no credentials seeded
	}
	method := strings.ToUpper(p.Request.Method)
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return verdict{allow: true}
	}

	if isDoc && s.inLoginPhase() {
		// A login form submission is a top-level POST to a policy host.
		// In a login-seeded session nothing was hoisted, so the only
		// credentials involved are the ones being typed into the form.
		// Fetch/XHR writes stay blocked; the allowance is audited.
		s.emit(SessionEvent{Type: "login_post", Method: method, URL: u.String(), Host: host})
		return verdict{allow: true}
	}
	body := s.requestBody(ctx, sid, p)
	var first *policy.Decision
	for _, pol := range pols {
		d := pol.Check(ctx, policy.CheckRequest{
			Method: method, URL: u, Headers: headersFromMap(p.Request.Headers), Body: body,
		})
		if d.Allowed {
			if d.Scope == policy.ScopeWrite && !s.spec.AllowWrites {
				return verdict{reason: ReasonWriteNotGranted, blockedWrite: true, body: body,
					err: apierr.Newf(apierr.DeniedNoGrant, "open the session with write access to allow writes, or use a throwaway account", "%s %s needs a write grant; this session is read-only", method, u.Path)}
			}
			return verdict{allow: true}
		}
		if first == nil {
			dd := d
			first = &dd
		}
	}
	reason := ReasonPolicyDenied
	var e *apierr.Error
	if first != nil {
		reason = fmt.Sprintf("%s:%s", ReasonPolicyDenied, first.Code)
		e = first.Error()
	}
	return verdict{reason: reason, blockedWrite: true, body: body, err: e}
}

func (s *Session) hostDenied(host string) *apierr.Error {
	return apierr.Newf(apierr.DeniedHost,
		"this session's policies cover: "+strings.Join(s.PolicyHosts(), ", ")+"; open a session with a policy for the other host",
		"navigation to host %q is blocked: it is not covered by the session's policies", host).With("host", host)
}

// checkNavigable pre-checks a URL the agent asked to open, with the same rules
// the interceptor applies to a Document request.
func (s *Session) checkNavigable(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "about", "data", "blob":
		return nil
	case "http", "https":
	default:
		return apierr.Newf(apierr.InvalidRequest, "use an absolute https:// URL on a policy host", "cannot open a %s: URL", u.Scheme)
	}
	if len(s.policiesFor(u.Hostname())) == 0 {
		return s.hostDenied(u.Hostname())
	}
	if strings.EqualFold(u.Scheme, "http") && !s.opts.Test {
		return apierr.Newf(apierr.DeniedHost, "use an https:// URL", "plain-http navigation to %q is blocked", u.Hostname())
	}
	return nil
}

// requestBody returns the request body for inspectors, or nil if the browser
// cannot provide it.
func (s *Session) requestBody(ctx context.Context, sid string, p *pausedRequest) []byte {
	if len(p.Request.PostDataEntries) > 0 {
		var out []byte
		for _, e := range p.Request.PostDataEntries {
			b, err := base64.StdEncoding.DecodeString(e.Bytes)
			if err != nil {
				continue
			}
			out = append(out, b...)
		}
		return out
	}
	if p.Request.PostData != "" {
		return []byte(p.Request.PostData)
	}
	if p.Request.HasPostData && p.NetworkID != "" {
		if b, _, err := s.postDataFetcher(ctx, sid, p.NetworkID); err == nil {
			return b
		}
	}
	return nil
}

// LoginPhase is how long a login-seeded session lets form submissions
// (Document POSTs) to policy hosts through without a write grant, so the user
// can sign in. `browse login done` ends it early.
const LoginPhase = 10 * time.Minute

func (s *Session) inLoginPhase() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.loginUntil.IsZero() && s.opts.Now().Before(s.loginUntil)
}

func (s *Session) endLoginPhase() {
	s.mu.Lock()
	s.loginUntil = time.Time{}
	s.mu.Unlock()
}
