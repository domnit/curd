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
	ReasonCookieScope     = "domain_cookie_scope"
	ReasonWebSocket       = "websocket_not_granted"
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
	blockedURL   string        // recorded instead of the request URL, if set
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
			URL:          firstNonEmpty(v.blockedURL, p.Request.URL),
			ResourceType: p.ResourceType,
			Headers:      headersFromMap(p.Request.Headers),
			PostData:     v.body,
		})
	}
	s.emit(SessionEvent{
		Type: "blocked", Method: p.Request.Method, URL: s.red.String(firstNonEmpty(v.blockedURL, p.Request.URL)),
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
		if isDoc {
			// Documents (top-level or framed) other than about:blank are
			// refused: data:/blob: documents would run page-authored script
			// outside any policy host (spec 9.6: no js escape hatch).
			if strings.EqualFold(p.Request.URL, "about:blank") {
				return verdict{allow: true}
			}
			return verdict{reason: ReasonScheme, err: apierr.Newf(apierr.DeniedHost, "only http(s) pages on policy hosts can be opened", "navigation to a %s: URL is blocked", scheme)}
		}
		return verdict{allow: true}
	}
	host := u.Hostname()
	if host == wsSentinelHost && !isDoc {
		// The WebSocket guard (wsGuardScript) reports a refused connection by
		// requesting this host; record it as a blocked entry.
		bu, _ := url.QueryUnescape(u.Query().Get("u"))
		if len(bu) > 2048 {
			bu = bu[:2048]
		}
		return verdict{reason: ReasonWebSocket, blockedWrite: true, blockedURL: bu}
	}
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
		if s.domainCookieMatches(host) {
			// A seeded domain cookie would be sent to this non-policy host.
			return verdict{reason: ReasonCookieScope, blockedWrite: true}
		}
		return verdict{allow: true} // subresource to a non-policy host: no credentials seeded
	}
	method := strings.ToUpper(p.Request.Method)
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return verdict{allow: true}
	}

	loginDoc := s.Seed == SeedLogin && isDoc && method == "POST"
	if loginDoc && s.loginPostAllowed(ctx, sid, p, u) {
		// A login form submission: a same-origin top-level form POST to a
		// policy host before any session cookie exists. Fetch/XHR writes stay
		// blocked; the allowance is audited. The body (it holds the typed
		// password) is never recorded.
		s.mu.Lock()
		s.loginPosted = true
		s.mu.Unlock()
		s.emit(SessionEvent{Type: "login_post", Method: method, URL: u.String(), Host: host})
		s.omitBody(p.NetworkID, "login form submission")
		return verdict{allow: true}
	}
	body := s.requestBody(ctx, sid, p)
	if loginDoc {
		body = nil
		s.omitBody(p.NetworkID, "form submission in a login session")
	}
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
	case "about":
		if strings.EqualFold(u.String(), "about:blank") {
			return nil
		}
		return apierr.Newf(apierr.InvalidRequest, "use an absolute https:// URL on a policy host", "cannot open %q", u.String())
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

// LoginPhase is how long a login-seeded session lets login form submissions
// through without a write grant. The phase also ends once a login submission
// has led to a new credential cookie for a policy host, or on
// `browse login done`.
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

func headerGet(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// originOf returns scheme://host[:port] with default ports dropped, the form
// of an Origin header.
func originOf(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		h += ":" + port
	}
	return strings.ToLower(u.Scheme) + "://" + h
}

// loginPostAllowed decides whether a top-level POST is the login form
// submission the login phase exists for: the phase is open, no session cookie
// has been minted yet, the request is a same-origin form submission (Origin
// equals the target origin; "null" is refused) and the page that submitted
// it is itself on a policy host.
func (s *Session) loginPostAllowed(ctx context.Context, sid string, p *pausedRequest, u *url.URL) bool {
	if !s.inLoginPhase() {
		return false
	}
	// A cookie minted since the last poll ends the phase now.
	s.refreshRedactor(ctx)
	if !s.inLoginPhase() {
		return false
	}
	if site, ok := headerGet(p.Request.Headers, "Sec-Fetch-Site"); ok && !strings.EqualFold(site, "same-origin") {
		return false
	}
	origin, ok := headerGet(p.Request.Headers, "Origin")
	if !ok || origin != originOf(u) {
		return false
	}
	s.mu.Lock()
	t := s.targets[sid]
	var pg *page
	if t != nil {
		pg = t.pg
	}
	s.mu.Unlock()
	if pg == nil {
		return false
	}
	top, _, err := s.pageInfo(ctx, pg)
	if err != nil {
		return false
	}
	tu, err := url.Parse(top)
	if err != nil || (tu.Scheme != "http" && tu.Scheme != "https") || len(s.policiesFor(tu.Hostname())) == 0 {
		return false
	}
	return true
}

// omitBody tells a recorder that supports it to drop a request's body.
func (s *Session) omitBody(networkID, reason string) {
	if networkID == "" {
		return
	}
	if o, ok := s.rec.(BodyOmitter); ok {
		o.OmitRequestBody(networkID, reason)
	}
}

// wsSentinelHost is the (unresolvable) host the WebSocket guard requests to
// tell curd about a refused connection.
const wsSentinelHost = "curd-ws-blocked.invalid"

// wsGuardScript replaces the WebSocket constructor, in every document and
// worker of a session without write access, with one that refuses
// connections to policy hosts. Fetch interception never sees a WebSocket
// handshake (Network.setBlockedURLs does not apply to them either), yet a
// socket carries seeded cookies and can carry writes, so this is the gate.
// The page cannot reach the native constructor: Proxy keeps the statics and
// instanceof, and prototype.constructor is repointed at the proxy.
const wsGuardScript = `(() => { try {
  const N = self.WebSocket; if (typeof N !== 'function' || N.__curdGuard) return;
  const exact = %s, wild = %s, dom = %s;
  const blocked = (h) => exact.includes(h) || wild.some((s) => h.endsWith(s)) || dom.some((d) => h === d || h.endsWith('.' + d));
  const P = new Proxy(N, { construct(t, args, nt) {
    let h = '', abs = String(args[0]);
    try { const u = new URL(abs, self.location.href); h = u.hostname.toLowerCase(); abs = u.href; } catch (e) {}
    if (blocked(h)) {
      try { fetch('https://` + wsSentinelHost + `/?u=' + encodeURIComponent(abs), {mode: 'no-cors', cache: 'no-store'}).catch(() => {}); } catch (e) {}
      throw new DOMException('WebSocket connections to policy hosts need a session opened with write access', 'SecurityError');
    }
    return Reflect.construct(t, args, nt === P ? t : nt);
  } });
  Object.defineProperty(P, '__curdGuard', {value: true});
  Object.defineProperty(N.prototype, 'constructor', {value: P, configurable: true, writable: true});
  Object.defineProperty(self, 'WebSocket', {value: P, configurable: false, writable: false});
} catch (e) {} })();`

// wsGuard returns the guard script for this session, or "" when sockets are
// allowed (the session has write access).
func (s *Session) wsGuard() string {
	if s.spec.AllowWrites {
		return ""
	}
	exact, wild, dom := []string{}, []string{}, []string{}
	for _, h := range s.PolicyHosts() {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			wild = append(wild, "."+suffix)
		} else {
			exact = append(exact, h)
		}
	}
	s.mu.Lock()
	dom = append(dom, s.domainCookies...)
	s.mu.Unlock()
	e, _ := json.Marshal(exact)
	w, _ := json.Marshal(wild)
	d, _ := json.Marshal(dom)
	return fmt.Sprintf(wsGuardScript, e, w, d)
}
