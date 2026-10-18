package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/redact"
)

// Session is one ephemeral browser. Agents only ever call Do.
type Session struct {
	ID        string
	ExpiresAt time.Time
	Seed      string

	m     *Manager
	opts  *Options
	owner string
	spec  OpenSpec
	red   *redact.Redactor
	rec   Recorder

	br    *chrome.Browser
	conn  *cdp.Conn
	ctxID string // the one off-the-record browser context
	dir   string // temp user-data-dir

	ctx    context.Context // cancelled on shutdown
	cancel context.CancelFunc
	done   chan struct{}
	timer  *time.Timer
	unsub  func()

	startURL string
	// loginUntil ends the login phase of a login-seeded session (see
	// inLoginPhase); zero when there is none.
	loginUntil time.Time
	lsScript   string
	// loginBase is the set of cookies seen before the first login form
	// submission; sites set anonymous cookies on the login page itself, so
	// those join the base (nil until taken).
	loginBase map[string]bool
	// loginPosted is set once a login form submission was let through. Only
	// after it does a new credential cookie end the login phase.
	loginPosted bool
	// domainCookies lists the domains of seeded domain cookies (lowercase,
	// no leading dot): non-policy hosts under them are never contacted.
	domainCookies []string

	verbMu sync.Mutex

	mu           sync.Mutex
	changed      chan struct{}
	targets      map[string]*target // by CDP session id
	pages        []*page
	active       *page
	inflight     map[string]string
	blockSeq     int
	lastDocBlock *blockRec
	secrets      map[string]string // test mode only: injected value -> placeholder, for the profile assertion
	closed       bool

	closeOnce sync.Once
	closeErr  error
}

type target struct {
	sid      string
	targetID string
	typ      string
	pg       *page
}

type page struct {
	targetID string
	sid      string
	loaded   map[string]bool // loaderIds that reached "load"
	navTick  int             // load events and same-document navigations
	loading  bool
	isoCtx   int64
	block    *blockRec // most recent blocked main-frame Document request
}

type blockRec struct {
	seq    int
	err    *apierr.Error
	reason string
	host   string
}

func newSession(m *Manager, spec OpenSpec) (*Session, error) {
	ctx, cancel := context.WithCancel(context.Background())
	now := m.opts.Now()
	s := &Session{
		ID:        newID(),
		ExpiresAt: now.Add(spec.TTL),
		Seed:      spec.Seed,
		m:         m,
		opts:      &m.opts,
		owner:     spec.Owner,
		spec:      spec,
		red:       redact.New(),
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		changed:   make(chan struct{}),
		targets:   map[string]*target{},
		inflight:  map[string]string{},
		secrets:   map[string]string{},
	}
	return s, nil
}

// Redactor returns the session's redactor, which holds every credential
// value the session knows.
func (s *Session) Redactor() *redact.Redactor { return s.red }

// Owner returns the grant id the session was opened for.
func (s *Session) Owner() string { return s.owner }

// ProfileDir returns the temp user-data-dir (tests use it for the profile
// assertion). It is deleted on close.
func (s *Session) ProfileDir() string { return s.dir }

// PolicyHosts lists the host patterns the session may navigate to.
func (s *Session) PolicyHosts() []string {
	var out []string
	for _, p := range s.spec.Policies {
		out = append(out, p.Match.Hosts...)
	}
	return out
}

func (s *Session) emit(ev SessionEvent) {
	if s.opts.OnEvent == nil {
		return
	}
	ev.SessionID = s.ID
	ev.Owner = s.owner
	ev.Time = s.opts.Now()
	ev.Explore = s.spec.Explore
	ev.Seed = s.Seed
	ev.Test = s.opts.Test
	s.opts.OnEvent(ev)
}

func (s *Session) call(ctx context.Context, sid, method string, params, out any) error {
	return s.conn.Call(ctx, sid, method, params, out)
}

func (s *Session) bump() {
	s.mu.Lock()
	s.bumpLocked()
	s.mu.Unlock()
}

func (s *Session) bumpLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// waitFor blocks until cond (evaluated under s.mu) is true. It returns false
// on timeout, cancellation or session close.
func (s *Session) waitFor(ctx context.Context, timeout time.Duration, cond func() bool) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		s.mu.Lock()
		ok := cond()
		ch := s.changed
		s.mu.Unlock()
		if ok {
			return true
		}
		select {
		case <-ch:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		case <-s.ctx.Done():
			return false
		}
	}
}

// ---------------------------------------------------------------- launch

func (s *Session) start(ctx context.Context) error {
	o := s.opts
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	dir, err := os.MkdirTemp(o.TempRoot, "curd-browser-")
	if err != nil {
		return apierr.Newf(apierr.BrowserError, "", "create temp profile: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return apierr.Newf(apierr.BrowserError, "", "chmod temp profile: %v", err)
	}
	s.dir = dir

	// Resolve the login URL first so a bad one fails before launching.
	if s.spec.Seed == SeedLogin {
		u, err := s.loginURL()
		if err != nil {
			return err
		}
		s.startURL = u
		s.loginUntil = s.opts.Now().Add(LoginPhase)
	}

	args := []string{"--disable-features=BackForwardCache", "--disable-extensions"}
	if o.Test {
		hm := map[string]string{}
		for h, ip := range o.HostMap {
			hm[h] = ip
		}
		for h, ip := range s.spec.HostMap {
			hm[h] = ip
		}
		var rules []string
		for h, ip := range hm {
			rules = append(rules, "MAP "+h+" "+ip)
		}
		sortStrings(rules)
		rules = append(rules, "EXCLUDE localhost")
		args = append(args, "--host-resolver-rules="+strings.Join(rules, ", "),
			"--ignore-certificate-errors", "--no-proxy-server")
	}
	br, err := chrome.Launch(ctx, chrome.LaunchOptions{
		Binary:       o.Binary,
		UserDataDir:  dir,
		Headless:     o.Headless || o.Test,
		MockKeychain: o.Test, // never in production (spec 9.1)
		ExtraArgs:    args,
	})
	if err != nil {
		return apierr.Newf(apierr.BrowserError, "install Google Chrome, or set chrome_binary: in ~/.config/curd/config.yaml (CURD_CHROME works in test mode only)", "launch browser: %v", err)
	}
	s.br, s.conn = br, br.Conn

	if o.Recorders != nil {
		s.rec = o.Recorders(s.ID, s.red, s.bodyFetcher("Network.getResponseBody"), s.postDataFetcher)
	}
	s.unsub = s.conn.Subscribe(s.onEvent)

	var bc struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := s.call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &bc); err != nil {
		return browserErr("create off-the-record context: %v", err)
	}
	s.ctxID = bc.BrowserContextID

	if err := s.call(ctx, "", "Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}, nil); err != nil {
		return browserErr("set auto-attach: %v", err)
	}

	if s.spec.Seed == SeedHoist {
		if err := s.seedHoist(ctx); err != nil {
			return err
		}
	}

	if err := s.closeForeignTargets(ctx); err != nil {
		return err
	}
	pg, err := s.createPage(ctx, "about:blank")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.active = pg
	s.mu.Unlock()
	s.startURL = firstNonEmpty(s.startURL, "about:blank")

	if s.spec.Seed == SeedLogin {
		if err := s.navigate(ctx, pg, s.startURL); err != nil {
			return err
		}
	}
	s.refreshRedactor(ctx) // login mode: also takes the baseline cookie set
	go s.refreshLoop()
	return nil
}

func firstNonEmpty(a ...string) string {
	for _, x := range a {
		if x != "" {
			return x
		}
	}
	return ""
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (s *Session) loginURL() (string, error) {
	u := s.spec.LoginURL
	if u == "" {
		for _, p := range s.spec.Policies {
			for _, h := range p.Match.Hosts {
				if !strings.HasPrefix(h, "*.") {
					u = "https://" + h + "/"
					break
				}
			}
			if u != "" {
				break
			}
		}
		if u == "" {
			return "", apierr.New(apierr.InvalidRequest, "no login URL: the policies only have wildcard hosts", "pass login_url")
		}
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Hostname() == "" {
		return "", apierr.Newf(apierr.InvalidRequest, "pass an absolute https:// URL on a policy host", "invalid login URL %q", u)
	}
	if err := s.checkNavigable(pu); err != nil {
		return "", err
	}
	return u, nil
}

// closeForeignTargets closes any page that exists outside our context (the
// browser's initial window, for instance).
func (s *Session) closeForeignTargets(ctx context.Context) error {
	var res struct {
		TargetInfos []targetInfo `json:"targetInfos"`
	}
	if err := s.call(ctx, "", "Target.getTargets", nil, &res); err != nil {
		return browserErr("list targets: %v", err)
	}
	for _, ti := range res.TargetInfos {
		if ti.Type == "page" && ti.BrowserContextID != s.ctxID {
			_ = s.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": ti.TargetID}, nil)
		}
	}
	return nil
}

type targetInfo struct {
	TargetID         string `json:"targetId"`
	Type             string `json:"type"`
	Title            string `json:"title"`
	URL              string `json:"url"`
	BrowserContextID string `json:"browserContextId"`
	OpenerID         string `json:"openerId"`
}

// createPage opens a new page in our context and waits until interception is
// installed on it.
func (s *Session) createPage(ctx context.Context, u string) (*page, error) {
	var res struct {
		TargetID string `json:"targetId"`
	}
	if err := s.call(ctx, "", "Target.createTarget", map[string]any{"url": u, "browserContextId": s.ctxID}, &res); err != nil {
		return nil, browserErr("create page: %v", err)
	}
	var pg *page
	ok := s.waitFor(ctx, 15*time.Second, func() bool {
		for _, p := range s.pages {
			if p.targetID == res.TargetID {
				pg = p
				return true
			}
		}
		return false
	})
	if !ok {
		return nil, browserErr("new page did not become ready")
	}
	return pg, nil
}

// ---------------------------------------------------------------- events

func (s *Session) onEvent(ev cdp.Event) {
	switch {
	case strings.HasPrefix(ev.Method, "Network."):
		if s.rec != nil {
			s.rec.HandleEvent(ev.SessionID, s.scrubForRecorder(ev))
		}
		s.trackNetwork(ev)
	case ev.Method == "Fetch.requestPaused":
		go s.onPaused(ev)
	case ev.Method == "Target.attachedToTarget":
		s.onAttached(ev)
	case ev.Method == "Target.detachedFromTarget":
		var p struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			s.onDetached(p.SessionID)
		}
	case strings.HasPrefix(ev.Method, "Page."):
		s.onPageEvent(ev)
	}
}

// scrubForRecorder removes the request body from the requestWillBeSent event
// of a Document POST in a login-seeded session before the recorder sees it:
// that body is a login form (it carries the typed password) and must never
// reach the capture API.
func (s *Session) scrubForRecorder(ev cdp.Event) cdp.Event {
	if s.Seed != SeedLogin || ev.Method != "Network.requestWillBeSent" {
		return ev
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(ev.Params, &top) != nil {
		return ev
	}
	var typ string
	_ = json.Unmarshal(top["type"], &typ)
	var req map[string]json.RawMessage
	if typ != "Document" || json.Unmarshal(top["request"], &req) != nil {
		return ev
	}
	var method string
	_ = json.Unmarshal(req["method"], &method)
	if !strings.EqualFold(method, "POST") {
		return ev
	}
	delete(req, "postData")
	delete(req, "postDataEntries")
	req["hasPostData"] = json.RawMessage("false")
	top["request"], _ = json.Marshal(req)
	b, err := json.Marshal(top)
	if err != nil {
		return ev
	}
	ev.Params = b
	return ev
}

func (s *Session) trackNetwork(ev cdp.Event) {
	switch ev.Method {
	case "Network.requestWillBeSent":
		var p struct {
			RequestID string `json:"requestId"`
			Type      string `json:"type"`
		}
		if json.Unmarshal(ev.Params, &p) != nil || p.Type == "EventSource" || p.Type == "WebSocket" {
			return
		}
		s.mu.Lock()
		s.inflight[ev.SessionID+"|"+p.RequestID] = p.Type
		s.bumpLocked()
		s.mu.Unlock()
	case "Network.loadingFinished", "Network.loadingFailed":
		var p struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		s.mu.Lock()
		delete(s.inflight, ev.SessionID+"|"+p.RequestID)
		s.bumpLocked()
		s.mu.Unlock()
	}
}

func (s *Session) onPageEvent(ev cdp.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.targets[ev.SessionID]
	if t == nil || t.pg == nil {
		return
	}
	pg := t.pg
	switch ev.Method {
	case "Page.lifecycleEvent":
		var p struct {
			FrameID  string `json:"frameId"`
			LoaderID string `json:"loaderId"`
			Name     string `json:"name"`
		}
		if json.Unmarshal(ev.Params, &p) == nil && p.Name == "load" && p.FrameID == pg.targetID {
			pg.loaded[p.LoaderID] = true
		}
	case "Page.loadEventFired", "Page.navigatedWithinDocument":
		if ev.Method == "Page.navigatedWithinDocument" {
			var p struct {
				FrameID string `json:"frameId"`
			}
			if json.Unmarshal(ev.Params, &p) != nil || p.FrameID != pg.targetID {
				return
			}
		}
		pg.navTick++
	case "Page.frameNavigated":
		var p struct {
			Frame struct {
				ID       string `json:"id"`
				ParentID string `json:"parentId"`
			} `json:"frame"`
		}
		if json.Unmarshal(ev.Params, &p) == nil && p.Frame.ParentID == "" {
			pg.isoCtx = 0
		}
	case "Page.frameStartedLoading", "Page.frameStoppedLoading":
		var p struct {
			FrameID string `json:"frameId"`
		}
		if json.Unmarshal(ev.Params, &p) == nil && p.FrameID == pg.targetID {
			pg.loading = ev.Method == "Page.frameStartedLoading"
		}
	default:
		return
	}
	s.bumpLocked()
}

func (s *Session) onAttached(ev cdp.Event) {
	var p struct {
		SessionID          string     `json:"sessionId"`
		TargetInfo         targetInfo `json:"targetInfo"`
		WaitingForDebugger bool       `json:"waitingForDebugger"`
	}
	if json.Unmarshal(ev.Params, &p) != nil || p.SessionID == "" {
		return
	}
	ti := p.TargetInfo
	// Children of our own sessions (frames, workers) are ours. A top-level
	// target must be in our context.
	if ev.SessionID == "" && ti.BrowserContextID != s.ctxID {
		go s.rejectForeign(p.SessionID, ti, p.WaitingForDebugger)
		return
	}
	// A visible browser puts its own WebUI (the omnibox popup and the like)
	// in the window's context as "browser_ui" targets. They are browser
	// chrome, not the site: let them run and detach, never close them, and
	// keep them out of capture and pages. Match the type only: a tab the
	// user opens (a "page" at chrome://newtab) can navigate to policy hosts
	// with the seeded cookies, so it stays attached and enforced.
	if ev.SessionID == "" && ti.Type == "browser_ui" {
		go s.releaseBrowserUI(p.SessionID, p.WaitingForDebugger)
		return
	}
	// Register before the event loop moves on, so later events for this
	// session find it.
	t := &target{sid: p.SessionID, targetID: ti.TargetID, typ: ti.Type}
	if ti.Type == "page" {
		t.pg = &page{targetID: ti.TargetID, sid: p.SessionID, loaded: map[string]bool{}}
	}
	s.mu.Lock()
	s.targets[p.SessionID] = t
	s.mu.Unlock()
	go s.setupTarget(t, p.WaitingForDebugger)
}

func (s *Session) releaseBrowserUI(sid string, waiting bool) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if waiting {
		_ = s.call(ctx, sid, "Runtime.runIfWaitingForDebugger", nil, nil)
	}
	_ = s.call(ctx, "", "Target.detachFromTarget", map[string]any{"sessionId": sid}, nil)
}

func (s *Session) rejectForeign(sid string, ti targetInfo, waiting bool) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if ti.Type == "page" {
		_ = s.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": ti.TargetID}, nil)
	}
	_ = s.call(ctx, "", "Target.detachFromTarget", map[string]any{"sessionId": sid}, nil)
}

func (s *Session) onDetached(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.targets[sid]
	delete(s.targets, sid)
	prefix := sid + "|"
	for k := range s.inflight {
		if strings.HasPrefix(k, prefix) {
			delete(s.inflight, k)
		}
	}
	if t != nil && t.pg != nil {
		for i, p := range s.pages {
			if p == t.pg {
				s.pages = append(s.pages[:i], s.pages[i+1:]...)
				break
			}
		}
		if s.active == t.pg {
			s.active = nil
			if n := len(s.pages); n > 0 {
				s.active = s.pages[n-1]
			}
		}
	}
	s.bumpLocked()
}

// setupTarget installs interception on a freshly attached target, then lets
// it run. It fails closed: if interception cannot be installed the whole
// session is torn down rather than leaving an uncontrolled target.
func (s *Session) setupTarget(t *target, waiting bool) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	pageLike := t.typ == "page" || t.typ == "iframe"
	type cmd struct {
		method   string
		params   any
		required bool
	}
	cmds := []cmd{
		{"Network.enable", nil, true},
		{"Fetch.enable", map[string]any{"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}}}, true},
	}
	guard := s.wsGuard()
	if guard != "" && !pageLike {
		// Workers (before they run): Runtime.evaluate on a paused worker.
		cmds = append(cmds, cmd{"Runtime.evaluate", map[string]any{"expression": guard}, t.typ == "worker" || t.typ == "shared_worker"})
	}
	if pageLike {
		cmds = append(cmds,
			cmd{"Page.enable", nil, true},
			cmd{"Page.setLifecycleEventsEnabled", map[string]any{"enabled": true}, true},
			cmd{"Network.setBypassServiceWorker", map[string]any{"bypass": true}, false},
			cmd{"Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true}, false},
		)
		if guard != "" {
			cmds = append(cmds, cmd{"Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": guard}, true})
		}
		if s.lsScript != "" {
			cmds = append(cmds, cmd{"Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": s.lsScript}, true})
		}
	}
	cmds = append(cmds, cmd{"Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}, false})
	for _, c := range cmds {
		if err := s.call(ctx, t.sid, c.method, c.params, nil); err != nil {
			if isGone(err) || s.ctx.Err() != nil {
				return
			}
			if c.required {
				s.failClosed(fmt.Errorf("install %s on %s target: %w", c.method, t.typ, err))
				return
			}
		}
	}
	if waiting {
		if err := s.call(ctx, t.sid, "Runtime.runIfWaitingForDebugger", nil, nil); err != nil && !isGone(err) {
			s.failClosed(fmt.Errorf("resume %s target: %w", t.typ, err))
			return
		}
	}
	if t.pg != nil {
		s.mu.Lock()
		if _, ok := s.targets[t.sid]; ok {
			s.pages = append(s.pages, t.pg)
			if s.active == nil {
				s.active = t.pg
			}
		}
		s.bumpLocked()
		s.mu.Unlock()
	}
}

// failClosed tears the session down after an interception failure.
func (s *Session) failClosed(err error) {
	go func() { _ = s.m.Close(context.Background(), s.ID) }()
	// The session may not be registered yet (still opening); shutdown is
	// idempotent, so also close directly.
	go s.shutdown(context.Background(), "fail closed: "+err.Error())
}

// ---------------------------------------------------------------- bodies

func (s *Session) bodyFetcher(method string) BodyFetcher {
	return func(ctx context.Context, sid, requestID string) ([]byte, bool, error) {
		var out struct {
			Body          string `json:"body"`
			Base64Encoded bool   `json:"base64Encoded"`
		}
		if err := s.call(ctx, sid, method, map[string]any{"requestId": requestID}, &out); err != nil {
			return nil, false, err
		}
		return []byte(out.Body), out.Base64Encoded, nil
	}
}

func (s *Session) postDataFetcher(ctx context.Context, sid, requestID string) ([]byte, bool, error) {
	var out struct {
		PostData      string `json:"postData"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	if err := s.call(ctx, sid, "Network.getRequestPostData", map[string]any{"requestId": requestID}, &out); err != nil {
		return nil, false, err
	}
	return []byte(out.PostData), out.Base64Encoded, nil
}

// ---------------------------------------------------------------- shutdown

func (s *Session) shutdown(ctx context.Context, reason string) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.bumpLocked()
		s.mu.Unlock()
		if s.timer != nil {
			s.timer.Stop()
		}
		s.cancel()
		var err error
		if s.br != nil {
			err = s.br.Close(ctx)
			if s.unsub != nil {
				s.unsub()
			}
		}
		if s.dir != "" {
			if s.opts.Test {
				s.m.addLeaks(s.scanProfile(ctx))
			}
			if rerr := os.RemoveAll(s.dir); rerr != nil && err == nil {
				err = rerr
			}
		}
		s.closeErr = err
		close(s.done)
		s.emit(SessionEvent{Type: "close", Reason: reason})
	})
	<-s.done
	return s.closeErr
}

// ---------------------------------------------------------------- helpers

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) policiesFor(host string) []*policy.Policy {
	var out []*policy.Policy
	for _, p := range s.spec.Policies {
		if p.MatchesHost(host) {
			out = append(out, p)
		}
	}
	return out
}

func headersFromMap(m map[string]string) []api.Header {
	out := make([]api.Header, 0, len(m))
	for k, v := range m {
		out = append(out, api.Header{Name: k, Value: v})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
