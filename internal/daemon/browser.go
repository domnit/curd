package daemon

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/browser"
	"github.com/domnit/curd/internal/capture"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/redact"
	"github.com/domnit/curd/internal/rpc"
)

const sessionHint = "open one with `curd session open <policy>` (see `curd policies ls`), or pass --session <id>"

// sessMeta is the daemon-side record of a browser session: who may use it
// and which grants it depends on. The browser package knows only the owner.
type sessMeta struct {
	id         string
	grantIDs   []string // one live grant per policy (an "allow once" consent is replaced by an internal session-lifetime grant); the first is the browser Owner
	sessionKey string
	policies   []*policy.Policy
	write      bool
	explore    bool
}

func (m *sessMeta) policyNames() []string {
	out := make([]string, len(m.policies))
	for i, p := range m.policies {
		out[i] = p.Name
	}
	return out
}

func (m *sessMeta) hasGrant(id string) bool {
	for _, g := range m.grantIDs {
		if g == id {
			return true
		}
	}
	return false
}

// covers reports whether the session's policies cover host.
func (m *sessMeta) covers(host string) bool {
	for _, p := range m.policies {
		if p.MatchesHost(host) {
			return true
		}
	}
	return false
}

// draftMeta remembers where a draft came from so verify can default its
// capture ids and find the exploration session.
type draftMeta struct {
	sessionID string
	ids       []string
}

// browserState is the daemon's browser sessions, capture store and drafts.
type browserState struct {
	mgr      *browser.Manager
	captures *capture.Store

	mu     sync.Mutex
	sess   map[string]*sessMeta
	order  []string // open order
	drafts map[string]draftMeta
}

// recorderAdapter lets capture.Recorder satisfy browser.Recorder (the two
// packages declare identical but distinct BlockedRequest types).
type recorderAdapter struct{ *capture.Recorder }

func (r recorderAdapter) MarkBlocked(id, reason string, blockedWrite bool, req browser.BlockedRequest) {
	r.Recorder.MarkBlocked(id, reason, blockedWrite, capture.BlockedRequest(req))
}

// registerBrowser creates the capture store and browser manager and
// registers the session, browse, capture and distill methods.
func (d *Daemon) registerBrowser() {
	b := &browserState{
		captures: capture.NewStore(capture.Options{}),
		sess:     map[string]*sessMeta{},
		drafts:   map[string]draftMeta{},
	}
	d.bs = b
	opts := browser.Options{
		Test: d.Test(),
		Load: d.loadForBrowser,
		Recorders: func(id string, red *redact.Redactor, body, postData browser.BodyFetcher) browser.Recorder {
			return recorderAdapter{b.captures.NewRecorder(id, red, capture.BodyFetcher(body), capture.BodyFetcher(postData))}
		},
		OnEvent: d.sessionEvent,
	}
	opts.Binary = d.chromeBin
	if d.Test() {
		opts.TempRoot = filepath.Join(d.cfg.Test.Dir, "tmp")
		_ = os.MkdirAll(opts.TempRoot, 0o700)
	}
	b.mgr = browser.NewManager(opts)

	d.SetSessionCounter(b.mgr.Len)
	d.OnShutdown(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b.mgr.CloseAll(ctx)
	})
	d.OnGrantRevoked(d.closeForGrant)

	d.register(api.MethodOpenSession, d.handleOpenSession)
	d.register(api.MethodCloseSession, d.handleCloseSession)
	d.register(api.MethodSessionsList, d.handleSessionsList)
	d.register(api.MethodBrowse, d.handleBrowse)
	d.registerCaptureHandlers()
	d.registerDistillHandlers()
}

// loadForBrowser gives a browser session the credentials the fetch broker
// would use for p, including cookies learned from Set-Cookie responses.
func (d *Daemon) loadForBrowser(ctx context.Context, p *policy.Policy) (*creds.Credentials, error) {
	e, err := d.sources.Get(ctx, p, false)
	if err != nil {
		return nil, err
	}
	return &creds.Credentials{
		Cookies:      e.Jar.All(time.Now()),
		LocalStorage: append([]creds.LocalStorageItem(nil), e.LocalStorage...),
		Profile:      e.Profile,
	}, nil
}

// closeForGrant closes the sessions that depend on a grant that ended.
func (d *Daemon) closeForGrant(g *grants.Grant) {
	b := d.bs
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b.mgr.CloseOwner(ctx, g.ID)
	b.mu.Lock()
	var ids []string
	for id, m := range b.sess {
		if m.hasGrant(g.ID) {
			ids = append(ids, id)
		}
	}
	b.mu.Unlock()
	for _, id := range ids {
		_ = b.mgr.Close(ctx, id)
	}
}

// sessionEvent turns browser events into audit records. The open event is
// audited by handleOpenSession, which knows the caller. Nothing here carries
// a value: details are already redacted and only host and path are kept.
func (d *Daemon) sessionEvent(ev browser.SessionEvent) {
	b := d.bs
	b.mu.Lock()
	m := b.sess[ev.SessionID]
	b.mu.Unlock()
	if ev.Type == "close" {
		b.captures.Drop(ev.SessionID)
		b.mu.Lock()
		delete(b.sess, ev.SessionID)
		for i, id := range b.order {
			if id == ev.SessionID {
				b.order = append(b.order[:i], b.order[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
	}
	if m == nil || ev.Type == "open" {
		return
	}
	rec := audit.Record{
		SessionID: ev.SessionID, GrantID: ev.Owner, SessionKey: m.sessionKey,
		Policy: joinPolicies(m.policyNames()), Decision: "allow",
	}
	if ev.Explore {
		rec.Tags = []string{"explore"}
	}
	switch ev.Type {
	case "close":
		rec.Event = "session_close"
	case "verb":
		rec.Event, rec.Verb, rec.Code = "browse", ev.Verb, ev.Error
		rec.Decision = decisionFor(ev.Error)
		if ev.Verb == "open" {
			rec.Host, rec.Path = hostPath(ev.Detail)
		}
	case "blocked":
		rec.Event, rec.Method, rec.Host, rec.Code = "blocked", ev.Method, ev.Host, ev.Reason
		_, rec.Path = hostPath(ev.URL)
		rec.Decision = "deny"
		if ev.BlockedWrite {
			rec.Tags = append(rec.Tags, "blocked_write")
		}
	case "login_end":
		rec.Event = "login_end"
	case "login_post":
		// A login form submission let through during the login phase.
		rec.Event, rec.Method, rec.Host = "login_post", ev.Method, ev.Host
		_, rec.Path = hostPath(ev.URL)
	default:
		return
	}
	d.writeAudit(rec)
}

// hostPath returns the host and query-free path of a URL.
func hostPath(raw string) (host, path string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	return u.Hostname(), audit.RedactPath(u)
}

// ---------------------------------------------------------------- open

func (d *Daemon) handleOpenSession(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.OpenSessionParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	rec := audit.Record{
		Event: "session_open", ClientPID: peer.PID, ClientExe: peer.Exe,
		SessionKey: p.SessionKey, Policy: joinPolicies(p.Policies),
	}
	if p.Explore {
		rec.Tags = []string{"explore"}
	}
	res, grantID, err := d.openSession(ctx, peer, &p)
	if err != nil {
		rec.Code = apierr.CodeOf(err)
		rec.Decision = decisionFor(rec.Code)
	} else {
		rec.Decision, rec.SessionID, rec.GrantID = "allow", res.SessionID, grantID
		rec.Tags = append(rec.Tags, res.Seed)
		if p.AllowWrites {
			rec.Tags = append(rec.Tags, "write")
		}
	}
	d.writeAudit(rec)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) openSession(ctx context.Context, peer rpc.Peer, p *api.OpenSessionParams) (*api.OpenSessionResult, string, error) {
	if len(p.Policies) == 0 {
		return nil, "", apierr.New(apierr.InvalidRequest, "name at least one policy", "e.g. `curd session open app`; list policies with `curd policies ls`")
	}
	ttl := browser.DefaultTTL
	if p.TTL != "" {
		t, err := ParseTTL(p.TTL)
		if err != nil {
			return nil, "", apierr.New(apierr.InvalidRequest, err.Error(), "use a duration like 30m, 2h or 1d")
		}
		ttl = t
	}
	seed := p.Seed
	switch seed {
	case "", browser.SeedHoist, browser.SeedLogin:
	default:
		return nil, "", apierr.Newf(apierr.InvalidRequest, `use --hoist or --login (seed "hoist" or "login")`, "unknown seed %q", seed)
	}

	view := d.policies.current()
	var pols []*policy.Policy
	seen := map[string]bool{}
	for _, n := range p.Policies {
		pol := view.set.Get(n)
		if pol == nil {
			if dr := view.set.GetAny(n); dr != nil && dr.IsDraft() {
				return nil, "", apierr.Newf(apierr.DeniedNoPolicy, "activate it with `curd policies approve "+n+"`", "policy %q is a draft and is inert until approved", n)
			}
			return nil, "", apierr.Newf(apierr.DeniedNoPolicy, view.noPolicyHint(""), "no policy named %q", n)
		}
		if !seen[n] {
			seen[n] = true
			pols = append(pols, pol)
		}
	}

	// Consent: the same path as fetch, once per policy.
	scope, detail := grants.ScopeRead, ""
	if p.AllowWrites {
		scope, detail = grants.ScopeWrite, "open a browser session that may write (POST, PUT, DELETE...)"
	} else {
		detail = "open a read-only browser session"
	}
	fp := &api.FetchParams{Caller: p.Caller}
	meta := &sessMeta{sessionKey: p.SessionKey, policies: pols, write: p.AllowWrites, explore: p.Explore}
	expires := time.Now().Add(ttl)
	var newToken string
	var onceGrants []*grants.Grant // consumed "allow once" grants, to be replaced
	var internal []string          // internal grants minted for this open, revoked if it fails
	fail := func(err error) (*api.OpenSessionResult, string, error) {
		for _, id := range internal {
			d.grants.Revoke(id)
		}
		return nil, "", err
	}
	for _, pol := range pols {
		g, minted, err := d.acquire(ctx, peer, fp, pol, scope, detail)
		if err != nil {
			return fail(err)
		}
		if g.Mode == grants.ModeOnce {
			// A once grant is consumed by the acquire above and cannot own a
			// session. Its consent buys a session-lifetime internal grant
			// instead, so revoking grants closes the session. Internal
			// grants are never reachable by session-key matching.
			onceGrants = append(onceGrants, g)
			meta.grantIDs = append(meta.grantIDs, "")
			continue
		}
		meta.grantIDs = append(meta.grantIDs, g.ID)
		if g.ExpiresAt.Before(expires) {
			expires = g.ExpiresAt
		}
		if minted && newToken == "" {
			newToken = g.Token
		}
	}
	ttl = time.Until(expires)
	if ttl <= 0 {
		return fail(apierr.New(apierr.InvalidToken, "the grant has expired", "request a new one with `curd grants request "+strings.Join(p.Policies, " ")+"`"))
	}
	cl := clientOf(peer)
	oi := 0
	for i, pol := range pols {
		if meta.grantIDs[i] != "" {
			continue
		}
		og := onceGrants[oi]
		oi++
		ig := d.grants.Mint(grants.MintSpec{
			Policies: []string{pol.Name}, Scopes: og.Scopes, Mode: grants.ModeSession, TTL: ttl,
			SessionKey: fp.SessionKey, SessionKeySource: fp.SessionKeySource,
			ClientPID: cl.PID, ClientExe: cl.Exe, Purpose: "browser session", Internal: true,
		})
		internal = append(internal, ig.ID)
		meta.grantIDs[i] = ig.ID
		d.writeAudit(audit.Record{
			Event: "grant", ClientPID: cl.PID, ClientExe: cl.Exe, GrantID: ig.ID, TokenHash: audit.HashToken(ig.Token),
			SessionKey: fp.SessionKey, Policy: pol.Name, Decision: "allow", Tags: []string{"session", scope, "internal"},
		})
	}

	if seed == "" {
		seed = d.defaultSeed(ctx, pols)
	}
	spec := browser.OpenSpec{
		Policies: pols, Owner: meta.grantIDs[0], TTL: ttl, AllowWrites: p.AllowWrites,
		Seed: seed, LoginURL: p.LoginURL, Explore: p.Explore, HostMap: d.hostMap(pols),
	}
	s, err := d.bs.mgr.Open(ctx, spec)
	if err != nil {
		return fail(err)
	}
	meta.id = s.ID
	for _, id := range internal {
		d.grants.SetPurpose(id, "browser session "+s.ID)
	}
	d.bs.mu.Lock()
	d.bs.sess[s.ID] = meta
	d.bs.order = append(d.bs.order, s.ID)
	d.bs.mu.Unlock()
	return &api.OpenSessionResult{SessionID: s.ID, ExpiresAt: s.ExpiresAt, Seed: s.Seed, NewToken: newToken}, meta.grantIDs[0], nil
}

// defaultSeed is "hoist" when the credential source holds anything for the
// policies, else "login".
func (d *Daemon) defaultSeed(ctx context.Context, pols []*policy.Policy) string {
	for _, pol := range pols {
		e, err := d.sources.Get(ctx, pol, false)
		if err != nil {
			d.log.Printf("session seed: credentials for policy %s unavailable (%s); defaulting to interactive login", pol.Name, apierrMessage(err))
			return browser.SeedLogin
		}
		if e.Jar.Len() > 0 || len(e.LocalStorage) > 0 {
			return browser.SeedHoist
		}
	}
	return browser.SeedLogin
}

// hostMap is the union of the policies' test.host_map (test mode only).
func (d *Daemon) hostMap(pols []*policy.Policy) map[string]string {
	if !d.Test() {
		return nil
	}
	m := map[string]string{}
	for _, p := range pols {
		if p.Test != nil {
			for h, ip := range p.Test.HostMap {
				m[strings.ToLower(h)] = ip
			}
		}
	}
	return m
}

// ---------------------------------------------------------------- ownership

// authorizeSession checks that the caller may use m (see the package notes in
// the task: token's grant id, or same session key plus a live grant).
func (d *Daemon) authorizeSession(c api.Caller, m *sessMeta) error {
	notYours := apierr.Newf(apierr.NotFound, sessionHint, "no browser session %q for this caller", m.id)
	if c.Token != "" {
		g, ok := d.grants.Get(c.Token)
		if !ok {
			return apierr.New(apierr.InvalidToken, "unknown, revoked or expired session token",
				"drop the token, or open a new session with `curd session open <policy>`")
		}
		if m.hasGrant(g.ID) {
			return nil
		}
		return notYours
	}
	if c.SessionKey != m.sessionKey {
		return notYours
	}
	// Same key is not enough: every grant the session depends on (looked up
	// by id, so an unrelated grant with the same key does not count) must
	// still be live.
	for _, id := range m.grantIDs {
		if _, ok := d.grants.Get(id); !ok {
			return notYours
		}
	}
	return nil
}

// sessionFor resolves a session id (empty means the caller's most recent
// session) and checks ownership.
func (d *Daemon) sessionFor(c api.Caller, id string) (*browser.Session, *sessMeta, error) {
	b := d.bs
	if id == "" {
		b.mu.Lock()
		var ids []string
		for i := len(b.order) - 1; i >= 0; i-- {
			ids = append(ids, b.order[i])
		}
		b.mu.Unlock()
		var firstErr error
		for _, sid := range ids {
			s, m, err := d.sessionFor(c, sid)
			if err == nil {
				return s, m, nil
			}
			if firstErr == nil || apierr.CodeOf(err) == apierr.InvalidToken {
				firstErr = err
			}
		}
		if apierr.CodeOf(firstErr) == apierr.InvalidToken {
			return nil, nil, firstErr
		}
		return nil, nil, apierr.New(apierr.NotFound, "you have no open browser session", sessionHint)
	}
	b.mu.Lock()
	m := b.sess[id]
	b.mu.Unlock()
	s, ok := b.mgr.Get(id)
	if m == nil || !ok {
		return nil, nil, apierr.Newf(apierr.NotFound, sessionHint, "no open browser session %q (closed, expired or never opened)", id)
	}
	if err := d.authorizeSession(c, m); err != nil {
		return nil, nil, err
	}
	return s, m, nil
}

// ---------------------------------------------------------------- close / browse

func (d *Daemon) handleCloseSession(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.CloseSessionParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	_, m, err := d.sessionFor(p.Caller, p.SessionID)
	if err != nil {
		d.writeAudit(audit.Record{Event: "session_close", ClientPID: peer.PID, ClientExe: peer.Exe, SessionKey: p.SessionKey,
			SessionID: p.SessionID, Decision: decisionFor(apierr.CodeOf(err)), Code: apierr.CodeOf(err)})
		return nil, err
	}
	// The browser's close event audits the close and drops the capture.
	if err := d.bs.mgr.Close(ctx, m.id); err != nil {
		return nil, apierr.Newf(apierr.BrowserError, "", "closing the browser: %v", err)
	}
	return map[string]bool{"ok": true}, nil
}

func (d *Daemon) handleSessionsList(_ context.Context, _ rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.SessionsListParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	b := d.bs
	b.mu.Lock()
	order := append([]string(nil), b.order...)
	b.mu.Unlock()
	out := api.SessionsListResult{Sessions: []api.SessionInfo{}}
	for _, id := range order {
		s, m, err := d.sessionFor(p.Caller, id)
		if err != nil {
			continue
		}
		out.Sessions = append(out.Sessions, api.SessionInfo{
			SessionID: id, Policies: m.policyNames(), Seed: s.Seed, Write: m.write, Explore: m.explore, ExpiresAt: s.ExpiresAt,
		})
	}
	return out, nil
}

func (d *Daemon) handleBrowse(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.BrowseParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.Verb == "" {
		return nil, apierr.New(apierr.InvalidRequest, "name a verb", "e.g. `curd browse open <url>`; `curd browse --help` lists the verbs")
	}
	s, m, err := d.sessionFor(p.Caller, p.SessionID)
	if err != nil {
		d.writeAudit(audit.Record{Event: "browse", ClientPID: peer.PID, ClientExe: peer.Exe, SessionKey: p.SessionKey,
			SessionID: p.SessionID, Verb: strings.ToLower(p.Verb), Decision: decisionFor(apierr.CodeOf(err)), Code: apierr.CodeOf(err)})
		return nil, err
	}
	d.touch(m)
	return s.Do(ctx, p.Verb, p.Args)
}

// touch records a use of the session's own grants (by id, never by session
// key, so it cannot consume an unrelated "once" grant) so an active session
// does not idle out.
func (d *Daemon) touch(m *sessMeta) {
	for _, id := range m.grantIDs {
		d.grants.Touch(id)
	}
}
