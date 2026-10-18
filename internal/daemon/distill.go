package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/broker"
	"github.com/domnit/curd/internal/capture"
	"github.com/domnit/curd/internal/distill"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/rpc"
)

// ---------------------------------------------------------------- capture

func (d *Daemon) registerCaptureHandlers() {
	d.register(api.MethodCaptureList, d.handleCaptureList)
	d.register(api.MethodCaptureGet, d.handleCaptureGet)
	d.register(api.MethodCaptureFind, d.handleCaptureFind)
	d.register(api.MethodCaptureExport, d.handleCaptureExport)
}

// captureAudit records a capture API call (never its content).
func (d *Daemon) captureAudit(peer rpc.Peer, c api.Caller, verb, sessionID string, err error) {
	rec := audit.Record{Event: "capture", Verb: verb, ClientPID: peer.PID, ClientExe: peer.Exe, SessionKey: c.SessionKey,
		SessionID: sessionID, Decision: "allow"}
	if err != nil {
		rec.Code = apierr.CodeOf(err)
		rec.Decision = decisionFor(rec.Code)
	}
	d.writeAudit(rec)
}

func (d *Daemon) handleCaptureList(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.CaptureListParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	s, _, err := d.sessionFor(p.Caller, p.SessionID)
	if err != nil {
		d.captureAudit(peer, p.Caller, "list", p.SessionID, err)
		return nil, err
	}
	d.captureAudit(peer, p.Caller, "list", s.ID, nil)
	return api.CaptureListResult{Entries: d.bs.captures.List(s.ID, p.Filter)}, nil
}

func (d *Daemon) handleCaptureGet(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.CaptureGetParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	var sid string
	if owner, ok := d.bs.captures.SessionOf(p.ID); ok {
		sid = owner
	}
	if sid == "" {
		err := apierr.Newf(apierr.NotFound, "list captures with `curd browse capture list`", "no capture %q", p.ID)
		d.captureAudit(peer, p.Caller, "get", "", err)
		return nil, err
	}
	if _, _, err := d.sessionFor(p.Caller, sid); err != nil {
		d.captureAudit(peer, p.Caller, "get", sid, err)
		return nil, err
	}
	det, err := d.bs.captures.Get(p.ID, p.Parts)
	d.captureAudit(peer, p.Caller, "get", sid, err)
	if err != nil {
		return nil, err
	}
	return det, nil
}

func (d *Daemon) handleCaptureFind(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.CaptureFindParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	s, _, err := d.sessionFor(p.Caller, p.SessionID)
	if err == nil {
		var srcs []api.CaptureSource
		if srcs, err = d.bs.captures.FindSource(s.ID, p.Value); err == nil {
			d.captureAudit(peer, p.Caller, "find_source", s.ID, nil)
			return api.CaptureFindResult{Sources: srcs}, nil
		}
	}
	d.captureAudit(peer, p.Caller, "find_source", p.SessionID, err)
	return nil, err
}

func (d *Daemon) handleCaptureExport(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.CaptureExportParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	s, _, err := d.sessionFor(p.Caller, p.SessionID)
	if err == nil {
		var har map[string]any
		if har, err = d.bs.captures.ExportHAR(s.ID, p.IDs); err == nil {
			d.captureAudit(peer, p.Caller, "export", s.ID, nil)
			return api.CaptureExportResult{HAR: har}, nil
		}
	}
	d.captureAudit(peer, p.Caller, "export", p.SessionID, err)
	return nil, err
}

// ---------------------------------------------------------------- distill

func (d *Daemon) registerDistillHandlers() {
	d.register(api.MethodDistillDraft, d.handleDistillDraft)
	d.register(api.MethodDistillVerify, d.handleDistillVerify)
}

func (d *Daemon) distillAudit(peer rpc.Peer, c api.Caller, verb, name, sessionID string, err error) {
	rec := audit.Record{Event: "distill", Verb: verb, Policy: name, ClientPID: peer.PID, ClientExe: peer.Exe,
		SessionKey: c.SessionKey, SessionID: sessionID, Decision: "allow"}
	if err != nil {
		rec.Code = apierr.CodeOf(err)
		rec.Decision = decisionFor(rec.Code)
	}
	d.writeAudit(rec)
}

func (d *Daemon) draftPath(name string) string {
	return filepath.Join(d.cfg.Paths.PolicyDir, name+".draft.yaml")
}

func (d *Daemon) handleDistillDraft(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.DistillDraftParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	res, sid, err := d.distillDraft(&p)
	d.distillAudit(peer, p.Caller, "draft", p.Name, sid, err)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) distillDraft(p *api.DistillDraftParams) (*api.DistillDraftResult, string, error) {
	if !policyNameRe.MatchString(p.Name) {
		return nil, "", apierr.New(apierr.InvalidRequest, "invalid policy name", "names contain letters, digits, '-' and '_'; e.g. `curd distill draft settings c3 c7`")
	}
	if len(p.IDs) == 0 {
		return nil, "", apierr.New(apierr.InvalidRequest, "select at least one capture id",
			"list them with `curd browse capture list`, then `curd distill draft "+p.Name+" <id>...`")
	}
	if d.policies.current().set.Get(p.Name) != nil {
		return nil, "", apierr.Newf(apierr.InvalidRequest, "choose a different draft name; an active policy cannot be replaced by a draft",
			"a policy named %q is already active", p.Name)
	}
	s, m, err := d.sessionFor(p.Caller, p.SessionID)
	if err != nil {
		return nil, "", err
	}
	entries, err := d.bs.captures.Entries(s.ID, p.IDs)
	if err != nil {
		return nil, s.ID, err
	}
	pol, cmds, err := distill.Draft(p.Name, entries)
	if err != nil {
		return nil, s.ID, apierr.New(apierr.InvalidRequest, err.Error(), "select requests to hosts the session visited, e.g. XHR/Fetch calls from `curd browse capture list --type XHR`")
	}
	if hm := d.hostMap(m.policies); len(hm) > 0 {
		// Test mode only: lets verify and fetch reach the mock. Only the draft's own hosts.
		own := map[string]string{}
		for _, h := range pol.Match.Hosts {
			if ip, ok := hm[strings.ToLower(h)]; ok {
				own[strings.ToLower(h)] = ip
			}
		}
		if len(own) > 0 {
			pol.Test = &policy.TestSection{HostMap: own}
		}
	}
	data, err := policy.Marshal(pol)
	if err != nil {
		return nil, s.ID, apierr.New(apierr.Internal, err.Error(), "")
	}
	path := d.draftPath(p.Name)
	if _, err := policy.Parse(data, path); err != nil {
		return nil, s.ID, apierr.Newf(apierr.Internal, "", "the generated draft is invalid: %v", err)
	}
	if err := os.MkdirAll(d.cfg.Paths.PolicyDir, 0o700); err != nil {
		return nil, s.ID, apierr.Newf(apierr.Internal, "", "create %s: %v", d.cfg.Paths.PolicyDir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, s.ID, apierr.Newf(apierr.Internal, "", "write %s: %v", path, err)
	}
	d.bs.mu.Lock()
	d.bs.drafts[p.Name] = draftMeta{sessionID: s.ID, ids: append([]string(nil), p.IDs...)}
	d.bs.mu.Unlock()
	return &api.DistillDraftResult{Name: p.Name, Path: path, YAML: string(data), Commands: cmds}, s.ID, nil
}

func (d *Daemon) handleDistillVerify(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.DistillVerifyParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	res, sid, err := d.distillVerify(ctx, &p)
	d.distillAudit(peer, p.Caller, "verify", p.Draft, sid, err)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) distillVerify(ctx context.Context, p *api.DistillVerifyParams) (*api.DistillVerifyResult, string, error) {
	if !policyNameRe.MatchString(p.Draft) {
		return nil, "", apierr.New(apierr.InvalidRequest, "invalid draft name", "names contain letters, digits, '-' and '_'")
	}
	draft := d.policies.current().set.GetAny(p.Draft)
	if draft == nil || !draft.IsDraft() {
		return nil, "", apierr.Newf(apierr.NotFound, "create one with `curd distill draft "+p.Draft+" <capture ids>`; list policies and drafts with `curd policies ls`",
			"no draft policy named %q", p.Draft)
	}

	d.bs.mu.Lock()
	dm, known := d.bs.drafts[p.Draft]
	d.bs.mu.Unlock()
	sessionID := ""
	if known {
		sessionID = dm.sessionID
	}
	s, m, err := d.sessionFor(p.Caller, sessionID)
	if err != nil {
		if known && apierr.CodeOf(err) == apierr.NotFound {
			return nil, sessionID, apierr.Newf(apierr.NotFound,
				"keep the exploration session open until the draft is verified: reopen one with `curd session open <policy> --explore` and capture the requests again",
				"the exploration session %s that produced draft %q is closed, so its captures are gone", sessionID, p.Draft)
		}
		return nil, sessionID, err
	}
	// The replay sends the draft's cookies to its hosts: the caller must hold
	// access to every one of them through the exploration session's grants.
	for _, h := range draft.Match.Hosts {
		if !m.covers(h) {
			return nil, s.ID, apierr.Newf(apierr.DeniedNoGrant,
				fmt.Sprintf("the draft reaches %s, which none of this session's policies (%s) cover; open a session with a policy for that host (`curd session open <policy> %s ...`) or draft only requests to hosts you were granted",
					h, strings.Join(m.policyNames(), ", "), strings.Join(m.policyNames(), " ")),
				"draft %q is not covered by your grant: host %q is outside the session's policies", p.Draft, h)
		}
	}
	ids := p.IDs
	if len(ids) == 0 {
		ids = dm.ids
	}
	entries, err := d.bs.captures.Entries(s.ID, ids)
	if err != nil {
		return nil, s.ID, err
	}
	if len(entries) == 0 {
		return nil, s.ID, apierr.New(apierr.InvalidRequest, "no captured requests to replay", "pass capture ids: `curd distill verify "+p.Draft+" <id>...`")
	}

	// Replaying a write needs a write grant covering the exploration
	// session's policies, and a non-safe request must never be sent more
	// than once. distill.Verify replays every entry again when minimizing
	// headers, so safe-method entries are verified (and minimized) in one
	// call and write entries in a second call without minimize, which sends
	// each of them exactly once. Write entries without the grant are
	// skipped with a reason and never reach the broker.
	canWrite := d.holdsWrite(m)
	var safe, writes []*capture.Entry
	skipped := map[string]string{}
	for _, e := range entries {
		switch {
		case isSafeMethod(e.Method):
			safe = append(safe, e)
		case canWrite:
			writes = append(writes, e)
		default:
			skipped[e.ID] = "replaying a write needs a write grant for this session's policies; open the session with `curd session open " +
				strings.Join(m.policyNames(), " ") + " --write` and verify again"
		}
	}
	replayer := brokerReplayer{d: d, scopes: d.grantScopes(m)}
	var safeRes, writeRes *api.DistillVerifyResult
	var narrowed *policy.Policy
	var err2 error
	if len(safe) > 0 {
		safeRes, narrowed, err2 = distill.Verify(ctx, draft, safe, replayer, p.Minimize)
	}
	if err2 == nil && len(writes) > 0 {
		writeRes, _, err2 = distill.Verify(ctx, draft, writes, replayer, false)
	}
	if err2 != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, s.ID, apierr.New(apierr.Internal, "verification was cancelled", "retry")
		}
		return nil, s.ID, apierr.As(err2)
	}
	res := &api.DistillVerifyResult{Items: []api.VerifyItem{}}
	items := map[string]api.VerifyItem{}
	for _, r := range []*api.DistillVerifyResult{safeRes, writeRes} {
		if r == nil {
			continue
		}
		for _, it := range r.Items {
			items[it.ID] = it
		}
		if res.YAML == "" {
			res.YAML = r.YAML
		}
	}
	if res.YAML == "" {
		if data, merr := policy.Marshal(draft); merr == nil {
			res.YAML = string(data)
		}
	}
	failures, tested := 0, 0
	for _, e := range entries {
		it, ok := items[e.ID]
		if !ok {
			it = api.VerifyItem{ID: e.ID, Method: e.Method, URL: e.URL, CapturedStatus: e.Status, Skipped: skipped[e.ID]}
		}
		if it.Skipped == "" {
			tested++
			if !it.OK {
				failures++
			}
		}
		res.Items = append(res.Items, it)
	}
	res.OK = tested > 0 && failures == 0
	if narrowed != nil {
		data, merr := policy.Marshal(narrowed)
		if merr == nil {
			if werr := os.WriteFile(d.draftPath(p.Draft), data, 0o600); werr != nil {
				return nil, s.ID, apierr.Newf(apierr.Internal, "", "save the narrowed draft: %v", werr)
			}
			res.YAML = string(data)
		}
	}
	return res, s.ID, nil
}

// brokerReplayer replays a captured request through the fetch broker under a
// draft policy, exactly as `curd fetch` would after approval.
type brokerReplayer struct {
	d      *Daemon
	scopes []string // scopes of the exploration session's grants
}

func (r brokerReplayer) Replay(ctx context.Context, pol *policy.Policy, req distill.ReplayRequest) (*distill.ReplayResponse, error) {
	u, err := url.Parse(req.URL)
	if err != nil || u.Host == "" {
		return nil, apierr.New(apierr.InvalidRequest, "invalid request URL", "")
	}
	if err := r.d.precheck(pol, u, req.Body); err != nil {
		return nil, err
	}
	dec := pol.Check(ctx, policy.CheckRequest{Method: strings.ToUpper(req.Method), URL: u, Headers: req.Headers, Body: req.Body})
	if !dec.Allowed {
		return nil, dec.Error()
	}
	resp, err := r.d.broker.Do(ctx, pol, broker.Request{Method: req.Method, URL: req.URL, Headers: req.Headers, Body: req.Body, Scopes: r.scopes})
	if err != nil {
		return nil, apierr.As(err)
	}
	return &distill.ReplayResponse{Status: resp.Status, Headers: resp.Headers, Body: resp.Body}, nil
}

func isSafeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// grantScopes is the union of the scopes of the session's live grants,
// looked up by id.
func (d *Daemon) grantScopes(m *sessMeta) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range m.grantIDs {
		if g, ok := d.grants.Get(id); ok {
			for _, sc := range g.Scopes {
				if !seen[sc] {
					seen[sc] = true
					out = append(out, sc)
				}
			}
		}
	}
	return out
}

// holdsWrite reports whether every grant the session depends on is live and
// carries the write scope.
func (d *Daemon) holdsWrite(m *sessMeta) bool {
	if len(m.grantIDs) == 0 {
		return false
	}
	for _, id := range m.grantIDs {
		g, ok := d.grants.Get(id)
		if !ok || !slices.Contains(g.Scopes, grants.ScopeWrite) {
			return false
		}
	}
	return true
}
