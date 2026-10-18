package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/rpc"
)

func (d *Daemon) registerGrantHandlers() {
	d.register(api.MethodGrantsRequest, d.handleGrantsRequest)
	d.register(api.MethodGrantsList, d.handleGrantsList)
	d.register(api.MethodGrantsRevoke, d.handleGrantsRevoke)
	d.register(api.MethodGrantsDerive, func(context.Context, rpc.Peer, json.RawMessage) (any, error) {
		return nil, apierr.New(apierr.NotAvailable, "grants.derive (delegating a narrower token to a subagent) is not built yet",
			"post-v1: request a separate grant for the subagent with `curd grants request <policy>`")
	})
}

// ParseTTL parses a Go duration with an optional "d" (days) suffix.
func ParseTTL(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid ttl %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid ttl %q", s)
	}
	return v, nil
}

func (d *Daemon) handleGrantsRequest(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.GrantsRequestParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	cl := clientOf(peer)
	rec := audit.Record{Event: "grant_request", ClientPID: peer.PID, ClientExe: peer.Exe, SessionKey: p.SessionKey, Policy: joinPolicies(p.Policies)}
	res, err := d.grantsRequest(ctx, cl, &p)
	if err != nil {
		rec.Code = apierr.CodeOf(err)
		rec.Decision = decisionFor(rec.Code)
	} else {
		rec.Decision = "allow"
		rec.GrantID = res.Grant.ID
		rec.TokenHash = res.Grant.TokenHash
	}
	d.writeAudit(rec)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) grantsRequest(ctx context.Context, cl client, p *api.GrantsRequestParams) (*api.GrantsRequestResult, error) {
	if len(p.Policies) == 0 {
		return nil, apierr.New(apierr.InvalidRequest, "name at least one policy", "e.g. `curd grants request app`; list policies with `curd policies ls`")
	}
	view := d.policies.current()
	var hosts []string
	seen := map[string]bool{}
	var names []string
	ttl := time.Duration(0)
	for _, n := range p.Policies {
		pol := view.set.Get(n)
		if pol == nil {
			if dr := view.set.GetAny(n); dr != nil && dr.IsDraft() {
				return nil, apierr.Newf(apierr.DeniedNoPolicy, "activate it with `curd policies approve "+n+"`", "policy %q is a draft and is inert until approved", n)
			}
			return nil, apierr.Newf(apierr.DeniedNoPolicy, view.noPolicyHint(""), "no policy named %q", n)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
		hosts = append(hosts, pol.Match.Hosts...)
		if t := time.Duration(pol.TTLDefault); ttl == 0 || t < ttl {
			ttl = t
		}
	}
	scope := grants.ScopeRead
	for _, s := range p.Scopes {
		switch s {
		case grants.ScopeRead:
		case grants.ScopeWrite:
			scope = grants.ScopeWrite
		default:
			return nil, apierr.Newf(apierr.InvalidRequest, "scopes are \"read\" and \"write\"", "unknown scope %q", s)
		}
	}
	if p.TTL != "" {
		t, err := ParseTTL(p.TTL)
		if err != nil {
			return nil, apierr.New(apierr.InvalidRequest, err.Error(), "use a duration like 30m, 8h or 2d")
		}
		ttl = t
	}
	switch p.Mode {
	case "", grants.ModeOnce, grants.ModeSession:
	default:
		return nil, apierr.Newf(apierr.InvalidRequest, "mode is \"once\" or \"session\"", "unknown mode %q", p.Mode)
	}
	if p.NoPrompt {
		return nil, apierr.New(apierr.DeniedNoGrant, "consent is required and --no-prompt is set",
			"run `curd grants request "+strings.Join(names, " ")+"` without --no-prompt so the user can approve")
	}

	ans, err := d.prompter.Ask(ctx, consent.Prompt{
		Kind: consent.KindGrant, Policies: names, Hosts: hosts, Scope: scope,
		ClientName: cl.Name, ClientPID: cl.PID, Duration: ttl, SessionKey: p.SessionKey, Purpose: p.Purpose,
	})
	d.auditConsent(cl, p.SessionKey, names, scope, ans, err)
	if err != nil {
		return nil, apierr.Newf(apierr.DeniedNoGrant, "ask the user to approve the request; in test mode check the consent script", "consent could not be obtained: %v", err)
	}
	mode := grants.ModeSession
	switch ans {
	case consent.Once:
		mode = grants.ModeOnce
	case consent.Session:
		if p.Mode == grants.ModeOnce {
			mode = grants.ModeOnce
		}
	default:
		return nil, apierr.Newf(apierr.DeniedNoGrant, "ask the user to allow it, then request again",
			"the user denied access to %s", strings.Join(names, ", "))
	}
	g := d.mint(cl, p.Caller, names, scope, mode, ttl, p.Purpose)
	return &api.GrantsRequestResult{Token: g.Token, Grant: d.grants.Info(g)}, nil
}

func (d *Daemon) handleGrantsList(_ context.Context, _ rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.GrantsListParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.Token != "" {
		g, ok := d.grants.Get(p.Token)
		if !ok {
			return nil, apierr.New(apierr.InvalidToken, "unknown, revoked or expired session token", "list all grants without a token, or request a new one with `curd grants request <policy>`")
		}
		return api.GrantsListResult{Grants: []api.GrantInfo{d.grants.Info(g)}}, nil
	}
	return api.GrantsListResult{Grants: d.grants.List()}, nil
}

func (d *Daemon) handleGrantsRevoke(_ context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.GrantsRevokeParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.TokenOrID == "" {
		return nil, apierr.New(apierr.InvalidRequest, "name a grant id, a token or \"all\"", "list grants with `curd grants ls`")
	}
	ids := d.grants.Revoke(p.TokenOrID)
	for _, id := range ids {
		d.writeAudit(audit.Record{Event: "revoke", ClientPID: peer.PID, ClientExe: peer.Exe, GrantID: id, Decision: "allow"})
	}
	if len(ids) == 0 && p.TokenOrID != "all" {
		return nil, apierr.New(apierr.NotFound, "no live grant matches that id or token", "list grants with `curd grants ls`; expired grants are already gone")
	}
	if ids == nil {
		ids = []string{}
	}
	return api.GrantsRevokeResult{Revoked: ids}, nil
}
