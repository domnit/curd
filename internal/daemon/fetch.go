package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/broker"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/rpc"
)

// maxPromptRounds bounds how often one fetch re-prompts after a "once"
// answer was consumed by a concurrent call.
const maxPromptRounds = 5

func (d *Daemon) registerFetchHandlers() {
	d.register(api.MethodFetch, d.handleFetch)
}

// decisionFor maps an error code to the audit decision field.
func decisionFor(code string) string {
	switch {
	case code == "":
		return "allow"
	case strings.HasPrefix(code, "denied_"), code == apierr.InvalidToken:
		return "deny"
	default:
		return "error"
	}
}

// handleFetch implements spec section 8 (with 6.3 and 7.5): resolve the
// policy, check the request against it, find or obtain a grant, send, audit.
func (d *Daemon) handleFetch(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.FetchParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	start := time.Now()
	rec := audit.Record{
		Event: "fetch", ClientPID: peer.PID, ClientExe: peer.Exe,
		SessionKey: p.SessionKey, Policy: p.Policy, Method: strings.ToUpper(p.Method),
	}
	if p.Token != "" {
		rec.TokenHash = audit.HashToken(p.Token)
	}
	if p.Explain {
		rec.Tags = []string{"explain"}
	}
	res, err := d.fetch(ctx, peer, &p, &rec)
	rec.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		rec.Code = apierr.CodeOf(err)
		rec.Decision = decisionFor(rec.Code)
	} else {
		rec.Decision = "allow"
		if res.Explain != nil && !res.Explain.Allowed {
			rec.Decision, rec.Code = "deny", res.Explain.Code
		}
		rec.Status = res.Status
		rec.Bytes = int64(len(res.Body))
	}
	d.writeAudit(rec)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (d *Daemon) fetch(ctx context.Context, peer rpc.Peer, p *api.FetchParams, rec *audit.Record) (*api.FetchResult, error) {
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		method = "GET"
	}
	rec.Method = method
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, apierr.New(apierr.InvalidRequest, "invalid request URL", "pass an absolute URL such as https://app.example.com/api/me")
	}
	rec.Host, rec.Path = u.Hostname(), audit.RedactPath(u)

	pol, err := d.resolvePolicy(d.policies.current(), p.Policy, u)
	if err != nil {
		return nil, err
	}
	rec.Policy = pol.Name
	if err := d.precheck(pol, u, p.Body); err != nil {
		return nil, err
	}

	dec := pol.Check(ctx, policy.CheckRequest{Method: method, URL: u, Headers: p.Headers, Body: p.Body})
	if !dec.Allowed {
		if p.Explain {
			return &api.FetchResult{Policy: pol.Name, Explain: &api.Explain{
				Policy: pol.Name, Scope: grants.ScopeRead, Allowed: false, Code: dec.Code, Reason: dec.Reason, Hint: dec.Hint,
			}}, nil
		}
		return nil, dec.Error()
	}
	scope := dec.Scope
	if p.Write {
		scope = grants.ScopeWrite
	}
	breq := broker.Request{Method: method, URL: u.String(), Headers: p.Headers, Body: p.Body}

	if p.Explain {
		return d.explain(ctx, p, pol, dec, scope, breq), nil
	}

	detail := ""
	if scope == grants.ScopeWrite {
		detail = fmt.Sprintf("%s %s (%d bytes)", method, audit.RedactPath(u), len(p.Body))
	}
	g, minted, err := d.acquire(ctx, peer, p, pol, scope, detail)
	if err != nil {
		return nil, err
	}
	rec.GrantID = g.ID
	rec.TokenHash = audit.HashToken(g.Token)

	resp, err := d.broker.Do(ctx, pol, breq)
	if err != nil {
		return nil, apierr.As(err)
	}
	out := &api.FetchResult{
		Status: resp.Status, Headers: resp.Headers, Body: resp.Body, Truncated: resp.Truncated,
		URL: resp.URL, RedirectBlocked: resp.RedirectBlocked, Retried: resp.Retried,
		Policy: pol.Name, GrantID: g.ID,
	}
	if minted {
		info := d.grants.Info(g)
		out.Granted = &info
		out.NewToken = g.Token
	}
	return out, nil
}

// resolvePolicy picks the policy for u (spec 8, step 1).
func (d *Daemon) resolvePolicy(v *policyView, name string, u *url.URL) (*policy.Policy, error) {
	if name != "" {
		pol := v.set.Get(name)
		if pol == nil {
			if dr := v.set.GetAny(name); dr != nil && dr.IsDraft() {
				return nil, apierr.Newf(apierr.DeniedNoPolicy,
					"review the draft with `curd policies show "+name+"`, then activate it with `curd policies approve "+name+"` (the user confirms in a dialog)",
					"policy %q is a draft and is inert until approved", name)
			}
			for _, s := range v.statuses {
				if s.Name == name && s.Status == policy.StatusError {
					return nil, apierr.Newf(apierr.DeniedNoPolicy, "fix the policy file ("+s.File+") and check it with `curd policies validate`",
						"policy %q failed to load: %s", name, s.Error)
				}
			}
			return nil, apierr.Newf(apierr.DeniedNoPolicy, v.noPolicyHint(u.Hostname()), "no policy named %q", name)
		}
		if !pol.MatchesHost(u.Host) {
			return nil, apierr.Newf(apierr.DeniedHost, "policy "+pol.Name+" covers: "+strings.Join(pol.Match.Hosts, ", "),
				"host %q is not covered by policy %q", u.Hostname(), pol.Name)
		}
		return pol, nil
	}
	ps := v.set.ForHost(u.Host)
	switch len(ps) {
	case 1:
		return ps[0], nil
	case 0:
		hint := v.noPolicyHint(u.Hostname())
		for _, p := range v.set.All() {
			if p.IsDraft() && p.MatchesHost(u.Host) {
				hint = "a draft policy covers this host; review it with `curd policies show " + p.Name +
					"` and activate it with `curd policies approve " + p.Name + "`"
			}
		}
		return nil, apierr.Newf(apierr.DeniedNoPolicy, hint, "no policy covers host %q", u.Hostname())
	default:
		names := make([]string, len(ps))
		for i, p := range ps {
			names[i] = p.Name
		}
		return nil, apierr.Newf(apierr.InvalidRequest, "name one: `curd fetch <policy> <url>`",
			"several policies cover host %q: %s", u.Hostname(), strings.Join(names, ", "))
	}
}

// precheck rejects requests the broker would refuse anyway, before the user
// is asked for consent.
func (d *Daemon) precheck(pol *policy.Policy, u *url.URL, body []byte) error {
	if u.User != nil {
		return apierr.New(apierr.InvalidRequest, "URL must not contain userinfo", "remove user:password@ from the URL; credentials come from the policy")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !d.Test() {
			return apierr.New(apierr.InvalidRequest, "plain http is not allowed", "use an https:// URL; plain http is refused")
		}
	default:
		return apierr.Newf(apierr.InvalidRequest, "use an https:// URL", "unsupported URL scheme %q", u.Scheme)
	}
	max := pol.Request.MaxBodyBytes
	if max <= 0 {
		max = policy.DefaultRequestMaxBody
	}
	if int64(len(body)) > max {
		return apierr.Newf(apierr.DeniedBodySize, fmt.Sprintf("send at most %d bytes (policy request.max_body_bytes)", max),
			"request body is %d bytes, over the policy limit of %d", len(body), max)
	}
	return nil
}

// explain builds the dry-run report: nothing is sent, no consent is shown,
// no grant is consumed.
func (d *Daemon) explain(ctx context.Context, p *api.FetchParams, pol *policy.Policy, dec policy.Decision, scope string, breq broker.Request) *api.FetchResult {
	ex := &api.Explain{Policy: pol.Name, Rule: dec.Rule, Scope: scope, Allowed: true}
	res := &api.FetchResult{Policy: pol.Name, Explain: ex}
	g, err := d.grants.Peek(p.Token, p.SessionKey, pol.Name, scope)
	if err != nil {
		e := apierr.As(err)
		ex.Allowed, ex.Code, ex.Reason, ex.Hint = false, e.Code, e.Message, e.Hint
		if e.Code == apierr.DeniedNoGrant && p.Token == "" {
			if p.NoPrompt {
				ex.Reason = "no active grant covers this request and --no-prompt is set, so the call would fail"
			} else {
				ex.Reason = "no active grant covers this request; a consent dialog would be shown"
				ex.Hint = "approve it when asked, or pre-authorize with `curd grants request " + pol.Name + writeFlag(scope) + "`"
			}
		}
		return res
	}
	ex.GrantID = g.ID
	plan, err := d.broker.Plan(ctx, pol, breq)
	if err != nil {
		e := apierr.As(err)
		ex.Allowed, ex.Code, ex.Reason, ex.Hint = false, e.Code, e.Message, e.Hint
		return res
	}
	ex.Cookies, ex.Injected = plan.Cookies, plan.Injected
	ex.Reason = "allowed by policy " + pol.Name + " (" + dec.Rule + ") under grant " + g.ID
	res.GrantID = g.ID
	return res
}

func writeFlag(scope string) string {
	if scope == grants.ScopeWrite {
		return " --write"
	}
	return ""
}

// acquire finds the grant for a request, running consent when there is none
// and the caller allows it. minted reports whether this call created the
// grant. Identical concurrent prompts are coalesced.
func (d *Daemon) acquire(ctx context.Context, peer rpc.Peer, p *api.FetchParams, pol *policy.Policy, scope, detail string) (g *grants.Grant, minted bool, err error) {
	cl := clientOf(peer)
	key := p.SessionKey + "\x00" + pol.Name + "\x00" + scope
	for round := 0; ; round++ {
		g, err = d.grants.Authorize(p.Token, p.SessionKey, pol.Name, scope)
		if err == nil {
			return g, minted, nil
		}
		e := apierr.As(err)
		// An explicit token is a capability: if it does not cover the
		// request, say so instead of prompting.
		if e.Code != apierr.DeniedNoGrant || p.Token != "" || p.NoPrompt || round >= maxPromptRounds {
			if p.NoPrompt && e.Code == apierr.DeniedNoGrant && p.Token == "" {
				e = apierr.New(apierr.DeniedNoGrant, "no active grant covers this request and --no-prompt is set",
					"request one with `curd grants request "+pol.Name+writeFlag(scope)+"` (the user approves in a dialog) and retry")
			}
			return nil, false, e
		}

		var mintedTok string
		ans, shared, perr := d.prompts.do(ctx, key, func() (consent.Answer, error) {
			a, tok, err := d.askAndMint(ctx, cl, p, pol, scope, detail)
			mintedTok = tok
			return a, err
		})
		if perr != nil && ctx.Err() != nil {
			return nil, false, apierr.New(apierr.DeniedNoGrant, "cancelled while waiting for consent", "retry the request")
		}
		if shared {
			if perr != nil && !errors.Is(perr, context.Canceled) {
				return nil, false, d.denied(pol, scope, perr)
			}
			if perr == nil && ans == consent.Deny {
				return nil, false, d.denied(pol, scope, nil)
			}
			continue // a session grant now exists, or a once grant was used up: look again
		}
		if perr != nil || ans == consent.Deny {
			return nil, false, d.denied(pol, scope, perr)
		}
		// Use the grant we just minted; this records the use and consumes a once grant.
		g, err = d.grants.Authorize(mintedTok, p.SessionKey, pol.Name, scope)
		if err != nil {
			return nil, false, apierr.As(err)
		}
		return g, true, nil
	}
}

// denied is the error for a refused or failed consent prompt.
func (d *Daemon) denied(pol *policy.Policy, scope string, cause error) error {
	why := "the user denied access"
	if cause != nil {
		why = "consent could not be obtained: " + cause.Error()
	}
	if scope == grants.ScopeWrite {
		return apierr.Newf(apierr.DeniedMethod,
			"this request is a write; it needs a write grant: `curd grants request "+pol.Name+" --write`",
			"%s to write to policy %q", why, pol.Name)
	}
	return apierr.Newf(apierr.DeniedNoGrant,
		"ask the user to allow it, then run `curd grants request "+pol.Name+"` or retry the call",
		"%s to policy %q", why, pol.Name)
}

// askAndMint shows the consent prompt for an implicit (first-use) grant and
// mints the grant the answer allows. It returns the minted token.
func (d *Daemon) askAndMint(ctx context.Context, cl client, p *api.FetchParams, pol *policy.Policy, scope, detail string) (consent.Answer, string, error) {
	ttl := time.Duration(pol.TTLDefault)
	ans, err := d.prompter.Ask(ctx, consent.Prompt{
		Kind: consent.KindGrant, Policies: []string{pol.Name}, Hosts: pol.Match.Hosts, Scope: scope,
		ClientName: cl.Name, ClientPID: cl.PID, Duration: ttl, SessionKey: p.SessionKey, Detail: detail,
	})
	d.auditConsent(cl, p.SessionKey, []string{pol.Name}, scope, ans, err)
	if err != nil {
		return consent.Deny, "", err
	}
	mode := ""
	switch ans {
	case consent.Once:
		mode = grants.ModeOnce
	case consent.Session:
		mode = grants.ModeSession
	default:
		return consent.Deny, "", nil
	}
	g := d.mint(cl, p.Caller, []string{pol.Name}, scope, mode, ttl, "")
	return ans, g.Token, nil
}

func (d *Daemon) mint(cl client, c api.Caller, policies []string, scope, mode string, ttl time.Duration, purpose string) *grants.Grant {
	g := d.grants.Mint(grants.MintSpec{
		Policies: policies, Scopes: []string{scope}, Mode: mode, TTL: ttl,
		SessionKey: c.SessionKey, SessionKeySource: c.SessionKeySource,
		ClientPID: cl.PID, ClientExe: cl.Exe, Purpose: purpose,
	})
	d.writeAudit(audit.Record{
		Event: "grant", ClientPID: cl.PID, ClientExe: cl.Exe, GrantID: g.ID, TokenHash: audit.HashToken(g.Token),
		SessionKey: c.SessionKey, Policy: joinPolicies(policies), Decision: "allow", Tags: []string{mode, scope},
	})
	return g
}

func (d *Daemon) auditConsent(cl client, sessionKey string, policies []string, scope string, ans consent.Answer, err error) {
	rec := audit.Record{
		Event: "consent", ClientPID: cl.PID, ClientExe: cl.Exe, SessionKey: sessionKey,
		Policy: joinPolicies(policies), Tags: []string{string(ans), scope},
	}
	switch {
	case err != nil:
		rec.Decision, rec.Code = "deny", "consent_error"
	case ans == consent.Deny:
		rec.Decision = "deny"
	default:
		rec.Decision = "allow"
	}
	d.writeAudit(rec)
}
