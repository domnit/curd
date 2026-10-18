package policy

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
)

// CheckRequest is the request to evaluate against a policy.
type CheckRequest struct {
	Method  string
	URL     *url.URL
	Headers []api.Header
	Body    []byte
}

// Decision is the result of Check.
type Decision struct {
	Allowed bool
	// Code is empty when allowed, otherwise an apierr Denied* code.
	Code string
	// RuleIndex is the index into Policy.Allow of the rule that allowed the
	// request (or, for denied_inspector, the first rule that was tried); -1
	// if no rule was involved.
	RuleIndex int
	Rule      string // human summary of that rule
	Scope     string // "read" or "write" for that rule
	Reason    string
	Hint      string
}

// Error converts a denial into an *apierr.Error; it returns nil if allowed.
func (d Decision) Error() *apierr.Error {
	if d.Allowed {
		return nil
	}
	return apierr.New(d.Code, d.Reason, d.Hint)
}

func isSafeMethod(m string) bool { return m == "GET" || m == "HEAD" || m == "OPTIONS" }

// EffectiveScope returns the rule's scope: the explicit scope if set,
// otherwise "read" when every method is safe or the rule inspects with
// graphql_query_only, else "write".
func (r *Rule) EffectiveScope() string {
	if r.Scope != "" {
		return r.Scope
	}
	if r.Inspect == InspectGraphQLQueryOnly {
		return ScopeRead
	}
	for _, m := range r.Methods {
		if !isSafeMethod(m) {
			return ScopeWrite
		}
	}
	return ScopeRead
}

// Summary renders the rule as in policy status, e.g.
// "POST ^/graphql$ inspect=graphql_query_only [read]".
func (r *Rule) Summary() string {
	s := strings.Join(r.Methods, ",") + " " + strings.Join(r.Paths, ",")
	if r.Inspect != "" {
		s += " inspect=" + r.Inspect
	}
	s += " [" + r.EffectiveScope() + "]"
	if r.Disabled {
		s = "(disabled) " + s
	}
	return s
}

func (r *Rule) hasMethod(m string) bool {
	for _, x := range r.Methods {
		if x == m {
			return true
		}
	}
	return false
}

func (r *Rule) matchesPath(p string) bool {
	for _, re := range r.paths {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// Check evaluates a request against the policy: host, then method, then path
// (matched against the decoded URL path only), then the rule's inspector. The
// first rule that passes all of them wins.
func (p *Policy) Check(ctx context.Context, req CheckRequest) Decision {
	deny := func(code, reason, hint string) Decision {
		return Decision{Code: code, RuleIndex: -1, Reason: reason, Hint: hint}
	}
	if req.URL == nil || req.URL.Host == "" {
		return deny(apierr.DeniedPath, "request has no URL host", "pass an absolute URL such as https://"+p.Match.Hosts[0]+"/path")
	}
	if !p.MatchesHost(req.URL.Host) {
		return deny(apierr.DeniedHost, fmt.Sprintf("host %q is not covered by policy %q", req.URL.Hostname(), p.Name),
			"policy "+p.Name+" covers: "+strings.Join(p.Match.Hosts, ", "))
	}
	method := strings.ToUpper(req.Method)
	if !methodRe.MatchString(method) {
		return deny(apierr.DeniedMethod, "invalid HTTP method", "use a standard method such as GET")
	}

	var byMethod, disabledByMethod []int
	for i := range p.Allow {
		if p.Allow[i].hasMethod(method) {
			if p.Allow[i].Disabled {
				disabledByMethod = append(disabledByMethod, i)
			} else {
				byMethod = append(byMethod, i)
			}
		}
	}
	if len(byMethod) == 0 {
		hint := p.methodHint(method)
		if len(disabledByMethod) > 0 {
			hint = fmt.Sprintf("a disabled %s rule exists for %s; enable it in the policy (and use a %s grant)",
				p.Allow[disabledByMethod[0]].EffectiveScope(), method, p.Allow[disabledByMethod[0]].EffectiveScope())
		}
		return deny(apierr.DeniedMethod, fmt.Sprintf("policy %q does not allow %s", p.Name, method), hint)
	}

	urlPath := req.URL.Path
	if urlPath == "" {
		urlPath = "/"
	}
	if hasDotSegment(urlPath) {
		return deny(apierr.DeniedPath, "path contains '.' or '..' segments", "send a normalized path without dot segments")
	}
	var byPath []int
	for _, i := range byMethod {
		if p.Allow[i].matchesPath(urlPath) {
			byPath = append(byPath, i)
		}
	}
	if len(byPath) == 0 {
		var pats []string
		for _, i := range byMethod {
			pats = append(pats, p.Allow[i].Paths...)
		}
		hint := fmt.Sprintf("%s is allowed only for paths matching: %s", method, strings.Join(pats, ", "))
		for _, i := range p.Allow {
			if i.Disabled && i.hasMethod(method) && i.matchesPath(urlPath) {
				hint = fmt.Sprintf("a disabled %s rule exists for this path; enable it in the policy", i.EffectiveScope())
				break
			}
		}
		return deny(apierr.DeniedPath, fmt.Sprintf("path is not allowed for %s by policy %q", method, p.Name), hint)
	}

	var firstDenial Decision
	for n, i := range byPath {
		r := &p.Allow[i]
		d := Decision{RuleIndex: i, Rule: r.Summary(), Scope: r.EffectiveScope()}
		if r.Inspect != "" {
			insp := inspectorFor(r)
			ok, reason, err := insp.Inspect(ctx, InspectRequest{Method: method, URL: req.URL, Headers: req.Headers, Body: req.Body, Rule: r})
			if err != nil {
				ok, reason = false, "inspector failed: "+err.Error()
			}
			if !ok {
				d.Code = apierr.DeniedInspector
				d.Reason = fmt.Sprintf("request rejected by %s: %s", inspectorLabel(r), reason)
				d.Hint = inspectorHint(r)
				if n == 0 {
					firstDenial = d
				}
				continue
			}
		}
		d.Allowed = true
		return d
	}
	return firstDenial
}

func (p *Policy) methodHint(method string) string {
	set := map[string]bool{}
	hasWrite := false
	for _, r := range p.Allow {
		if r.Disabled {
			continue
		}
		for _, m := range r.Methods {
			set[m] = true
		}
		if r.EffectiveScope() == ScopeWrite {
			hasWrite = true
		}
	}
	var ms []string
	for m := range set {
		ms = append(ms, m)
	}
	sort.Strings(ms)
	h := "allowed methods: " + strings.Join(ms, ", ")
	switch {
	case isSafeMethod(method):
	case !hasWrite:
		h = "this policy is read-only (" + strings.Join(ms, ", ") + "); " + method + " needs a write rule in the policy and a write grant"
	default:
		h += "; " + method + " would need its own write rule in the policy and a write grant"
	}
	return h
}

func inspectorLabel(r *Rule) string {
	if r.Inspect == InspectGraphQLQueryOnly {
		return InspectGraphQLQueryOnly
	}
	return "exec inspector"
}

func inspectorHint(r *Rule) string {
	if r.Inspect == InspectGraphQLQueryOnly {
		return "graphql_query_only allows only query operations; mutations need a write rule and write grant"
	}
	return "the policy's exec inspector denied this request; check its rules"
}
