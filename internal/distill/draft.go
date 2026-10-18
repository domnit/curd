// Package distill turns captured browser traffic into a draft policy and
// verifies it by replaying requests through the fetch broker (spec 16.3,
// 16.4).
package distill

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/capture"
	"github.com/domnit/curd/internal/policy"
)

const writeNote = "captured write; enable explicitly"

var (
	numRe    = regexp.MustCompile(`^[0-9]+$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	opaqueRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`)
	digitRe  = regexp.MustCompile(`[0-9]`)
	// placeholderRe matches the placeholders curd's redactor emits.
	placeholderRe = regexp.MustCompile(`\{(?:cookie|ls|header):[^}]*\}`)
	lsRe          = regexp.MustCompile(`\{ls:(https?://[^/:}]+(?::[0-9]+)?):([^}]+)\}`)
)

// GeneralizePath returns an anchored path regexp for a concrete URL path:
// numeric segments become [0-9]+, UUIDs [0-9a-fA-F-]{36}, long opaque ids
// [^/]+, everything else a quoted literal.
func GeneralizePath(path string) string {
	if path == "" {
		path = "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case numRe.MatchString(s):
			segs[i] = `[0-9]+`
		case uuidRe.MatchString(s):
			segs[i] = `[0-9a-fA-F-]{36}`
		case opaqueRe.MatchString(s) && digitRe.MatchString(s):
			segs[i] = `[^/]+`
		default:
			segs[i] = regexp.QuoteMeta(s)
		}
	}
	return "^" + strings.Join(segs, "/") + "$"
}

func isSafe(m string) bool { return m == "GET" || m == "HEAD" || m == "OPTIONS" }

// Request headers that are never allowlisted (policy always drops them).
var alwaysDropped = map[string]bool{
	"cookie": true, "authorization": true, "host": true, "proxy-authorization": true,
	"proxy-authenticate": true, "proxy-connection": true, "connection": true, "keep-alive": true,
	"te": true, "trailer": true, "upgrade": true, "content-length": true, "transfer-encoding": true,
}

// Method-override headers are refused in a policy's header_allowlist.
var methodOverride = map[string]bool{"x-http-method-override": true, "x-http-method": true, "x-method-override": true}

// Browser noise that a script has no reason to send.
var noiseHeaders = map[string]bool{
	"user-agent": true, "accept-encoding": true, "origin": true, "referer": true,
	"priority": true, "upgrade-insecure-requests": true, "cache-control": true, "pragma": true,
	"if-none-match": true, "if-modified-since": true, "dnt": true,
}

func isNoise(lower string) bool {
	return noiseHeaders[lower] || strings.HasPrefix(lower, "sec-ch-") || strings.HasPrefix(lower, "sec-fetch-")
}

func hasPlaceholder(s string) bool { return placeholderRe.MatchString(s) }

// gqlClass describes a captured GraphQL request.
type gqlClass struct {
	isGQL    bool
	mutation bool     // not provably query-only
	names    []string // operation names seen (queries)
	anon     bool     // some query has no name
	hashes   []string // persisted query hashes
}

type gqlItem struct {
	Query         string
	OperationName string
	Extensions    json.RawMessage
}

func classify(e *capture.Entry, u *url.URL) gqlClass {
	var c gqlClass
	pathHint := strings.Contains(strings.ToLower(u.Path), "graphql")
	// Parse exactly as graphql_query_only does, so a body with duplicate
	// or case-variant keys (which servers may read differently) is never
	// classified as a query.
	var items []gqlItem
	if rs, err := policy.ParseGraphQLRequests(e.RequestBody); err == nil {
		for _, r := range rs {
			it := gqlItem{Query: r.Query, Extensions: r.Extensions}
			if r.OperationName != nil {
				it.OperationName = *r.OperationName
			}
			items = append(items, it)
		}
	}
	hasQuery := false
	for _, it := range items {
		if it.Query != "" {
			hasQuery = true
		}
	}
	if e.Method != "POST" || !(pathHint || hasQuery) {
		return c
	}
	c.isGQL = true
	if len(items) == 0 {
		c.mutation = true // cannot tell; stay conservative
		return c
	}
	for _, it := range items {
		if strings.TrimSpace(it.Query) == "" {
			h := persistedHash(it.Extensions)
			if h == "" {
				c.mutation = true
				continue
			}
			c.hashes = append(c.hashes, h)
			continue
		}
		doc, err := parser.ParseQuery(&ast.Source{Name: "capture", Input: it.Query})
		if err != nil || doc == nil || len(doc.Operations) == 0 {
			c.mutation = true
			continue
		}
		ops := doc.Operations
		if it.OperationName != "" {
			if op := doc.Operations.ForName(it.OperationName); op != nil {
				ops = ast.OperationList{op}
			}
		}
		for _, op := range ops {
			if op.Operation != ast.Query {
				c.mutation = true
				continue
			}
			if op.Name == "" {
				c.anon = true
			} else {
				c.names = append(c.names, op.Name)
			}
		}
	}
	return c
}

func persistedHash(ext json.RawMessage) string { return policy.PersistedQueryHash(ext) }

func addUnique(l []string, vs ...string) []string {
	for _, v := range vs {
		found := false
		for _, x := range l {
			if x == v {
				found = true
				break
			}
		}
		if !found {
			l = append(l, v)
		}
	}
	return l
}

type ruleKey struct {
	method, path, kind string // kind: "", "gqlq", "gqlw"
}

// Draft builds a draft policy and one `curd fetch` command per entry.
func Draft(name string, entries []*capture.Entry) (*policy.Policy, []string, error) {
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no captured requests selected")
	}
	p := &policy.Policy{Name: name, Status: policy.StatusDraft}
	var cmds []string

	ruleIdx := map[ruleKey]int{}
	gqlNames := map[int]*gqlClass{}
	hdrSeen := map[string]string{} // lower -> display name
	hdrUsable := map[string]bool{} // has at least one placeholder-free value
	type inj struct{ origin, key, header string }
	injSeen := map[inj]bool{}
	var cookies []string

	for _, e := range entries {
		u, err := url.Parse(e.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		p.Match.Hosts = addUnique(p.Match.Hosts, strings.ToLower(u.Hostname()))
		method := strings.ToUpper(e.Method)
		pathRe := GeneralizePath(u.Path)

		cls := classify(e, u)
		key := ruleKey{method, pathRe, ""}
		switch {
		case cls.isGQL && !cls.mutation:
			key.kind = "gqlq"
		case cls.isGQL:
			key.kind = "gqlw"
		}
		i, ok := ruleIdx[key]
		if !ok {
			r := policy.Rule{Methods: []string{method}, Paths: []string{pathRe}}
			switch key.kind {
			case "gqlq":
				r.Inspect = policy.InspectGraphQLQueryOnly
			case "gqlw":
				r.Scope, r.Disabled, r.Note = policy.ScopeWrite, true, "captured GraphQL mutation; "+strings.TrimPrefix(writeNote, "captured write; ")
			default:
				if !isSafe(method) {
					r.Scope, r.Disabled, r.Note = policy.ScopeWrite, true, writeNote
				}
			}
			p.Allow = append(p.Allow, r)
			i = len(p.Allow) - 1
			ruleIdx[key] = i
			gqlNames[i] = &gqlClass{}
		}
		if key.kind == "gqlq" {
			g := gqlNames[i]
			g.names = addUnique(g.names, cls.names...)
			g.hashes = addUnique(g.hashes, cls.hashes...)
			g.anon = g.anon || cls.anon || (len(cls.names) == 0 && len(cls.hashes) == 0)
		}

		for _, h := range e.RequestHeaders {
			l := strings.ToLower(h.Name)
			switch {
			case l == "cookie":
				for _, part := range strings.Split(h.Value, ";") {
					if n, _, _ := strings.Cut(strings.TrimSpace(part), "="); n != "" {
						cookies = addUnique(cookies, n)
					}
				}
				continue
			case alwaysDropped[l] && l != "authorization":
				continue
			}
			if m := lsRe.FindStringSubmatch(h.Value); m != nil {
				k := inj{m[1], m[2], h.Name}
				if !injSeen[k] {
					injSeen[k] = true
					tmpl := strings.ReplaceAll(h.Value, m[0], "{value}")
					p.Credentials.LocalStorage = append(p.Credentials.LocalStorage, policy.LocalStorageRule{
						Origin: m[1], Keys: []string{m[2]}, InjectAs: "header:" + h.Name + ":" + tmpl,
					})
				}
				continue
			}
			if alwaysDropped[l] || isNoise(l) || methodOverride[l] {
				continue
			}
			if _, ok := hdrSeen[l]; !ok {
				hdrSeen[l] = l
			}
			if !hasPlaceholder(h.Value) {
				hdrUsable[l] = true
			}
		}
	}
	if len(p.Match.Hosts) == 0 {
		return nil, nil, fmt.Errorf("no usable URLs in the selected requests")
	}
	for i, g := range gqlNames {
		if p.Allow[i].Inspect != policy.InspectGraphQLQueryOnly {
			continue
		}
		if !g.anon && len(g.names) > 0 || len(g.hashes) > 0 {
			ga := &policy.GraphQLAllow{PersistedHashes: g.hashes}
			if !g.anon {
				ga.Operations = g.names
			}
			if len(ga.Operations) > 0 || len(ga.PersistedHashes) > 0 {
				p.Allow[i].GraphQL = ga
			}
		}
	}
	p.Credentials.Cookies = cookies
	// An empty cookies list means "all cookies"; when no request sent any,
	// the draft says so explicitly.
	p.Credentials.CookiesNone = len(cookies) == 0
	for l := range hdrSeen {
		if hdrUsable[l] {
			p.Request.HeaderAllowlist = append(p.Request.HeaderAllowlist, l)
		}
	}
	sort.Strings(p.Request.HeaderAllowlist)
	p.Response.StripHeaders = []string{"set-cookie"}
	p.Redirects = policy.RedirectsSameHost
	p.TTLDefault = policy.Duration(8 * time.Hour)

	// Round-trip so the returned policy is validated and has compiled rules.
	data, err := policy.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := policy.Parse(data, "")
	if err != nil {
		return nil, nil, fmt.Errorf("draft policy is invalid: %w", err)
	}
	for _, e := range entries {
		if c := fetchCommand(name, parsed.Request.HeaderAllowlist, e); c != "" {
			cmds = append(cmds, c)
		}
	}
	return parsed, cmds, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fetchCommand(name string, allow []string, e *capture.Entry) string {
	u, err := url.Parse(e.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.RawQuery != "" {
		var keep []string
		for _, kv := range strings.Split(u.RawQuery, "&") {
			if dec, err := url.QueryUnescape(kv); err == nil && hasPlaceholder(dec) {
				continue
			}
			keep = append(keep, kv)
		}
		u.RawQuery = strings.Join(keep, "&")
	}
	u.Fragment = ""
	parts := []string{"curd", "fetch", shellQuote(name)}
	method := strings.ToUpper(e.Method)
	if method != "GET" {
		parts = append(parts, "-X", method)
	}
	for _, h := range sentHeaders(allow, e.RequestHeaders) {
		parts = append(parts, "-H", shellQuote(h.Name+": "+h.Value))
	}
	if method != "GET" && len(e.RequestBody) > 0 && !hasPlaceholder(string(e.RequestBody)) {
		parts = append(parts, "-d", shellQuote(string(e.RequestBody)))
	}
	parts = append(parts, shellQuote(u.String()))
	return strings.Join(parts, " ")
}

// sentHeaders returns the captured headers on the allowlist whose values
// carry no placeholder, one per name.
func sentHeaders(allow []string, hs []api.Header) []api.Header {
	set := map[string]bool{}
	for _, a := range allow {
		set[strings.ToLower(a)] = true
	}
	var out []api.Header
	seen := map[string]bool{}
	for _, h := range hs {
		l := strings.ToLower(h.Name)
		if !set[l] || seen[l] || hasPlaceholder(h.Value) || alwaysDropped[l] {
			continue
		}
		seen[l] = true
		out = append(out, h)
	}
	return out
}
