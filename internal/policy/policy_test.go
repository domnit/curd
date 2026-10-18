package policy

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
)

const goodYAML = `
name: internal-dashboard
profile: Default
match:
  hosts: [app.example.com, '*.example.com']
credentials:
  cookies: [session, '__Host-*']
  local_storage:
    - origin: https://app.example.com
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [get, head]
    paths: ['^/api/.*']
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
request:
  header_allowlist: [accept, content-type, x-csrf-token]
response:
  strip_headers: [x-secret]
  redact: ['sk-[a-z0-9]+']
`

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParseDefaultsAndRoundTrip(t *testing.T) {
	p := mustParse(t, goodYAML)
	if p.Request.MaxBodyBytes != 1<<20 || p.Response.MaxBodyBytes != 10<<20 ||
		p.Redirects != "same-host-only" || time.Duration(p.TTLDefault) != 8*time.Hour {
		t.Fatalf("defaults wrong: %+v", p)
	}
	if p.Allow[0].Methods[0] != "GET" {
		t.Errorf("methods not uppercased: %v", p.Allow[0].Methods)
	}
	out, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Parse(out, "")
	if err != nil {
		t.Fatalf("round trip: %v\n%s", err, out)
	}
	out2, _ := Marshal(p2)
	if string(out) != string(out2) {
		t.Errorf("round trip differs:\n%s\n---\n%s", out, out2)
	}
	if got := p2.Allow[1].Inspect; got != "graphql_query_only" {
		t.Errorf("inspect lost: %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	base := func(mod string) string {
		return "name: x\nmatch:\n  hosts: [a.example.com]\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n" + mod
	}
	tests := []struct {
		name, yaml, want string
	}{
		{"empty", "", "empty"},
		{"no name", "match:\n  hosts: [a.com]\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n", "name is required"},
		{"bad name", strings.Replace(base(""), "name: x", "name: 'a/b'", 1), "name"},
		{"no hosts", "name: x\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n", "match.hosts"},
		{"star host", strings.Replace(base(""), "a.example.com", "'*'", 1), "host"},
		{"star prefix", strings.Replace(base(""), "a.example.com", "'*foo.com'", 1), "host"},
		{"middle star", strings.Replace(base(""), "a.example.com", "a.*.com", 1), "host"},
		{"double wildcard", strings.Replace(base(""), "a.example.com", "'*.*.com'", 1), "host"},
		{"tld wildcard", strings.Replace(base(""), "a.example.com", "'*.com'", 1), "wildcard"},
		{"scheme host", strings.Replace(base(""), "a.example.com", "'https://a.com'", 1), "bare hostname"},
		{"port host", strings.Replace(base(""), "a.example.com", "'a.com:443'", 1), "bare hostname"},
		{"no allow", "name: x\nmatch:\n  hosts: [a.com]\n", "allow"},
		{"bad regexp", strings.Replace(base(""), "^/$", "([", 1), "regexp"},
		{"bad method", strings.Replace(base(""), "GET", "'G ET'", 1), "method"},
		{"no methods", "name: x\nmatch:\n  hosts: [a.com]\nallow:\n  - paths: ['^/$']\n", "methods"},
		{"bad inspect", base("")[:len(base(""))] + "    inspect: foo\n", "inspect"},
		{"relative exec", base("") + "    inspect: 'exec:bin/x'\n", "absolute"},
		{"bad scope", base("") + "    scope: admin\n", "scope"},
		{"graphql without inspect", base("") + "    graphql:\n      operations: [a]\n", "graphql"},
		{"bad redirects", base("redirects: always\n"), "redirects"},
		{"bad ttl", base("ttl_default: forever\n"), "duration"},
		{"unknown field", base("bogus: 1\n"), "bogus"},
		{"unknown rule field", base("") + "    mehtods: [x]\n", "mehtods"},
		{"bad status", base("status: live\n"), "status"},
		{"bad cookie glob", base("credentials:\n  cookies: ['[']\n"), "glob"},
		{"bad inject_as", base("credentials:\n  local_storage:\n    - origin: https://a.com\n      keys: [k]\n      inject_as: 'Authorization'\n"), "inject_as"},
		{"inject_as no value", base("credentials:\n  local_storage:\n    - origin: https://a.com\n      keys: [k]\n      inject_as: 'header:X:fixed'\n"), "{value}"},
		{"inject_as host", base("credentials:\n  local_storage:\n    - origin: https://a.com\n      keys: [k]\n      inject_as: 'header:Host:{value}'\n"), "cannot be injected"},
		{"bad origin", base("credentials:\n  local_storage:\n    - origin: a.com\n      keys: [k]\n"), "origin"},
		{"bad redact", base("response:\n  redact: ['(']\n"), "redact"},
		{"negative body", base("request:\n  max_body_bytes: -1\n"), "negative"},
		{"method override header", base("request:\n  header_allowlist: [accept, X-HTTP-Method-Override]\n"), "method-override"},
		{"x-http-method header", base("request:\n  header_allowlist: [x-http-method]\n"), "method-override"},
		{"x-method-override header", base("request:\n  header_allowlist: [X-Method-Override]\n"), "method-override"},
		{"cookies_none with list", base("credentials:\n  cookies_none: true\n  cookies: [a]\n"), "cookies_none"},
	}
	for _, tc := range tests {
		_, err := Parse([]byte(tc.yaml), "")
		if err == nil {
			t.Errorf("%s: expected error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

func TestHostValidationAccepts(t *testing.T) {
	for _, h := range []string{"a.com", "App.Example.COM", "*.example.com", "127.0.0.1", "localhost", "my-host_1.example.co.uk"} {
		if _, err := validateHostPattern(h); err != nil {
			t.Errorf("%q rejected: %v", h, err)
		}
	}
}

func TestParseFileNameRules(t *testing.T) {
	y := []byte("name: foo\nmatch:\n  hosts: [a.com]\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n")
	if _, err := Parse(y, "/p/foo.yaml"); err != nil {
		t.Errorf("foo.yaml: %v", err)
	}
	if _, err := Parse(y, "/p/bar.yaml"); err == nil || !strings.Contains(err.Error(), "must match") {
		t.Errorf("bar.yaml: %v", err)
	}
	p, err := Parse(y, "/p/foo.draft.yaml")
	if err != nil || !p.IsDraft() {
		t.Errorf("foo.draft.yaml: %v draft=%v", err, p != nil && p.IsDraft())
	}
}

func TestWarningsUnanchored(t *testing.T) {
	p := mustParse(t, "name: x\nmatch:\n  hosts: [a.com]\nallow:\n  - methods: [GET]\n    paths: ['/api']\n")
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "anchored") {
		t.Errorf("warnings: %v", p.Warnings)
	}
}

func TestMatchesHost(t *testing.T) {
	p := mustParse(t, goodYAML)
	for h, want := range map[string]bool{
		"app.example.com":      true,
		"APP.example.com:8443": true,
		"x.example.com":        true,
		"a.b.example.com":      true,
		"example.com":          false,
		"evil-example.com":     false,
		"example.com.evil.com": false,
	} {
		if got := p.MatchesHost(h); got != want {
			t.Errorf("MatchesHost(%q)=%v want %v", h, got, want)
		}
	}
}

func TestScopeDerivation(t *testing.T) {
	tests := []struct {
		r    Rule
		want string
	}{
		{Rule{Methods: []string{"GET", "HEAD"}}, "read"},
		{Rule{Methods: []string{"OPTIONS"}}, "read"},
		{Rule{Methods: []string{"GET", "POST"}}, "write"},
		{Rule{Methods: []string{"DELETE"}}, "write"},
		{Rule{Methods: []string{"POST"}, Inspect: "graphql_query_only"}, "read"},
		{Rule{Methods: []string{"POST"}, Inspect: "exec:/bin/x"}, "write"},
		{Rule{Methods: []string{"GET"}, Scope: "write"}, "write"},
		{Rule{Methods: []string{"POST"}, Scope: "read"}, "read"},
	}
	for i, tc := range tests {
		if got := tc.r.EffectiveScope(); got != tc.want {
			t.Errorf("case %d: got %s want %s", i, got, tc.want)
		}
	}
}

func check(p *Policy, method, u string, body string, ct string) Decision {
	pu, _ := url.Parse(u)
	var hs []api.Header
	if ct != "" {
		hs = append(hs, api.Header{Name: "Content-Type", Value: ct})
	}
	return p.Check(context.Background(), CheckRequest{Method: method, URL: pu, Headers: hs, Body: []byte(body)})
}

const rulesYAML = `
name: r
match: {hosts: [a.com]}
allow:
  - methods: [GET]
    paths: ['^/api/.*']
  - methods: [GET]
    paths: ['^/other$']
    scope: write
  - methods: [DELETE]
    paths: ['^/items/\d+$']
    disabled: true
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
`

func TestCheckDecisions(t *testing.T) {
	p := mustParse(t, rulesYAML)
	tests := []struct {
		name, method, url, body string
		allowed                 bool
		code                    string
		rule                    int
		scope                   string
		hintHas                 string
	}{
		{name: "get api", method: "GET", url: "https://a.com/api/x?y=1", allowed: true, rule: 0, scope: "read"},
		{name: "lowercase method", method: "get", url: "https://a.com/api/x", allowed: true, rule: 0, scope: "read"},
		{name: "explicit write scope", method: "GET", url: "https://a.com/other", allowed: true, rule: 1, scope: "write"},
		{name: "port ignored", method: "GET", url: "https://a.com:8443/api/x", allowed: true, rule: 0, scope: "read"},
		{name: "method not allowed", method: "PUT", url: "https://a.com/api/x", code: apierr.DeniedMethod, hintHas: "write rule"},
		{name: "disabled write rule", method: "DELETE", url: "https://a.com/items/3", code: apierr.DeniedMethod, hintHas: "disabled write rule exists"},
		{name: "path denied", method: "GET", url: "https://a.com/admin", code: apierr.DeniedPath, hintHas: "^/api/.*"},
		{name: "dot segments", method: "GET", url: "https://a.com/api/../admin", code: apierr.DeniedPath, hintHas: "normalized"},
		{name: "encoded dot segments", method: "GET", url: "https://a.com/api/%2e%2e/admin", code: apierr.DeniedPath},
		{name: "wrong host", method: "GET", url: "https://b.com/api/x", code: apierr.DeniedHost},
		{name: "graphql ok", method: "POST", url: "https://a.com/graphql", body: `{"query":"{ me { id } }"}`, allowed: true, rule: 3, scope: "read"},
		{name: "graphql mutation", method: "POST", url: "https://a.com/graphql", body: `{"query":"mutation Boom { x }"}`, code: apierr.DeniedInspector, hintHas: "write rule and write grant"},
		{name: "graphql path", method: "POST", url: "https://a.com/graphql2", body: `{"query":"{a}"}`, code: apierr.DeniedPath},
	}
	for _, tc := range tests {
		d := check(p, tc.method, tc.url, tc.body, "application/json")
		if d.Allowed != tc.allowed {
			t.Errorf("%s: allowed=%v (%s / %s)", tc.name, d.Allowed, d.Reason, d.Hint)
			continue
		}
		if tc.allowed {
			if d.RuleIndex != tc.rule || d.Scope != tc.scope || d.Rule == "" {
				t.Errorf("%s: rule=%d scope=%s", tc.name, d.RuleIndex, d.Scope)
			}
			continue
		}
		if d.Code != tc.code {
			t.Errorf("%s: code=%s want %s", tc.name, d.Code, tc.code)
		}
		if tc.hintHas != "" && !strings.Contains(d.Hint, tc.hintHas) {
			t.Errorf("%s: hint %q lacks %q", tc.name, d.Hint, tc.hintHas)
		}
		if d.Reason == "" || d.Error() == nil {
			t.Errorf("%s: missing reason", tc.name)
		}
	}
}

func TestReadOnlyHint(t *testing.T) {
	p := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/.*$']\n")
	d := check(p, "POST", "https://a.com/x", "", "")
	if d.Code != apierr.DeniedMethod || !strings.Contains(d.Hint, "read-only") || !strings.Contains(d.Hint, "write grant") {
		t.Errorf("hint: %q", d.Hint)
	}
}

func TestRuleOrderFirstPassingWins(t *testing.T) {
	// Rule 0 is GraphQL-restricted by operation name; rule 1 is broader.
	p := mustParse(t, `
name: x
match: {hosts: [a.com]}
allow:
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
    graphql: {operations: [Allowed]}
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
`)
	d := check(p, "POST", "https://a.com/graphql", `{"query":"query Allowed { a }"}`, "application/json")
	if !d.Allowed || d.RuleIndex != 0 {
		t.Errorf("want rule 0, got %+v", d)
	}
	d = check(p, "POST", "https://a.com/graphql", `{"query":"query Other { a }"}`, "application/json")
	if !d.Allowed || d.RuleIndex != 1 {
		t.Errorf("want rule 1, got %+v", d)
	}
	d = check(p, "POST", "https://a.com/graphql", `{"query":"mutation M { a }"}`, "application/json")
	if d.Allowed || d.Code != apierr.DeniedInspector {
		t.Errorf("want inspector denial, got %+v", d)
	}
}

func TestNoSecretsInMessages(t *testing.T) {
	p := mustParse(t, rulesYAML)
	secret := "SUPERSECRETVALUE"
	pu := mustURL(t, "https://a.com/graphql")
	for _, body := range []string{
		`{"query":"mutation { pay(token: \"` + secret + `\") }"}`,
		`{"query":"{ ` + secret + `"}`,
		secret,
	} {
		d := p.Check(context.Background(), CheckRequest{
			Method: "POST", URL: pu, Body: []byte(body),
			Headers: []api.Header{{Name: "X-Token", Value: secret}, {Name: "Content-Type", Value: "application/json"}},
		})
		if d.Allowed {
			t.Fatalf("unexpectedly allowed: %s", body)
		}
		if strings.Contains(d.Reason+d.Hint, secret) {
			t.Errorf("secret leaked: %q / %q", d.Reason, d.Hint)
		}
	}
	d := check(p, "PUT", "https://a.com/"+secret, secret, "")
	if strings.Contains(d.Reason+d.Hint, secret) {
		t.Errorf("secret leaked in method denial")
	}
	d = check(p, "GET", "https://a.com/"+secret, secret, "")
	if strings.Contains(d.Reason+d.Hint, secret) {
		t.Errorf("secret leaked in path denial: %q", d.Reason)
	}
}

func gqlPolicy(t *testing.T, extra string) *Policy {
	return mustParse(t, "name: g\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET, POST]\n    paths: ['^/graphql$']\n    inspect: graphql_query_only\n"+extra)
}

func TestGraphQLInspector(t *testing.T) {
	p := gqlPolicy(t, "")
	hash := strings.Repeat("ab", 32)
	pp := gqlPolicy(t, "    graphql:\n      persisted_hashes: ['"+hash+"']\n")
	ops := gqlPolicy(t, "    graphql:\n      operations: [GetMe, Other]\n")
	tests := []struct {
		name    string
		p       *Policy
		method  string
		url     string
		ct      string
		body    string
		allowed bool
		reason  string
	}{
		{"query", p, "POST", "/graphql", "application/json", `{"query":"query Q { me { id } }"}`, true, ""},
		{"shorthand query", p, "POST", "/graphql", "application/json", `{"query":"{ me { id } }"}`, true, ""},
		{"no content-type", p, "POST", "/graphql", "", `{"query":"{ me }"}`, true, ""},
		{"mutation", p, "POST", "/graphql", "application/json", `{"query":"mutation M { x }"}`, false, "mutation"},
		{"anonymous mutation", p, "POST", "/graphql", "application/json", `{"query":"mutation { x }"}`, false, "mutation"},
		{"subscription", p, "POST", "/graphql", "application/json", `{"query":"subscription S { x }"}`, false, "subscription"},
		{"mixed doc no opname", p, "POST", "/graphql", "application/json", `{"query":"query Q { a } mutation M { b }"}`, false, "mutation"},
		{"mixed doc opname query", p, "POST", "/graphql", "application/json", `{"query":"query Q { a } mutation M { b }","operationName":"Q"}`, true, ""},
		{"mixed doc opname mutation", p, "POST", "/graphql", "application/json", `{"query":"query Q { a } mutation M { b }","operationName":"M"}`, false, "mutation"},
		{"unknown opname", p, "POST", "/graphql", "application/json", `{"query":"query Q { a }","operationName":"Zzz"}`, false, "not found"},
		{"fragment only", p, "POST", "/graphql", "application/json", `{"query":"fragment F on T { a }"}`, false, "no operation"},
		{"batch ok", p, "POST", "/graphql", "application/json", `[{"query":"{a}"},{"query":"{b}"}]`, true, ""},
		{"batch with mutation", p, "POST", "/graphql", "application/json", `[{"query":"{a}"},{"query":"mutation { b }"}]`, false, "mutation"},
		{"empty batch", p, "POST", "/graphql", "application/json", `[]`, false, "not a valid"},
		{"garbage", p, "POST", "/graphql", "application/json", `}{ not json`, false, "not a valid"},
		{"binary garbage", p, "POST", "/graphql", "application/json", "\x00\x01\x02", false, "not a valid"},
		{"unparseable query", p, "POST", "/graphql", "application/json", `{"query":"query {{{"}`, false, "parsed"},
		{"missing query", p, "POST", "/graphql", "application/json", `{"variables":{}}`, false, "no query"},
		{"empty body", p, "POST", "/graphql", "application/json", ``, false, "no GraphQL"},
		{"trailing json", p, "POST", "/graphql", "application/json", `{"query":"{a}"} {"query":"mutation{b}"}`, false, "not a valid"},
		{"wrong types", p, "POST", "/graphql", "application/json", `{"query":5}`, false, "not a valid"},
		{"application/graphql ok", p, "POST", "/graphql", "application/graphql", `{ me }`, true, ""},
		{"application/graphql mutation", p, "POST", "/graphql", "application/graphql; charset=utf-8", `mutation { x }`, false, "mutation"},
		{"GET query", p, "GET", "/graphql?query=%7Bme%7D", "", ``, true, ""},
		{"GET mutation", p, "GET", "/graphql?query=mutation%7Bx%7D", "", ``, false, "mutation"},
		{"GET without query", p, "GET", "/graphql", "", ``, false, "no GraphQL"},
		{"POST body ok but URL mutation", p, "POST", "/graphql?query=mutation%7Bx%7D", "application/json", `{"query":"{a}"}`, false, "mutation"},
		{"persisted allowed", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"` + hash + `"}}}`, true, ""},
		{"persisted uppercase", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + strings.ToUpper(hash) + `"}}}`, true, ""},
		{"persisted unknown", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + strings.Repeat("cd", 32) + `"}}}`, false, "persisted_hashes"},
		{"persisted no list", p, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + hash + `"}}}`, false, "persisted_hashes"},
		{"persisted batch mixed", pp, "POST", "/graphql", "application/json", `[{"extensions":{"persistedQuery":{"sha256Hash":"` + hash + `"}}},{"query":"mutation{x}"}]`, false, "mutation"},
		{"ops allowed", ops, "POST", "/graphql", "application/json", `{"query":"query GetMe { me }"}`, true, ""},
		{"ops not listed", ops, "POST", "/graphql", "application/json", `{"query":"query Evil { me }"}`, false, "Evil"},
		{"ops anonymous", ops, "POST", "/graphql", "application/json", `{"query":"{ me }"}`, false, "anonymous"},
		{"case-variant query key", p, "POST", "/graphql", "application/json", `{"query":"mutation Del{deleteAll}","QUERY":"query Ok{me}"}`, false, "not a valid"},
		{"case-variant query key first", p, "POST", "/graphql", "application/json", `{"Query":"query Ok{me}","query":"mutation Del{deleteAll}"}`, false, "not a valid"},
		{"case-variant opname", p, "POST", "/graphql", "application/json", `{"query":"query A{me} mutation B{deleteAll}","operationName":"B","OperationName":"A"}`, false, "not a valid"},
		{"only case-variant query", p, "POST", "/graphql", "application/json", `{"QUERY":"query Ok{me}"}`, false, "not a valid"},
		{"duplicate query key", p, "POST", "/graphql", "application/json", `{"query":"mutation Del{deleteAll}","query":"query Ok{me}"}`, false, "not a valid"},
		{"duplicate opname", p, "POST", "/graphql", "application/json", `{"query":"query A{me} mutation B{x}","operationName":"B","operationName":"A"}`, false, "not a valid"},
		{"batch case-variant", p, "POST", "/graphql", "application/json", `[{"query":"{a}"},{"query":"mutation{x}","Query":"{b}"}]`, false, "not a valid"},
		{"case-variant extensions", pp, "POST", "/graphql", "application/json", `{"query":"mutation{x}","Extensions":{"persistedQuery":{"sha256Hash":"` + hash + `"}}}`, false, "not a valid"},
		{"case-variant persistedQuery", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + strings.Repeat("cd", 32) + `"},"PersistedQuery":{"sha256Hash":"` + hash + `"}}}`, false, "not a valid"},
		{"case-variant sha256Hash", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + strings.Repeat("cd", 32) + `","SHA256Hash":"` + hash + `"}}}`, false, "no query text"},
		{"duplicate nested key", pp, "POST", "/graphql", "application/json", `{"extensions":{"persistedQuery":{"sha256Hash":"` + strings.Repeat("cd", 32) + `","sha256Hash":"` + hash + `"}}}`, false, "not a valid"},
		{"null opname ok", p, "POST", "/graphql", "application/json", `{"query":"{a}","operationName":null,"variables":{"x":{"y":[1,{"z":2}]}}}`, true, ""},
		{"GET duplicate query", p, "GET", "/graphql?query=mutation%7Bx%7D&query=%7Bme%7D", "", ``, false, "ambiguous"},
		{"GET case-variant opname", p, "GET", "/graphql?query=query+A%7Bme%7D+mutation+B%7Bx%7D&operationName=B&OperationName=A", "", ``, false, "ambiguous"},
		{"ops opname selects", ops, "POST", "/graphql", "application/json", `{"query":"query GetMe { a } query Evil { b }","operationName":"GetMe"}`, true, ""},
	}
	for _, tc := range tests {
		pu := mustURL(t, "https://a.com"+tc.url)
		var hs []api.Header
		if tc.ct != "" {
			hs = []api.Header{{Name: "content-type", Value: tc.ct}}
		}
		req := InspectRequest{Method: tc.method, URL: pu, Headers: hs, Body: []byte(tc.body), Rule: &tc.p.Allow[0]}
		ok, reason, err := GraphQLQueryOnly{}.Inspect(context.Background(), req)
		if err != nil {
			t.Errorf("%s: err %v", tc.name, err)
			continue
		}
		if ok != tc.allowed {
			t.Errorf("%s: allowed=%v reason=%q", tc.name, ok, reason)
			continue
		}
		if !ok && !strings.Contains(reason, tc.reason) {
			t.Errorf("%s: reason %q lacks %q", tc.name, reason, tc.reason)
		}
	}
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "insp.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func execPolicy(t *testing.T, script string) *Policy {
	return mustParse(t, "name: e\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [POST]\n    paths: ['^/x$']\n    inspect: 'exec:"+script+"'\n")
}

func TestExecInspector(t *testing.T) {
	// The script records stdin so we can check the payload.
	dir := t.TempDir()
	dump := filepath.Join(dir, "stdin.json")
	allow := writeScript(t, "cat > '"+dump+"'\necho allow\n")
	p := execPolicy(t, allow)
	d := check(p, "POST", "https://a.com/x?q=1", "hello", "text/plain")
	if !d.Allowed || d.Scope != "write" {
		t.Fatalf("allow: %+v", d)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Method     string
		URL        string
		Headers    []api.Header
		BodyBase64 string `json:"body_base64"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.Method != "POST" || payload.URL != "https://a.com/x?q=1" || payload.BodyBase64 != "aGVsbG8=" || len(payload.Headers) != 1 {
		t.Errorf("payload: %+v", payload)
	}

	long := strings.Repeat("z", 500)
	tests := []struct {
		name, script string
		allowed      bool
		reason       string
	}{
		{"deny with reason", "cat >/dev/null\necho 'no way'\nexit 1\n", false, "no way"},
		{"exit 0 but not allow", "cat >/dev/null\necho maybe\n", false, "maybe"},
		{"exit nonzero but allow", "cat >/dev/null\necho allow\nexit 3\n", false, "denied by exec"},
		{"silent deny", "exit 1\n", false, "denied by exec"},
		{"long reason truncated", "echo " + long + "\nexit 1\n", false, strings.Repeat("z", 200)},
		{"allow not first line", "echo hmm\necho allow\n", false, "hmm"},
	}
	for _, tc := range tests {
		d := check(execPolicy(t, writeScript(t, tc.script)), "POST", "https://a.com/x", "", "")
		if d.Allowed != tc.allowed {
			t.Errorf("%s: %+v", tc.name, d)
			continue
		}
		if !d.Allowed {
			if d.Code != apierr.DeniedInspector || !strings.Contains(d.Reason, tc.reason) {
				t.Errorf("%s: %q", tc.name, d.Reason)
			}
		}
	}
	d = check(execPolicy(t, writeScript(t, "echo "+long+"\nexit 1\n")), "POST", "https://a.com/x", "", "")
	if strings.Contains(d.Reason, strings.Repeat("z", 201)) {
		t.Error("reason not truncated to 200 chars")
	}

	// Missing program: denied, not allowed.
	d = check(execPolicy(t, "/nonexistent/curd-inspector"), "POST", "https://a.com/x", "", "")
	if d.Allowed || d.Code != apierr.DeniedInspector {
		t.Errorf("missing program: %+v", d)
	}
}

func TestExecInspectorTimeout(t *testing.T) {
	old := execTimeout
	execTimeout = 200 * time.Millisecond
	defer func() { execTimeout = old }()
	p := execPolicy(t, writeScript(t, "sleep 30\necho allow\n"))
	start := time.Now()
	d := check(p, "POST", "https://a.com/x", "", "")
	if d.Allowed || !strings.Contains(d.Reason, "timed out") {
		t.Errorf("timeout: %+v", d)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestFilterRequestHeaders(t *testing.T) {
	p := mustParse(t, goodYAML)
	in := []api.Header{
		{Name: "Accept", Value: "a"}, {Name: "Cookie", Value: "c=1"}, {Name: "authorization", Value: "Bearer x"}, {Name: "Host", Value: "evil"},
		{Name: "X-CSRF-Token", Value: "t"}, {Name: "X-Other", Value: "o"}, {Name: "Content-Length", Value: "5"}, {Name: "Connection", Value: "close"},
		{Name: "Transfer-Encoding", Value: "chunked"}, {Name: "Proxy-Authorization", Value: "p"}, {Name: "Content-Type", Value: "application/json"},
		{Name: "Accept-Language", Value: "en"}, {Name: "X-Evil", Value: "a\r\nInjected: 1"},
	}
	kept, dropped := p.FilterRequestHeaders(in)
	var kn []string
	for _, h := range kept {
		kn = append(kn, h.Name)
	}
	if strings.Join(kn, ",") != "Accept,X-CSRF-Token,Content-Type" {
		t.Errorf("kept %v", kn)
	}
	for _, d := range dropped {
		for _, h := range in {
			if d == h.Value && d != h.Name {
				t.Errorf("dropped contains a value: %q", d)
			}
		}
	}
	if len(dropped) != len(in)-3 {
		t.Errorf("dropped %v", dropped)
	}

	// Default allowlist.
	p2 := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n")
	kept, _ = p2.FilterRequestHeaders(in)
	kn = nil
	for _, h := range kept {
		kn = append(kn, h.Name)
	}
	if strings.Join(kn, ",") != "Accept,Content-Type,Accept-Language" {
		t.Errorf("default kept %v", kn)
	}
	// Allowlisting a forbidden header does not let it through.
	p3 := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\nrequest:\n  header_allowlist: [cookie, host, x-a]\n")
	kept, _ = p3.FilterRequestHeaders([]api.Header{{Name: "Cookie", Value: "a"}, {Name: "Host", Value: "b"}, {Name: "X-A", Value: "c"}})
	if len(kept) != 1 || kept[0].Name != "X-A" {
		t.Errorf("kept %v", kept)
	}
	if len(p3.Warnings) != 2 {
		t.Errorf("warnings %v", p3.Warnings)
	}
}

func TestInjectRulesAndCookies(t *testing.T) {
	p := mustParse(t, goodYAML)
	ir := p.InjectRules()
	if len(ir) != 1 || ir[0].Header != "Authorization" || ir[0].Key != "authToken" ||
		ir[0].Origin != "https://app.example.com" || ir[0].Template != "Bearer {value}" {
		t.Fatalf("inject rules: %+v", ir)
	}
	if v, err := ir[0].Render("tok"); err != nil || v != "Bearer tok" {
		t.Errorf("render: %q %v", v, err)
	}
	if _, err := ir[0].Render("a\nb"); err == nil {
		t.Error("render accepted newline")
	}
	// Template containing colons is kept intact.
	if h, tm, err := parseInjectAs("header:X-A:a:b {value}"); err != nil || h != "X-A" || tm != "a:b {value}" {
		t.Errorf("colon template: %q %q %v", h, tm, err)
	}
	for name, want := range map[string]bool{"session": true, "__Host-abc": true, "other": false, "sessionx": false} {
		if got := p.CookieNameAllowed(name); got != want {
			t.Errorf("CookieNameAllowed(%q)=%v", name, got)
		}
	}
	all := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n")
	if !all.CookieNameAllowed("anything") {
		t.Error("empty list should allow all")
	}
	if got := all.CookieRequestNames(); len(got) != 0 {
		t.Errorf("CookieRequestNames for all = %q", got)
	}
	none := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\ncredentials:\n  cookies_none: true\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n")
	if none.CookieNameAllowed("anything") || none.CookieNameAllowed("session") {
		t.Error("cookies_none should allow no cookie")
	}
	rn := none.CookieRequestNames()
	if len(rn) != 1 {
		t.Fatalf("CookieRequestNames = %q", rn)
	}
	for _, n := range []string{"session", "a", "__Host-x", ""} {
		if ok, _ := path.Match(rn[0], n); ok {
			t.Errorf("no-cookies pattern matched %q", n)
		}
	}
	out, err := Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := Parse(out, ""); err != nil || !back.Credentials.CookiesNone {
		t.Errorf("cookies_none did not round-trip: %v\n%s", err, out)
	}
}

func TestRedactAndStrip(t *testing.T) {
	p := mustParse(t, goodYAML)
	if got := string(p.Redact([]byte(`{"k":"sk-abc123"}`))); got != `{"k":"[REDACTED]"}` {
		t.Errorf("redact: %s", got)
	}
	if !p.StripsResponseHeader("Set-Cookie") || !p.StripsResponseHeader("X-Secret") || p.StripsResponseHeader("Content-Type") {
		t.Error("strip headers")
	}
}

func TestLoadDirAndSet(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pol := func(name, host, extra string) string {
		return "name: " + name + "\n" + extra + "match: {hosts: ['" + host + "']}\nallow:\n  - methods: [GET, HEAD]\n    paths: ['^/api/.*']\n  - methods: [POST]\n    paths: ['^/graphql$']\n    inspect: graphql_query_only\n"
	}
	w("alpha.yaml", pol("alpha", "a.example.com", ""))
	w("wild.yaml", pol("wild", "*.example.com", ""))
	w("beta.draft.yaml", pol("beta", "b.example.com", ""))
	w("gamma.yaml", pol("gamma", "c.example.com", "status: draft\n"))
	w("broken.yaml", "name: broken\nmatch: {hosts: ['*']}\nallow: []\n")
	w("mismatch.yaml", pol("other", "d.example.com", ""))
	w("alpha.draft.yaml", pol("alpha", "z.example.com", "")) // collides with active alpha
	w("notes.txt", "ignored")

	s, errs := LoadDir(dir)
	if len(errs) != 3 {
		t.Fatalf("errors: %v", errs)
	}
	if s.Get("alpha") == nil || s.Get("beta") != nil || s.GetAny("beta") == nil || s.Get("gamma") != nil || !s.GetAny("gamma").IsDraft() {
		t.Error("Get/GetAny/draft handling wrong")
	}
	if s.Get("broken") != nil || s.GetAny("other") != nil {
		t.Error("invalid policies loaded")
	}
	var ns []string
	for _, p := range s.ForHost("a.example.com") {
		ns = append(ns, p.Name)
	}
	if strings.Join(ns, ",") != "alpha,wild" {
		t.Errorf("ForHost: %v", ns)
	}
	if got := s.ForHost("b.example.com"); len(got) != 1 || got[0].Name != "wild" {
		t.Errorf("draft must not match: %v", got)
	}
	if len(s.All()) != 4 {
		t.Errorf("All: %d", len(s.All()))
	}

	byName := map[string]api.PolicyStatus{}
	for _, st := range s.Statuses() {
		byName[st.Name+"/"+st.Status] = st
	}
	a := byName["alpha/active"]
	if len(a.Rules) != 2 || a.Rules[0] != "GET,HEAD ^/api/.* [read]" || a.Rules[1] != "POST ^/graphql$ inspect=graphql_query_only [read]" {
		t.Errorf("rules: %q", a.Rules)
	}
	if byName["beta/draft"].Name == "" || byName["gamma/draft"].Name == "" {
		t.Error("draft statuses missing")
	}
	if st := byName["broken/error"]; st.Error == "" {
		t.Error("error status missing")
	}

	if s2, errs := LoadDir(filepath.Join(dir, "nope")); len(errs) != 0 || len(s2.All()) != 0 {
		t.Error("missing dir should be empty")
	}
}

func TestDisabledRuleSummary(t *testing.T) {
	p := mustParse(t, rulesYAML)
	if got := p.Allow[2].Summary(); got != `(disabled) DELETE ^/items/\d+$ [write]` {
		t.Errorf("summary: %s", got)
	}
}

func TestDurationParsing(t *testing.T) {
	for in, want := range map[string]time.Duration{"8h": 8 * time.Hour, "30m": 30 * time.Minute, "2d": 48 * time.Hour} {
		p := mustParse(t, "name: x\nttl_default: "+in+"\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\n")
		if time.Duration(p.TTLDefault) != want {
			t.Errorf("%s: %v", in, p.TTLDefault)
		}
	}
}

func TestTestSection(t *testing.T) {
	p := mustParse(t, "name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\ntest:\n  host_map: {a.com: 127.0.0.1}\n")
	if p.Test == nil || p.Test.HostMap["a.com"] != "127.0.0.1" {
		t.Errorf("test section: %+v", p.Test)
	}
	if _, err := Parse([]byte("name: x\nmatch: {hosts: [a.com]}\nallow:\n  - methods: [GET]\n    paths: ['^/$']\ntest:\n  host_map: {'*.a.com': 127.0.0.1}\n"), ""); err == nil {
		t.Error("wildcard host_map key accepted")
	}
}
