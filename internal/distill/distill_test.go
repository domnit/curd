package distill

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/capture"
	"github.com/domnit/curd/internal/policy"
)

func h(kv ...string) []api.Header {
	var out []api.Header
	for i := 0; i < len(kv); i += 2 {
		out = append(out, api.Header{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func TestGeneralizePath(t *testing.T) {
	for in, want := range map[string]string{
		"/":               `^/$`,
		"/api/teams":      `^/api/teams$`,
		"/api/teams/123":  `^/api/teams/[0-9]+$`,
		"/api/teams/123/": `^/api/teams/[0-9]+/$`,
		"/u/550e8400-e29b-41d4-a716-446655440000/x": `^/u/[0-9a-fA-F-]{36}/x$`,
		"/o/a1b2c3d4e5f6a7b8c9":                     `^/o/[^/]+$`,
		"/files/report.v2.json":                     `^/files/report\.v2\.json$`,
		"/api/organizations":                        `^/api/organizations$`,
		"/a+b/(c)":                                  `^/a\+b/\(c\)$`,
		"/short1/abc-def":                           `^/short1/abc-def$`,
	} {
		if got := GeneralizePath(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func entries() []*capture.Entry {
	return []*capture.Entry{
		{ID: "c1", Method: "GET", URL: "https://app.example.com/api/teams/42?x=1", Status: 200, MimeType: "application/json",
			RequestHeaders: h("Accept", "application/json", "User-Agent", "Mozilla", "Sec-Fetch-Mode", "cors", "Referer", "https://app.example.com/",
				"Cookie", "session={cookie:session}; theme={cookie:theme}", "X-CSRF-Token", "abc123token", "X-Client-Version", "9",
				"Authorization", "Bearer {ls:https://app.example.com:authToken}", "Content-Length", "0"),
			ResponseHeaders: h("Content-Type", "application/json"),
			ResponseBody:    []byte(`{"id":42,"name":"t","members":[{"id":1,"email":"a"}]}`)},
		{ID: "c2", Method: "GET", URL: "https://app.example.com/api/teams/43", Status: 200,
			RequestHeaders: h("Cookie", "session={cookie:session}")},
		{ID: "c3", Method: "POST", URL: "https://app.example.com/api/teams/42/notes", Status: 200, BlockedWrite: true, Blocked: "write",
			RequestHeaders: h("Content-Type", "application/json", "X-CSRF-Token", "abc123token"),
			RequestBody:    []byte(`{"text":"hi"}`)},
		{ID: "c4", Method: "GET", URL: "https://cdn.example.com/x", Status: 200, RequestHeaders: h("Accept", "*/*")},
	}
}

func TestDraft(t *testing.T) {
	p, cmds, err := Draft("team-api", entries())
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != policy.StatusDraft || !reflect.DeepEqual(p.Match.Hosts, []string{"app.example.com", "cdn.example.com"}) {
		t.Fatalf("%+v", p.Match)
	}
	if len(p.Allow) != 3 {
		t.Fatalf("rules %+v", p.Allow)
	}
	r0, r2 := p.Allow[0], p.Allow[1]
	if r0.Methods[0] != "GET" || r0.Paths[0] != `^/api/teams/[0-9]+$` || r0.Disabled {
		t.Fatalf("%+v", r0)
	}
	if r2.Methods[0] != "POST" || !r2.Disabled || r2.Scope != "write" || !strings.Contains(r2.Note, "enable explicitly") {
		t.Fatalf("%+v", r2)
	}
	if !reflect.DeepEqual(p.Credentials.Cookies, []string{"session", "theme"}) {
		t.Fatalf("cookies %v", p.Credentials.Cookies)
	}
	if len(p.Credentials.LocalStorage) != 1 || p.Credentials.LocalStorage[0].InjectAs != "header:Authorization:Bearer {value}" ||
		p.Credentials.LocalStorage[0].Origin != "https://app.example.com" || p.Credentials.LocalStorage[0].Keys[0] != "authToken" {
		t.Fatalf("%+v", p.Credentials.LocalStorage)
	}
	if got := strings.Join(p.Request.HeaderAllowlist, ","); got != "accept,content-type,x-client-version,x-csrf-token" {
		t.Fatalf("allowlist %s", got)
	}
	if p.Redirects != "same-host-only" || p.TTLDefault != policy.Duration(8*time.Hour) || !reflect.DeepEqual(p.Response.StripHeaders, []string{"set-cookie"}) {
		t.Fatalf("%+v", p)
	}
	// round trip
	data, err := policy.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Parse(data, ""); err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 4 {
		t.Fatalf("cmds %v", cmds)
	}
	if !strings.HasPrefix(cmds[0], "curd fetch 'team-api' -H 'Accept: application/json'") ||
		!strings.HasSuffix(cmds[0], "'https://app.example.com/api/teams/42?x=1'") {
		t.Fatalf("%s", cmds[0])
	}
	if !strings.Contains(cmds[2], "-X POST") || !strings.Contains(cmds[2], `-d '{"text":"hi"}'`) {
		t.Fatalf("%s", cmds[2])
	}
	for _, c := range cmds {
		if strings.Contains(c, "{cookie:") || strings.Contains(c, "{ls:") || strings.Contains(strings.ToLower(c), "authorization") {
			t.Fatalf("placeholder in %s", c)
		}
	}
}

func TestDraftGraphQL(t *testing.T) {
	gq := func(id, body string) *capture.Entry {
		return &capture.Entry{ID: id, Method: "POST", URL: "https://app.example.com/graphql", Status: 200,
			RequestHeaders: h("Content-Type", "application/json"), RequestBody: []byte(body)}
	}
	p, _, err := Draft("gql", []*capture.Entry{
		gq("c1", `{"operationName":"Teams","query":"query Teams { teams { id } }"}`),
		gq("c2", `{"operationName":"Me","query":"query Me { me { id } }"}`),
		gq("c3", `{"operationName":"Rename","query":"mutation Rename($n:String){ rename(n:$n){ id } }"}`),
		{ID: "c4", Method: "POST", URL: "https://app.example.com/api/search", Status: 200,
			RequestBody: []byte(`{"query":"{ viewer { id } }"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) != 3 {
		t.Fatalf("%+v", p.Allow)
	}
	q := p.Allow[0]
	if q.Inspect != "graphql_query_only" || q.Disabled || q.GraphQL == nil || !reflect.DeepEqual(q.GraphQL.Operations, []string{"Teams", "Me"}) {
		t.Fatalf("%+v", q)
	}
	m := p.Allow[1]
	if m.Inspect != "" || !m.Disabled || m.Scope != "write" {
		t.Fatalf("%+v", m)
	}
	s := p.Allow[2] // anonymous query on non-graphql path: query rule, no operation list
	if s.Inspect != "graphql_query_only" || s.GraphQL != nil {
		t.Fatalf("%+v", s)
	}
}

// fakeRep scripts a server: needs x-csrf-token for 200, else 403.
type fakeRep struct {
	calls   int
	respond func(req ReplayRequest) (*ReplayResponse, error)
}

func (f *fakeRep) Replay(_ context.Context, _ *policy.Policy, req ReplayRequest) (*ReplayResponse, error) {
	f.calls++
	return f.respond(req)
}

func hasHeader(req ReplayRequest, n string) bool {
	for _, x := range req.Headers {
		if strings.EqualFold(x.Name, n) {
			return true
		}
	}
	return false
}

func jsonResp(status int, body string) *ReplayResponse {
	return &ReplayResponse{Status: status, Headers: h("Content-Type", "application/json; charset=utf-8"), Body: []byte(body)}
}

func TestVerifyMinimizeAndSkips(t *testing.T) {
	es := entries()[:1]
	es = append(es, &capture.Entry{ID: "c9", Method: "GET", URL: "https://app.example.com/api/teams/44", Status: 200, MimeType: "application/json",
		RequestHeaders: h("Accept", "application/json", "X-CSRF-Token", "abc123token", "X-Client-Version", "9"),
		ResponseBody:   []byte(`{"id":44,"name":"x","members":[]}`)}, entries()[2])
	draft, _, err := Draft("team-api", es)
	if err != nil {
		t.Fatal(err)
	}
	rep := &fakeRep{respond: func(req ReplayRequest) (*ReplayResponse, error) {
		if !hasHeader(req, "x-csrf-token") {
			return jsonResp(403, `{}`), nil
		}
		return jsonResp(200, `{"id":1,"name":"n","members":[{"id":2,"email":"e"}]}`), nil
	}}
	res, narrowed, err := Verify(context.Background(), draft, es, rep, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || len(res.Items) != 3 {
		t.Fatalf("%+v", res)
	}
	for _, it := range res.Items[:2] {
		if !it.OK || !reflect.DeepEqual(it.NeededHeaders, []string{"x-csrf-token"}) {
			t.Fatalf("%+v", it)
		}
	}
	if !strings.Contains(res.Items[2].Skipped, "disabled") {
		t.Fatalf("write not skipped: %+v", res.Items[2])
	}
	// accept and x-client-version were tested and dropped; content-type
	// appears only on the skipped write, so it is kept.
	if got := strings.Join(narrowed.Request.HeaderAllowlist, ","); got != "content-type,x-csrf-token" {
		t.Fatalf("allowlist %s", got)
	}
	if !strings.Contains(res.YAML, "x-csrf-token") || strings.Contains(res.YAML, "x-client-version") {
		t.Fatalf("yaml %s", res.YAML)
	}
	if _, err := policy.Parse([]byte(res.YAML), ""); err != nil {
		t.Fatal(err)
	}
	// draft itself untouched
	if len(draft.Request.HeaderAllowlist) < 4 {
		t.Fatal("draft mutated")
	}
}

func TestVerifyMinimizeJointRedundancy(t *testing.T) {
	// Server needs at least one of a/b: each alone is removable, both not.
	e := &capture.Entry{ID: "c1", Method: "GET", URL: "https://app.example.com/x", Status: 200, MimeType: "text/plain",
		RequestHeaders: h("X-A", "1", "X-B", "1")}
	draft, _, err := Draft("p", []*capture.Entry{e})
	if err != nil {
		t.Fatal(err)
	}
	rep := &fakeRep{respond: func(req ReplayRequest) (*ReplayResponse, error) {
		if !hasHeader(req, "x-a") && !hasHeader(req, "x-b") {
			return &ReplayResponse{Status: 401}, nil
		}
		return &ReplayResponse{Status: 200, Headers: h("Content-Type", "text/plain")}, nil
	}}
	res, narrowed, err := Verify(context.Background(), draft, []*capture.Entry{e}, rep, true)
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	if len(narrowed.Request.HeaderAllowlist) != 2 {
		t.Fatalf("must fall back to full set: %v", narrowed.Request.HeaderAllowlist)
	}
}

func TestVerifyShapeAndStatus(t *testing.T) {
	e := entries()[0]
	draft, _, _ := Draft("p", []*capture.Entry{e})
	run := func(resp *ReplayResponse, err error) *api.VerifyItem {
		rep := &fakeRep{respond: func(ReplayRequest) (*ReplayResponse, error) { return resp, err }}
		res, _, verr := Verify(context.Background(), draft, []*capture.Entry{e}, rep, false)
		if verr != nil {
			t.Fatal(verr)
		}
		return &res.Items[0]
	}
	// same shape, different values; both 2xx with different codes is fine
	it := run(&ReplayResponse{Status: 201, Headers: h("Content-Type", "application/json"),
		Body: []byte(`{"id":1,"name":"q","members":[{"id":5,"email":"x"},{"id":6}]}`)}, nil)
	if !it.OK {
		t.Fatalf("%+v", it)
	}
	it = run(jsonResp(200, `{"id":"1","members":[{"id":5}],"new":true}`), nil)
	want := []string{"type changed $.id: number -> string", "missing key $.members[0].email", "missing key $.name", "extra key $.new"}
	if it.OK || !reflect.DeepEqual(it.ShapeDiff, want) {
		t.Fatalf("%+v", it)
	}
	it = run(&ReplayResponse{Status: 200, Headers: h("Content-Type", "text/html"), Body: []byte("<html>")}, nil)
	if it.OK || len(it.ShapeDiff) != 1 || !strings.Contains(it.ShapeDiff[0], "json -> html") {
		t.Fatalf("%+v", it)
	}
	it = run(jsonResp(500, `{}`), nil)
	if it.OK || it.ReplayStatus != 500 || it.CapturedStatus != 200 {
		t.Fatalf("%+v", it)
	}
	it = run(nil, apierr.New(apierr.DeniedPath, "no", ""))
	if it.OK || it.Error != apierr.DeniedPath {
		t.Fatalf("%+v", it)
	}
}

func TestVerifyContext(t *testing.T) {
	e := entries()[0]
	draft, _, _ := Draft("p", []*capture.Entry{e})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := &fakeRep{respond: func(ReplayRequest) (*ReplayResponse, error) { return nil, ctx.Err() }}
	if _, _, err := Verify(ctx, draft, []*capture.Entry{e}, rep, false); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestReplayRequestOmitsPlaceholders(t *testing.T) {
	e := entries()[0]
	draft, _, _ := Draft("p", []*capture.Entry{e})
	var got ReplayRequest
	rep := &fakeRep{respond: func(r ReplayRequest) (*ReplayResponse, error) {
		got = r
		return jsonResp(200, `{}`), nil
	}}
	_, _, _ = Verify(context.Background(), draft, []*capture.Entry{e}, rep, false)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "{cookie") || strings.Contains(string(b), "{ls:") || hasHeader(got, "cookie") || hasHeader(got, "authorization") {
		t.Fatalf("%s", b)
	}
}

func TestDraftNoCookiesIsExplicit(t *testing.T) {
	p, _, err := Draft("nocookie", []*capture.Entry{{ID: "c1", Method: "GET", URL: "https://app.example.com/api/x", Status: 200,
		RequestHeaders: h("Accept", "application/json", "X-HTTP-Method-Override", "DELETE")}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Credentials.CookiesNone || len(p.Credentials.Cookies) != 0 {
		t.Fatalf("credentials %+v", p.Credentials)
	}
	if p.CookieNameAllowed("session") {
		t.Fatal("draft without captured cookies allows all cookies")
	}
	for _, a := range p.Request.HeaderAllowlist {
		if strings.EqualFold(a, "x-http-method-override") {
			t.Fatalf("method override allowlisted: %v", p.Request.HeaderAllowlist)
		}
	}
	// With cookies captured, the list is used and cookies_none is off.
	p, _, err = Draft("withcookie", []*capture.Entry{{ID: "c1", Method: "GET", URL: "https://app.example.com/api/x", Status: 200,
		RequestHeaders: h("Cookie", "session={cookie:session}")}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Credentials.CookiesNone || !p.CookieNameAllowed("session") || p.CookieNameAllowed("other") {
		t.Fatalf("credentials %+v", p.Credentials)
	}
}

func TestDraftGraphQLAmbiguousKeysNotQuery(t *testing.T) {
	p, _, err := Draft("gql", []*capture.Entry{{ID: "c1", Method: "POST", URL: "https://app.example.com/graphql", Status: 200,
		RequestHeaders: h("Content-Type", "application/json"),
		RequestBody:    []byte(`{"query":"mutation Del{deleteAll}","QUERY":"query Ok{me}"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Allow[0]; r.Inspect == policy.InspectGraphQLQueryOnly || !r.Disabled || r.Scope != "write" {
		t.Fatalf("ambiguous GraphQL body drafted as query: %+v", r)
	}
}
