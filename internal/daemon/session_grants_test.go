package daemon_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/chrome"
)

func needChrome(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("launches Chrome")
	}
	if _, err := chrome.FindBinary(); err != nil {
		t.Skipf("no Chrome/Chromium: %v", err)
	}
}

// A browser session opened under "Allow once" is owned by an internal
// session-lifetime grant: revocation closes it, ownership needs a live grant,
// renewing does not consume unrelated once grants, and the internal grant
// never serves fetches by session-key matching.
func TestBrowserSessionOnceGrantRevocable(t *testing.T) {
	needChrome(t)
	e := newTenv(t, writeScript(t, `
prompts:
  - {expect: {kind: grant, policies: [app], scope: read}, answer: once}
  - {expect: {kind: grant, policies: [app], scope: read}, answer: once}
`))
	ctx := context.Background()
	c := caller("k")
	var open api.OpenSessionResult
	if err := e.cl.Call(ctx, api.MethodOpenSession, api.OpenSessionParams{Caller: c, Policies: []string{"app"}}, &open); err != nil {
		t.Fatal(err)
	}
	list := func() []api.GrantInfo {
		var r api.GrantsListResult
		if err := e.cl.Call(ctx, api.MethodGrantsList, api.GrantsListParams{}, &r); err != nil {
			t.Fatal(err)
		}
		return r.Grants
	}
	if gs := list(); len(gs) != 1 || gs[0].Mode != "session" || gs[0].Policies[0] != "app" {
		t.Fatalf("want one internal session grant, got %+v", gs)
	}
	// The internal grant does not authorize fetches for the same key.
	nc := c
	nc.NoPrompt = true
	_, err := e.fetch(api.FetchParams{Caller: nc, URL: e.url("app.example.com", "/api/me")})
	wantCode(t, err, apierr.DeniedNoGrant)

	// A second, unrelated once grant survives browse renewal.
	var gr api.GrantsRequestResult
	if err := e.cl.Call(ctx, api.MethodGrantsRequest, api.GrantsRequestParams{Caller: c, Policies: []string{"app"}, Mode: "once"}, &gr); err != nil {
		t.Fatal(err)
	}
	if gr.Grant.Mode != "once" {
		t.Fatalf("%+v", gr.Grant)
	}
	var br api.BrowseResult
	if err := e.cl.Call(ctx, api.MethodBrowse, api.BrowseParams{Caller: c, SessionID: open.SessionID, Verb: "url"}, &br); err != nil {
		t.Fatal(err)
	}
	if gs := list(); len(gs) != 2 {
		t.Fatalf("browse consumed an unrelated once grant: %+v", gs)
	}
	// Another key cannot drive it.
	err = e.cl.Call(ctx, api.MethodBrowse, api.BrowseParams{Caller: caller("other"), SessionID: open.SessionID, Verb: "url"}, &br)
	wantCode(t, err, apierr.NotFound)

	var rv api.GrantsRevokeResult
	if err := e.cl.Call(ctx, api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: "all"}, &rv); err != nil {
		t.Fatal(err)
	}
	var sl api.SessionsListResult
	if err := e.cl.Call(ctx, api.MethodSessionsList, api.SessionsListParams{Caller: c}, &sl); err != nil {
		t.Fatal(err)
	}
	if len(sl.Sessions) != 0 {
		t.Fatalf("revoking all grants left the session open: %+v", sl)
	}
	err = e.cl.Call(ctx, api.MethodBrowse, api.BrowseParams{Caller: c, SessionID: open.SessionID, Verb: "url"}, &br)
	wantCode(t, err, apierr.NotFound)
}

func (e *tenv) posts(path string) (n int) {
	for _, r := range e.mock.Requests() {
		if r.Method == "POST" && r.Path == path {
			n++
		}
	}
	return n
}

// exploreAndDraft runs the CSRF flow from spec 16.8 through the RPC API and
// returns the draft name, with its write rule enabled by hand.
func exploreAndDraft(t *testing.T, e *tenv, c api.Caller, write bool) string {
	t.Helper()
	ctx := context.Background()
	var open api.OpenSessionResult
	if err := e.cl.Call(ctx, api.MethodOpenSession, api.OpenSessionParams{Caller: c, Policies: []string{"app"}, Explore: true, AllowWrites: write}, &open); err != nil {
		t.Fatal(err)
	}
	browse := func(verb string, args ...string) {
		t.Helper()
		var r api.BrowseResult
		if err := e.cl.Call(ctx, api.MethodBrowse, api.BrowseParams{Caller: c, SessionID: open.SessionID, Verb: verb, Args: args}, &r); err != nil {
			t.Fatalf("browse %s %v: %v", verb, args, err)
		}
	}
	browse("open", e.url("app.example.com", "/settings"))
	browse("click", "#save")
	browse("waitidle")
	browse("open", e.url("app.example.com", "/api/settings"))
	var cl api.CaptureListResult
	if err := e.cl.Call(ctx, api.MethodCaptureList, api.CaptureListParams{Caller: c, SessionID: open.SessionID}, &cl); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, en := range cl.Entries {
		if strings.HasSuffix(en.URL, "/api/settings") && (en.Method == "GET" || en.Method == "POST") {
			ids = append(ids, en.ID)
		}
	}
	if len(ids) < 2 {
		t.Fatalf("captures: %+v", cl.Entries)
	}
	var dr api.DistillDraftResult
	if err := e.cl.Call(ctx, api.MethodDistillDraft, api.DistillDraftParams{Caller: c, SessionID: open.SessionID, IDs: ids, Name: "settings"}, &dr); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dr.Path)
	if err != nil || !strings.Contains(string(b), "disabled: true") {
		t.Fatalf("draft has no disabled write rule: %v\n%s", err, b)
	}
	if err := os.WriteFile(dr.Path, []byte(strings.ReplaceAll(string(b), "disabled: true", "disabled: false")), 0o600); err != nil {
		t.Fatal(err)
	}
	return dr.Name
}

func verifyItems(t *testing.T, e *tenv, c api.Caller, draft string) map[string]api.VerifyItem {
	t.Helper()
	var vr api.DistillVerifyResult
	if err := e.cl.Call(context.Background(), api.MethodDistillVerify, api.DistillVerifyParams{Caller: c, Draft: draft, Minimize: true}, &vr); err != nil {
		t.Fatal(err)
	}
	out := map[string]api.VerifyItem{}
	for _, it := range vr.Items {
		out[it.Method] = it
	}
	return out
}

// distill.verify replays a write only with a write grant, and a write is
// sent exactly once even with minimize.
func TestDistillVerifyWriteNeedsWriteGrant(t *testing.T) {
	needChrome(t)
	t.Run("read-only session skips writes", func(t *testing.T) {
		e := newTenv(t, "allow-all")
		c := caller("k")
		draft := exploreAndDraft(t, e, c, false)
		items := verifyItems(t, e, c, draft)
		post, ok := items["POST"]
		if !ok || !strings.Contains(post.Skipped, "write grant") {
			t.Fatalf("POST not skipped for lack of a write grant: %+v", items)
		}
		if n := e.posts("/api/settings"); n != 0 {
			t.Fatalf("%d POSTs reached the upstream (the browser's was blocked, verify must not send one)", n)
		}
		if get := items["GET"]; !get.OK {
			t.Fatalf("GET: %+v", get)
		}
	})
	t.Run("write session replays once", func(t *testing.T) {
		e := newTenv(t, "allow-all")
		c := caller("k")
		draft := exploreAndDraft(t, e, c, true)
		before := e.posts("/api/settings") // the page's own POST
		items := verifyItems(t, e, c, draft)
		if post := items["POST"]; post.Skipped != "" {
			t.Fatalf("POST skipped despite a write grant: %+v", post)
		}
		if n := e.posts("/api/settings") - before; n != 1 {
			t.Fatalf("verify sent the write %d times, want exactly 1", n)
		}
	})
}
