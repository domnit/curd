package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/redact"
)

const (
	secretCookie = "SECRETSESSIONVALUE-abc123"
	secretLS     = "LSSECRETTOKEN-xyz789"
	loginCookie  = "MINTEDLOGINCOOKIE-q1w2e3"
)

type reqRec struct{ Method, Host, Path, Cookie, Body string }

type env struct {
	t       *testing.T
	srv     *httptest.Server
	port    string
	mu      sync.Mutex
	reqs    []reqRec
	hostMap map[string]string
}

func (e *env) base(host string) string { return "http://" + host + ":" + e.port }

func (e *env) hits(host, method, path string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, r := range e.reqs {
		if r.Host == host && r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func (e *env) last(host, method, path string) (reqRec, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.reqs) - 1; i >= 0; i-- {
		r := e.reqs[i]
		if r.Host == host && r.Method == method && r.Path == path {
			return r, true
		}
	}
	return reqRec{}, false
}

const appPage = `<!doctype html><html><head><title>Home Page</title></head><body>
<h1 id="heading">Hello curd</h1>
<div id="hidden" style="display:none">nothing</div>
<div id="out">idle</div>
<div id="ls">none</div>
<div id="who">unknown</div>
<input id="name" type="text">
<button id="btn" onclick="document.getElementById('out').textContent='clicked'">Click</button>
<button id="write" onclick="fetch('/api/write',{method:'POST',body:'x=1'}).then(r=>document.getElementById('out').textContent='write status '+r.status).catch(e=>document.getElementById('out').textContent='write failed')">w</button>
<button id="gqlq" onclick="fetch('/graphql',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({query:'query Q { me { id } }'})}).then(r=>document.getElementById('out').textContent='gql status '+r.status).catch(e=>document.getElementById('out').textContent='gql failed')">q</button>
<button id="gqlm" onclick="fetch('/graphql',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({query:'mutation M { del(id: 1) { id } }'})}).then(r=>document.getElementById('out').textContent='gql status '+r.status).catch(e=>document.getElementById('out').textContent='gql failed')">m</button>
<button id="pop" onclick="window.open('/popup')">pop</button>
<a id="toother" href="OTHERURL">other</a>
<a id="next" href="/p2">next</a>
<script>
document.getElementById('ls').textContent = localStorage.getItem('token') || 'empty';
fetch('/whoami').then(r=>r.text()).then(t=>document.getElementById('who').textContent=t);
</script></body></html>`

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ck := r.Header.Get("Cookie")
		e.mu.Lock()
		e.reqs = append(e.reqs, reqRec{r.Method, hostOnly(r.Host), r.URL.Path, ck, string(body)})
		e.mu.Unlock()
		host := hostOnly(r.Host)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case host == "other.example.net":
			fmt.Fprint(w, "<title>Other</title><p>other site</p>")
		case r.URL.Path == "/":
			fmt.Fprint(w, strings.ReplaceAll(appPage, "OTHERURL", e.base("other.example.net")+"/"))
		case r.URL.Path == "/p2":
			fmt.Fprint(w, `<title>Page Two</title><a id="back" href="/">home</a><p id="p">second page</p>`)
		case r.URL.Path == "/popup":
			fmt.Fprint(w, `<title>Popup</title><p>popup page</p>`)
		case r.URL.Path == "/redir":
			http.Redirect(w, r, e.base("other.example.net")+"/", http.StatusFound)
		case r.URL.Path == "/dynamic":
			fmt.Fprint(w, `<title>Dyn</title><div id="box"></div><script>let n=0;const i=setInterval(()=>{document.getElementById('box').textContent='tick'+(++n);if(n>=5)clearInterval(i)},100)</script>`)
		case r.URL.Path == "/whoami":
			c, err := r.Cookie("sid")
			w.Header().Set("Content-Type", "text/plain")
			if err != nil {
				fmt.Fprint(w, "no cookie")
			} else {
				fmt.Fprint(w, "sid="+c.Value)
			}
		case r.URL.Path == "/api/write" || r.URL.Path == "/graphql":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		case r.URL.Path == "/login":
			http.SetCookie(w, &http.Cookie{Name: "minted", Value: loginCookie, Path: "/"})
			fmt.Fprint(w, `<title>Login</title><p id="c">welcome `+loginCookie+`</p>`)
		case r.URL.Path == "/big":
			fmt.Fprint(w, "<title>Big</title><pre id='b'>"+strings.Repeat("0123456789", 40000)+"</pre>")
		default:
			http.NotFound(w, r)
		}
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	_, e.port, _ = net.SplitHostPort(e.srv.Listener.Addr().String())
	e.hostMap = map[string]string{"app.example.com": "127.0.0.1", "other.example.net": "127.0.0.1"}
	return e
}

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i >= 0 {
		return h[:i]
	}
	return h
}

func mustPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(yaml), "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const appPolicy = `
name: app
match:
  hosts: [app.example.com]
allow:
  - methods: [GET]
    paths: ['^/.*$']
  - methods: [POST]
    paths: ['^/graphql$']
    inspect: graphql_query_only
  - methods: [POST]
    paths: ['^/api/write$']
    scope: write
`

type fakeRec struct {
	mu      sync.Mutex
	events  map[string]int
	blocked []blockedRec
	body    BodyFetcher
	post    BodyFetcher
	red     *redact.Redactor
}

type blockedRec struct {
	ID, Reason string
	Write      bool
	Req        BlockedRequest
}

func (f *fakeRec) HandleEvent(sid string, ev cdp.Event) {
	f.mu.Lock()
	f.events[ev.Method]++
	f.mu.Unlock()
}

func (f *fakeRec) MarkBlocked(id, reason string, write bool, req BlockedRequest) {
	f.mu.Lock()
	f.blocked = append(f.blocked, blockedRec{id, reason, write, req})
	f.mu.Unlock()
}

func (f *fakeRec) blockedList() []blockedRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]blockedRec(nil), f.blocked...)
}

type harness struct {
	env  *env
	mgr  *Manager
	rec  *fakeRec
	evMu sync.Mutex
	evs  []SessionEvent
}

func (h *harness) events(typ string) []SessionEvent {
	h.evMu.Lock()
	defer h.evMu.Unlock()
	var out []SessionEvent
	for _, e := range h.evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping browser tests in -short mode")
	}
	bin, err := chrome.FindBinary()
	if err != nil {
		t.Skipf("no Chrome available: %v", err)
	}
	h := &harness{env: newEnv(t)}
	h.rec = &fakeRec{events: map[string]int{}}
	h.mgr = NewManager(Options{
		Binary:   bin,
		Test:     true,
		HostMap:  h.env.hostMap,
		TempRoot: t.TempDir(),
		Load: func(ctx context.Context, p *policy.Policy) (*creds.Credentials, error) {
			return &creds.Credentials{
				Cookies: []creds.Cookie{
					{Name: "sid", Value: secretCookie, Domain: "app.example.com", Path: "/", HTTPOnly: true},
					{Name: "unrelated", Value: "UNRELATEDVALUE-999", Domain: "other.example.net", Path: "/"},
				},
				LocalStorage: []creds.LocalStorageItem{
					{Origin: "http://app.example.com", Key: "token", Value: secretLS},
				},
			}, nil
		},
		Recorders: func(id string, red *redact.Redactor, body, post BodyFetcher) Recorder {
			h.rec.body, h.rec.post, h.rec.red = body, post, red
			return h.rec
		},
		OnEvent: func(e SessionEvent) {
			h.evMu.Lock()
			h.evs = append(h.evs, e)
			h.evMu.Unlock()
		},
	})
	t.Cleanup(func() { h.mgr.CloseAll(context.Background()) })
	return h
}

func (h *harness) open(t *testing.T, spec OpenSpec) *Session {
	t.Helper()
	if spec.Policies == nil {
		spec.Policies = []*policy.Policy{mustPolicy(t, appPolicy)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := h.mgr.Open(ctx, spec)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func do(t *testing.T, s *Session, verb string, args ...string) *api.BrowseResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, err := s.Do(ctx, verb, args)
	if err != nil {
		t.Fatalf("%s %v: %v", verb, args, err)
	}
	return r
}

func doErr(t *testing.T, s *Session, verb string, args ...string) *apierr.Error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_, err := s.Do(ctx, verb, args)
	if err == nil {
		t.Fatalf("%s %v: expected an error", verb, args)
	}
	return apierr.As(err)
}

func waitText(t *testing.T, s *Session, sel, want string) string {
	t.Helper()
	var got string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got = do(t, s, "text", sel).Text
		if strings.Contains(got, want) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("text %s = %q, want to contain %q", sel, got, want)
	return got
}

func TestHoistSessionAndVerbs(t *testing.T) {
	h := newHarness(t)
	e := h.env
	s := h.open(t, OpenSpec{Owner: "grant1", Seed: SeedHoist})
	if !strings.HasPrefix(s.ID, "bs_") || h.mgr.Len() != 1 {
		t.Fatalf("id=%q len=%d", s.ID, h.mgr.Len())
	}
	if l, ok := h.mgr.Latest("grant1"); !ok || l != s {
		t.Fatal("Latest")
	}
	if g, ok := h.mgr.Get(s.ID); !ok || g != s {
		t.Fatal("Get")
	}
	if len(h.events("open")) != 1 {
		t.Fatalf("open events: %v", h.events("open"))
	}

	t.Run("profile is private", func(t *testing.T) {
		st, err := os.Stat(s.ProfileDir())
		if err != nil || st.Mode().Perm() != 0o700 {
			t.Fatalf("profile dir: %v %v", st, err)
		}
	})

	t.Run("open and seeding", func(t *testing.T) {
		r := do(t, s, "open", e.base("app.example.com")+"/")
		if !strings.Contains(r.Text, "app.example.com") || !strings.Contains(r.Text, "Home Page") {
			t.Fatalf("open: %q", r.Text)
		}
		// localStorage seeded before page scripts ran.
		if got := waitText(t, s, "#ls", "{ls:"); !strings.Contains(got, "{ls:http://app.example.com:token}") {
			t.Fatalf("ls text not redacted placeholder: %q", got)
		}
		// Cookie was sent to the policy host.
		waitText(t, s, "#who", "{cookie:sid}")
		rec, ok := e.last("app.example.com", "GET", "/whoami")
		if !ok || !strings.Contains(rec.Cookie, "sid="+secretCookie) {
			t.Fatalf("server did not see the seeded cookie: %+v", rec)
		}
		// The cookie for the unrelated host was not seeded anywhere visible.
		if strings.Contains(rec.Cookie, "UNRELATED") {
			t.Fatal("unrelated cookie leaked")
		}
		// Output never carries the secrets.
		for _, v := range []string{"text", "html"} {
			out := do(t, s, v, "body").Text
			if strings.Contains(out, secretCookie) || strings.Contains(out, secretLS) {
				t.Fatalf("%s leaked a secret: %q", v, out)
			}
		}
	})

	t.Run("simple verbs", func(t *testing.T) {
		if got := do(t, s, "url").Text; got != e.base("app.example.com")+"/" {
			t.Fatalf("url = %q", got)
		}
		if got := do(t, s, "title").Text; got != "Home Page" {
			t.Fatalf("title = %q", got)
		}
		if got := do(t, s, "text", "#heading").Text; got != "Hello curd" {
			t.Fatalf("text = %q", got)
		}
		if got := do(t, s, "html", "#heading").Text; got != `<h1 id="heading">Hello curd</h1>` {
			t.Fatalf("html = %q", got)
		}
		if do(t, s, "exists", "#btn").Text != "true" || do(t, s, "exists", "#nope").Text != "false" {
			t.Fatal("exists")
		}
		if do(t, s, "visible", "#btn").Text != "true" || do(t, s, "visible", "#hidden").Text != "false" || do(t, s, "visible", "#nope").Text != "false" {
			t.Fatal("visible")
		}
		e1 := doErr(t, s, "text", "#nope")
		if e1.Code != apierr.NotFound || !strings.Contains(e1.Message, `"#nope"`) {
			t.Fatalf("no-match error: %+v", e1)
		}
		if e2 := doErr(t, s, "text", "###"); e2.Code != apierr.InvalidRequest {
			t.Fatalf("invalid selector: %+v", e2)
		}
		if e3 := doErr(t, s, "click", "#nope"); e3.Code != apierr.NotFound {
			t.Fatalf("click no-match: %+v", e3)
		}
		if e4 := doErr(t, s, "text"); e4.Code != apierr.InvalidRequest {
			t.Fatalf("missing arg: %+v", e4)
		}
	})

	t.Run("click type focus", func(t *testing.T) {
		do(t, s, "click", "#btn")
		if got := do(t, s, "text", "#out").Text; got != "clicked" {
			t.Fatalf("after click: %q", got)
		}
		do(t, s, "focus", "#name")
		do(t, s, "type", "#name", "hello", "world")
		// Read the value back through html of the input is not possible; use
		// a selector on the focused value via :focus.
		if do(t, s, "exists", "#name:focus").Text != "true" {
			t.Fatal("input not focused")
		}
		if e := doErr(t, s, "focus", "#heading"); e.Code != apierr.BrowserError {
			t.Fatalf("focus non-focusable: %+v", e)
		}
	})

	t.Run("wait verbs", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/dynamic")
		start := time.Now()
		do(t, s, "waitstable", "300")
		if got := do(t, s, "text", "#box").Text; got != "tick5" {
			t.Fatalf("after waitstable box = %q (%v)", got, time.Since(start))
		}
		do(t, s, "waitidle", "100")
		do(t, s, "waitidle")
		if e := doErr(t, s, "waitstable", "abc"); e.Code != apierr.InvalidRequest {
			t.Fatalf("bad ms: %+v", e)
		}
	})

	t.Run("history", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		do(t, s, "click", "#next")
		if got := do(t, s, "title").Text; got != "Page Two" {
			t.Fatalf("after click nav title = %q", got)
		}
		r := do(t, s, "back")
		if !strings.Contains(r.Text, "Home Page") {
			t.Fatalf("back: %q", r.Text)
		}
		r = do(t, s, "forward")
		if !strings.Contains(r.Text, "Page Two") {
			t.Fatalf("forward: %q", r.Text)
		}
		r = do(t, s, "reload")
		if !strings.Contains(r.Text, "Page Two") {
			t.Fatalf("reload: %q", r.Text)
		}
		if e := doErr(t, s, "forward"); e.Code != apierr.InvalidRequest {
			t.Fatalf("forward at end: %+v", e)
		}
	})

	t.Run("screenshot", func(t *testing.T) {
		r := do(t, s, "screenshot")
		if len(r.PNG) < 100 || string(r.PNG[1:4]) != "PNG" {
			t.Fatalf("not a PNG: %d bytes", len(r.PNG))
		}
	})

	t.Run("big output is capped", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/big")
		out := do(t, s, "text", "#b").Text
		if len(out) > maxOutput+200 || !strings.Contains(out, "[truncated") {
			t.Fatalf("len=%d tail=%q", len(out), out[max(0, len(out)-80):])
		}
	})

	t.Run("gated and unknown verbs", func(t *testing.T) {
		if e := doErr(t, s, "js", "document.cookie"); e.Code != apierr.NotAvailable || e.Hint == "" {
			t.Fatalf("js: %+v", e)
		}
		if e := doErr(t, s, "capture", "list"); e.Code != apierr.InvalidRequest || !strings.Contains(e.Hint, "curd browse capture") {
			t.Fatalf("capture: %+v", e)
		}
		e := doErr(t, s, "cookies")
		if e.Code != apierr.InvalidRequest || !strings.Contains(e.Hint, "waitstable") {
			t.Fatalf("unknown verb: %+v", e)
		}
		if help := do(t, s, "help").Text; !strings.Contains(help, "newpage") || !strings.Contains(help, "screenshot") {
			t.Fatalf("help: %q", help)
		}
		if do(t, s, "login").Text == "" {
			t.Fatal("login verb empty")
		}
	})

	t.Run("navigation to unmatched host is blocked", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		before := len(h.rec.blockedList())
		err := doErr(t, s, "open", e.base("other.example.net")+"/")
		if err.Code != apierr.DeniedHost || !strings.Contains(err.Message, "other.example.net") || !strings.Contains(err.Hint, "app.example.com") {
			t.Fatalf("open other: %+v", err)
		}
		// Pre-check does not even reach the browser; the interceptor handles
		// clicks, redirects and scripted navigation.
		do(t, s, "open", e.base("app.example.com")+"/")
		err = doErr(t, s, "click", "#toother")
		if err.Code != apierr.DeniedHost || !strings.Contains(err.Message, "other.example.net") {
			t.Fatalf("click link to other host: %+v", err)
		}
		err = doErr(t, s, "open", e.base("app.example.com")+"/redir")
		if err.Code != apierr.DeniedHost || !strings.Contains(err.Message, "other.example.net") {
			t.Fatalf("redirect to other host: %+v", err)
		}
		bl := h.rec.blockedList()
		if len(bl) < before+2 {
			t.Fatalf("recorder saw %d blocked (before %d)", len(bl), before)
		}
		for _, b := range bl[before:] {
			if b.Reason != ReasonHostNotInPolicy || b.Write || b.Req.ResourceType != "Document" || b.ID == "" {
				t.Fatalf("blocked rec: %+v", b)
			}
		}
		if e.hits("other.example.net", "GET", "/") != 0 {
			t.Fatal("request reached the unmatched host")
		}
		if len(h.events("blocked")) < 2 {
			t.Fatalf("blocked events: %v", h.events("blocked"))
		}
		if e := doErr(t, s, "open", "file:///etc/passwd"); e.Code != apierr.InvalidRequest {
			t.Fatalf("file url: %+v", e)
		}
	})

	t.Run("writes blocked when read-only", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		before := len(h.rec.blockedList())
		do(t, s, "click", "#write")
		waitText(t, s, "#out", "write failed")
		if e.hits("app.example.com", "POST", "/api/write") != 0 {
			t.Fatal("blocked write reached the server")
		}
		bl := h.rec.blockedList()
		if len(bl) != before+1 {
			t.Fatalf("blocked: %+v", bl)
		}
		b := bl[len(bl)-1]
		if !b.Write || b.Reason != ReasonWriteNotGranted || b.Req.Method != "POST" || string(b.Req.PostData) != "x=1" || !strings.HasSuffix(b.Req.URL, "/api/write") {
			t.Fatalf("blocked write record: %+v", b)
		}
	})

	t.Run("graphql inspector", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		do(t, s, "click", "#gqlq")
		waitText(t, s, "#out", "gql status 200")
		if e.hits("app.example.com", "POST", "/graphql") != 1 {
			t.Fatal("query did not reach the server")
		}
		before := len(h.rec.blockedList())
		do(t, s, "click", "#gqlm")
		waitText(t, s, "#out", "gql failed")
		if e.hits("app.example.com", "POST", "/graphql") != 1 {
			t.Fatal("mutation reached the server")
		}
		bl := h.rec.blockedList()
		if len(bl) != before+1 || !bl[len(bl)-1].Write || !strings.Contains(bl[len(bl)-1].Reason, apierr.DeniedInspector) {
			t.Fatalf("blocked mutation: %+v", bl[before:])
		}
	})

	t.Run("pages", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		before := len(strings.Split(strings.TrimSpace(do(t, s, "pages").Text), "\n"))
		r := do(t, s, "newpage", e.base("app.example.com")+"/p2")
		if !strings.Contains(r.Text, "/p2") {
			t.Fatalf("newpage: %q", r.Text)
		}
		pages := do(t, s, "pages").Text
		lines := strings.Split(strings.TrimSpace(pages), "\n")
		if len(lines) != before+1 {
			t.Fatalf("pages:\n%s", pages)
		}
		if !strings.HasPrefix(lines[len(lines)-1], "*") || !strings.Contains(lines[len(lines)-1], "Page Two") {
			t.Fatalf("active marker:\n%s", pages)
		}
		if got := do(t, s, "title").Text; got != "Page Two" {
			t.Fatalf("active title %q", got)
		}
		do(t, s, "page", "0")
		if got := do(t, s, "title").Text; got != "Home Page" {
			t.Fatalf("after page 0, title %q", got)
		}
		if e := doErr(t, s, "page", "99"); e.Code != apierr.InvalidRequest {
			t.Fatalf("page 99: %+v", e)
		}
		if e := doErr(t, s, "newpage", e.base("other.example.net")+"/"); e.Code != apierr.DeniedHost {
			t.Fatalf("newpage other: %+v", e)
		}
		do(t, s, "closepage", "1")
		lines = strings.Split(strings.TrimSpace(do(t, s, "pages").Text), "\n")
		if len(lines) != before {
			t.Fatalf("after closepage: %v", lines)
		}
		if e := doErr(t, s, "closepage"); e.Code != apierr.InvalidRequest {
			t.Fatalf("close last page: %+v", e)
		}
	})

	t.Run("popup lands in our context and is intercepted", func(t *testing.T) {
		do(t, s, "open", e.base("app.example.com")+"/")
		before := len(strings.Split(strings.TrimSpace(do(t, s, "pages").Text), "\n"))
		do(t, s, "click", "#pop")
		var pages string
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			pages = do(t, s, "pages").Text
			if strings.Contains(pages, "Popup") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !strings.Contains(pages, "Popup") || len(strings.Split(strings.TrimSpace(pages), "\n")) != before+1 {
			t.Fatalf("popup not listed:\n%s", pages)
		}
		// The popup carries the seeded cookie (same context) ...
		do(t, s, "page", fmt.Sprint(before))
		do(t, s, "open", e.base("app.example.com")+"/whoami")
		if got := do(t, s, "text", "body").Text; got != "sid={cookie:sid}" {
			t.Fatalf("popup whoami = %q", got)
		}
		// ... and is subject to the navigation policy.
		if err := doErr(t, s, "open", e.base("other.example.net")+"/"); err.Code != apierr.DeniedHost {
			t.Fatalf("popup open other: %+v", err)
		}
		do(t, s, "closepage", fmt.Sprint(before))
	})

	t.Run("network events reach the recorder", func(t *testing.T) {
		h.rec.mu.Lock()
		n := h.rec.events["Network.requestWillBeSent"]
		h.rec.mu.Unlock()
		if n == 0 {
			t.Fatal("recorder got no Network events")
		}
		if h.rec.body == nil || h.rec.post == nil || h.rec.red != s.Redactor() {
			t.Fatal("recorder factory args")
		}
	})

	t.Run("verb events carry no secrets", func(t *testing.T) {
		for _, ev := range h.events("verb") {
			if strings.Contains(fmt.Sprint(ev), secretCookie) || strings.Contains(fmt.Sprint(ev), secretLS) {
				t.Fatalf("audit event leaks: %+v", ev)
			}
		}
		if len(h.events("verb")) < 10 {
			t.Fatal("verb events missing")
		}
	})

	t.Run("close deletes profile and leak assertion passes", func(t *testing.T) {
		dir := s.ProfileDir()
		if err := h.mgr.Close(context.Background(), s.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("profile still exists: %v", err)
		}
		if h.mgr.Len() != 0 {
			t.Fatal("session still registered")
		}
		if f := h.mgr.LeakFindings(); len(f) != 0 {
			t.Fatalf("unexpected leak findings: %v", f)
		}
		if len(h.events("close")) != 1 {
			t.Fatalf("close events: %v", h.events("close"))
		}
		if _, err := s.Do(context.Background(), "url", nil); err == nil {
			t.Fatal("Do on closed session succeeded")
		}
		if err := h.mgr.Close(context.Background(), s.ID); err != nil {
			t.Fatalf("second close: %v", err)
		}
	})
}

func TestWritesAllowedWithGrantAndPlantedSecretDetected(t *testing.T) {
	h := newHarness(t)
	e := h.env
	s := h.open(t, OpenSpec{Owner: "g2", Seed: SeedHoist, AllowWrites: true})
	do(t, s, "open", e.base("app.example.com")+"/")
	do(t, s, "click", "#write")
	waitText(t, s, "#out", "write status 200")
	if r, ok := e.last("app.example.com", "POST", "/api/write"); !ok || r.Body != "x=1" || !strings.Contains(r.Cookie, "sid="+secretCookie) {
		t.Fatalf("write not delivered with cookie: %+v", r)
	}
	if n := len(h.rec.blockedList()); n != 0 {
		t.Fatalf("blocked %d", n)
	}
	// Deliberately plant a secret in the profile: the assertion must notice.
	if err := os.WriteFile(filepath.Join(s.ProfileDir(), "planted.txt"), []byte("x"+secretCookie+"y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.Close(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	f := h.mgr.LeakFindings()
	if len(f) != 1 || !strings.Contains(f[0], "planted.txt") || !strings.Contains(f[0], "{cookie:sid}") || strings.Contains(f[0], secretCookie) {
		t.Fatalf("findings: %v", f)
	}
}

func TestLoginSessionRedactsMintedCookies(t *testing.T) {
	h := newHarness(t)
	e := h.env
	var loads atomic.Int32
	h.mgr.opts.Load = func(context.Context, *policy.Policy) (*creds.Credentials, error) {
		loads.Add(1)
		return nil, nil
	}
	s := h.open(t, OpenSpec{Owner: "g3", Seed: SeedLogin, LoginURL: e.base("app.example.com") + "/login"})
	if loads.Load() != 0 {
		t.Fatal("login mode must not load credentials")
	}
	if got := do(t, s, "url").Text; !strings.HasSuffix(got, "/login") {
		t.Fatalf("url = %q", got)
	}
	got := do(t, s, "text", "#c").Text
	if strings.Contains(got, loginCookie) || !strings.Contains(got, "{cookie:minted}") {
		t.Fatalf("minted cookie not redacted: %q", got)
	}
	if r, _ := e.last("app.example.com", "GET", "/login"); strings.Contains(r.Cookie, "sid=") {
		t.Fatalf("login mode sent seeded cookie: %q", r.Cookie)
	}
	if lt := do(t, s, "login").Text; !strings.Contains(lt, "interactive login") {
		t.Fatalf("login text: %q", lt)
	}
	if err := h.mgr.Close(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	if f := h.mgr.LeakFindings(); len(f) != 0 {
		t.Fatalf("leaks: %v", f)
	}
}

func TestTTLAndOwnerClose(t *testing.T) {
	h := newHarness(t)
	s1 := h.open(t, OpenSpec{Owner: "a", Seed: SeedHoist, TTL: 2 * time.Second})
	s2 := h.open(t, OpenSpec{Owner: "b", Seed: SeedHoist})
	s3 := h.open(t, OpenSpec{Owner: "b", Seed: SeedHoist})
	if l, _ := h.mgr.Latest("b"); l != s3 {
		t.Fatal("Latest should be the newest")
	}
	h.mgr.CloseOwner(context.Background(), "b")
	if _, ok := h.mgr.Get(s2.ID); ok {
		t.Fatal("owner close missed s2")
	}
	if _, err := os.Stat(s3.ProfileDir()); !os.IsNotExist(err) {
		t.Fatal("s3 profile left behind")
	}
	deadline := time.Now().Add(15 * time.Second)
	for h.mgr.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if h.mgr.Len() != 0 {
		t.Fatal("TTL did not expire the session")
	}
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s1.ProfileDir()); os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(s1.ProfileDir()); !os.IsNotExist(err) {
		t.Fatal("expired profile left behind")
	}
}

func TestBrowserDeathCleansUp(t *testing.T) {
	h := newHarness(t)
	s := h.open(t, OpenSpec{Owner: "d", Seed: SeedHoist})
	_ = s.br.Cmd.Process.Kill()
	deadline := time.Now().Add(15 * time.Second)
	for h.mgr.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if h.mgr.Len() != 0 {
		t.Fatal("dead browser session still registered")
	}
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s.ProfileDir()); os.IsNotExist(err) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(s.ProfileDir()); !os.IsNotExist(err) {
		t.Fatal("profile left behind")
	}
}

func TestOpenValidation(t *testing.T) {
	m := NewManager(Options{Test: true})
	if _, err := m.Open(context.Background(), OpenSpec{}); apierr.CodeOf(err) != apierr.InvalidRequest {
		t.Fatalf("no policies: %v", err)
	}
	p := mustPolicy(t, appPolicy)
	if _, err := m.Open(context.Background(), OpenSpec{Policies: []*policy.Policy{p}, Seed: "bogus"}); apierr.CodeOf(err) != apierr.InvalidRequest {
		t.Fatalf("bad seed: %v", err)
	}
	prod := NewManager(Options{HostMap: map[string]string{"a": "127.0.0.1"}})
	if _, err := prod.Open(context.Background(), OpenSpec{Policies: []*policy.Policy{p}, Seed: SeedLogin}); err == nil {
		t.Fatal("host_map outside test mode must be refused")
	}
}
