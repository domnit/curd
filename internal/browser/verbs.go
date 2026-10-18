package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
)

const (
	maxOutput      = 256 << 10 // cap for text/html output
	jsFetchCap     = 8 << 20   // cap inside the page, before redaction
	navTimeout     = 30 * time.Second
	waitTimeout    = 30 * time.Second
	defaultQuietMS = 500
)

type verbInfo struct{ name, usage, desc string }

var verbList = []verbInfo{
	{"open", "open <url>", "navigate the active page to a policy-host URL and wait for load"},
	{"back", "back", "go back in history"},
	{"forward", "forward", "go forward in history"},
	{"reload", "reload", "reload the page"},
	{"url", "url", "print the current URL"},
	{"title", "title", "print the page title"},
	{"text", "text <selector>", "print the visible text of the first element matching a CSS selector"},
	{"html", "html <selector>", "print the outer HTML of the first element matching a CSS selector"},
	{"exists", "exists <selector>", "print true/false: does the selector match an element"},
	{"visible", "visible <selector>", "print true/false: is the element rendered and visible"},
	{"click", "click <selector>", "scroll the element into view and click its center"},
	{"type", "type <selector> <text>", "focus the element and insert text"},
	{"focus", "focus <selector>", "focus the element"},
	{"waitstable", "waitstable [ms]", "wait until the DOM has not changed for ms (default 500; max wait 30s)"},
	{"waitidle", "waitidle [ms]", "wait until no network requests are in flight for ms (default 500; max wait 30s)"},
	{"screenshot", "screenshot", "capture a PNG of the viewport"},
	{"pages", "pages", "list open pages (the active one is marked *)"},
	{"newpage", "newpage [url]", "open a new page and make it active"},
	{"closepage", "closepage [index]", "close a page (default: the active one)"},
	{"page", "page <index>", "make a page active"},
	{"login", "login", "show login state and instructions (login-mode sessions)"},
	{"capture", "capture <subcommand>", "use `curd browse capture ...` (handled by the daemon)"},
	{"help", "help", "list the verbs"},
}

func verbNames() string {
	var n []string
	for _, v := range verbList {
		n = append(n, v.name)
	}
	return strings.Join(n, ", ")
}

// Do runs one browse verb. It is the only way an agent reaches the browser.
// Output is redacted before it is returned.
func (s *Session) Do(ctx context.Context, verb string, args []string) (*api.BrowseResult, error) {
	s.verbMu.Lock()
	defer s.verbMu.Unlock()
	if s.isClosed() {
		return nil, errSessionClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()

	res, err := s.dispatch(ctx, strings.ToLower(verb), args)
	if s.isClosed() && err != nil {
		err = errSessionClosed
	}
	s.refreshRedactor(ctx) // login mode: learn cookies minted by this verb before redacting its output

	if res != nil {
		res.Text = s.red.String(res.Text)
		if res.Data != nil {
			res.Data = s.redactData(res.Data)
		}
	}
	var out error
	if err != nil {
		e := apierr.As(err)
		c := *e
		c.Message = s.red.String(e.Message)
		c.Hint = s.red.String(e.Hint)
		out = &c
	}
	ev := SessionEvent{Type: "verb", Verb: strings.ToLower(verb), Error: apierr.CodeOf(err)}
	if len(args) > 0 {
		ev.Detail = s.red.String(args[0])
	}
	s.emit(ev)
	return res, out
}

func (s *Session) redactData(d any) any {
	b, err := json.Marshal(d)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal([]byte(s.red.String(string(b))), &v) != nil {
		// Redaction broke the JSON (a secret inside an escape): fall back to
		// redacting the escaped text as a string.
		return s.red.String(string(b))
	}
	return v
}

func usage(verb string) error {
	for _, v := range verbList {
		if v.name == verb {
			return apierr.Newf(apierr.InvalidRequest, "usage: "+v.usage, "wrong arguments for %q", verb)
		}
	}
	return nil
}

func (s *Session) dispatch(ctx context.Context, verb string, args []string) (*api.BrowseResult, error) {
	switch verb {
	case "help":
		var b strings.Builder
		for _, v := range verbList {
			fmt.Fprintf(&b, "%-24s %s\n", v.usage, v.desc)
		}
		return &api.BrowseResult{Text: b.String()}, nil
	case "js":
		return nil, apierr.New(apierr.NotAvailable, "the js verb is gated and deferred: it needs an explicit js grant and is refused on credentialed origins",
			"use the structured verbs (text, html, exists, visible, click, type, waitstable); for page data prefer `curd browse capture ...`")
	case "capture":
		return nil, apierr.New(apierr.InvalidRequest, "capture is not a page verb", "use `curd browse capture ...` — handled by the daemon")
	case "open":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		return s.vOpen(ctx, args[0])
	case "back", "forward":
		return s.vHistory(ctx, verb)
	case "reload":
		return s.vReload(ctx)
	case "url", "title":
		pg, err := s.activePage()
		if err != nil {
			return nil, err
		}
		u, t, err := s.pageInfo(ctx, pg)
		if err != nil {
			return nil, err
		}
		if verb == "url" {
			return &api.BrowseResult{Text: u, Data: map[string]string{"url": u}}, nil
		}
		return &api.BrowseResult{Text: t, Data: map[string]string{"title": t}}, nil
	case "text", "html":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		return s.vContent(ctx, verb, args[0])
	case "exists", "visible":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		fn := jsExists
		if verb == "visible" {
			fn = jsVisible
		}
		var r struct {
			Err string `json:"err"`
			V   bool   `json:"v"`
		}
		if err := s.domEval(ctx, fn, []any{args[0]}, false, &r); err != nil {
			return nil, err
		}
		if err := selErr(r.Err, args[0]); err != nil {
			return nil, err
		}
		return &api.BrowseResult{Text: strconv.FormatBool(r.V), Data: map[string]bool{verb: r.V}}, nil
	case "click":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		return s.vClick(ctx, args[0])
	case "focus":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		if err := s.focus(ctx, args[0]); err != nil {
			return nil, err
		}
		return &api.BrowseResult{Text: "focused " + args[0]}, nil
	case "type":
		if len(args) < 2 {
			return nil, usage(verb)
		}
		text := strings.Join(args[1:], " ")
		if err := s.focus(ctx, args[0]); err != nil {
			return nil, err
		}
		pg, err := s.activePage()
		if err != nil {
			return nil, err
		}
		if err := s.call(ctx, pg.sid, "Input.insertText", map[string]any{"text": text}, nil); err != nil {
			return nil, browserErr("type: %v", err)
		}
		return &api.BrowseResult{Text: fmt.Sprintf("typed %d characters into %s", utf8.RuneCountInString(text), args[0])}, nil
	case "waitstable":
		ms, err := msArg(verb, args, defaultQuietMS)
		if err != nil {
			return nil, err
		}
		var r struct {
			Timeout bool `json:"timeout"`
		}
		if err := s.domEval(ctx, jsWaitStable, []any{ms, waitTimeout.Milliseconds()}, true, &r); err != nil {
			return nil, err
		}
		if r.Timeout {
			return nil, apierr.Newf(apierr.BrowserError, "the page keeps changing; use waitidle, or check for a spinner or animation", "page not stable after %s", waitTimeout)
		}
		return &api.BrowseResult{Text: fmt.Sprintf("stable (no DOM changes for %dms)", ms)}, nil
	case "waitidle":
		ms, err := msArg(verb, args, defaultQuietMS)
		if err != nil {
			return nil, err
		}
		return s.vWaitIdle(ctx, time.Duration(ms)*time.Millisecond)
	case "screenshot":
		pg, err := s.activePage()
		if err != nil {
			return nil, err
		}
		var r struct {
			Data string `json:"data"`
		}
		if err := s.call(ctx, pg.sid, "Page.captureScreenshot", map[string]any{"format": "png"}, &r); err != nil {
			return nil, browserErr("screenshot: %v", err)
		}
		png, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, browserErr("screenshot: %v", err)
		}
		return &api.BrowseResult{Text: fmt.Sprintf("screenshot: %d bytes PNG (pixels are not redacted)", len(png)), PNG: png}, nil
	case "pages":
		return s.vPages(ctx)
	case "newpage":
		if len(args) > 1 {
			return nil, usage(verb)
		}
		return s.vNewPage(ctx, args)
	case "closepage":
		if len(args) > 1 {
			return nil, usage(verb)
		}
		return s.vClosePage(ctx, args)
	case "page":
		if len(args) != 1 {
			return nil, usage(verb)
		}
		return s.vSwitchPage(ctx, args[0])
	case "login":
		return s.vLogin(ctx)
	}
	return nil, apierr.Newf(apierr.InvalidRequest, "verbs: "+verbNames(), "unknown browse verb %q", verb)
}

func msArg(verb string, args []string, def int64) (int64, error) {
	if len(args) == 0 {
		return def, nil
	}
	if len(args) > 1 {
		return 0, usage(verb)
	}
	n, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || n < 0 || n > 60000 {
		return 0, apierr.Newf(apierr.InvalidRequest, "usage: "+verb+" [ms] with 0 <= ms <= 60000", "invalid duration %q", args[0])
	}
	return n, nil
}

func selErr(code, sel string) error {
	switch code {
	case "":
		return nil
	case "nomatch":
		return apierr.Newf(apierr.NotFound, "check the selector with `exists`; after navigation or clicks try `waitstable` first", "no element matches selector %q", sel)
	case "invalid":
		return apierr.Newf(apierr.InvalidRequest, "use a valid CSS selector such as #id, .class or button[type=submit]", "invalid CSS selector %q", sel)
	case "hidden":
		return apierr.Newf(apierr.BrowserError, "wait for it with `waitstable`, or pick a visible element (see `visible`)", "element %q has no size (hidden)", sel)
	case "notfocusable":
		return apierr.Newf(apierr.BrowserError, "pick an input, textarea or other focusable element", "element %q cannot take focus", sel)
	}
	return browserErr("unexpected result %q for selector %q", code, sel)
}

// ---------------------------------------------------------------- pages

func (s *Session) activePage() (*page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, apierr.New(apierr.BrowserError, "there is no active page", "open one with `newpage [url]`")
	}
	return s.active, nil
}

func (s *Session) pageInfo(ctx context.Context, pg *page) (string, string, error) {
	var r struct {
		TargetInfo targetInfo `json:"targetInfo"`
	}
	if err := s.call(ctx, "", "Target.getTargetInfo", map[string]any{"targetId": pg.targetID}, &r); err != nil {
		return "", "", browserErr("page info: %v", err)
	}
	return r.TargetInfo.URL, r.TargetInfo.Title, nil
}

func (s *Session) vPages(ctx context.Context) (*api.BrowseResult, error) {
	var res struct {
		TargetInfos []targetInfo `json:"targetInfos"`
	}
	if err := s.call(ctx, "", "Target.getTargets", nil, &res); err != nil {
		return nil, browserErr("list pages: %v", err)
	}
	info := map[string]targetInfo{}
	for _, ti := range res.TargetInfos {
		info[ti.TargetID] = ti
	}
	s.mu.Lock()
	pages := append([]*page(nil), s.pages...)
	active := s.active
	s.mu.Unlock()
	type row struct {
		Index  int    `json:"index"`
		URL    string `json:"url"`
		Title  string `json:"title"`
		Active bool   `json:"active"`
	}
	var rows []row
	var b strings.Builder
	for i, pg := range pages {
		ti := info[pg.targetID]
		r := row{Index: i, URL: ti.URL, Title: ti.Title, Active: pg == active}
		rows = append(rows, r)
		mark := " "
		if r.Active {
			mark = "*"
		}
		fmt.Fprintf(&b, "%s %d %s %q\n", mark, i, r.URL, r.Title)
	}
	return &api.BrowseResult{Text: b.String(), Data: rows}, nil
}

func (s *Session) pageAt(arg string) (*page, int, error) {
	n, err := strconv.Atoi(arg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || n < 0 || n >= len(s.pages) {
		return nil, 0, apierr.Newf(apierr.InvalidRequest, "list pages with `pages`", "no page with index %q (there are %d pages)", arg, len(s.pages))
	}
	return s.pages[n], n, nil
}

func (s *Session) vSwitchPage(ctx context.Context, arg string) (*api.BrowseResult, error) {
	pg, n, err := s.pageAt(arg)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.active = pg
	s.mu.Unlock()
	_ = s.call(ctx, "", "Target.activateTarget", map[string]any{"targetId": pg.targetID}, nil)
	u, _, _ := s.pageInfo(ctx, pg)
	return &api.BrowseResult{Text: fmt.Sprintf("active page %d: %s", n, u)}, nil
}

func (s *Session) vNewPage(ctx context.Context, args []string) (*api.BrowseResult, error) {
	var target string
	if len(args) == 1 {
		u, err := parseOpenURL(args[0])
		if err != nil {
			return nil, err
		}
		if err := s.checkNavigable(u); err != nil {
			return nil, err
		}
		target = u.String()
	}
	pg, err := s.createPage(ctx, "about:blank")
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.active = pg
	n := len(s.pages) - 1
	for i, p := range s.pages {
		if p == pg {
			n = i
		}
	}
	s.mu.Unlock()
	_ = s.call(ctx, "", "Target.activateTarget", map[string]any{"targetId": pg.targetID}, nil)
	if target != "" {
		if err := s.navigate(ctx, pg, target); err != nil {
			return nil, err
		}
	}
	u, _, _ := s.pageInfo(ctx, pg)
	return &api.BrowseResult{Text: fmt.Sprintf("page %d: %s", n, u), Data: map[string]any{"index": n, "url": u}}, nil
}

func (s *Session) vClosePage(ctx context.Context, args []string) (*api.BrowseResult, error) {
	var pg *page
	var n int
	if len(args) == 1 {
		var err error
		if pg, n, err = s.pageAt(args[0]); err != nil {
			return nil, err
		}
	} else {
		var err error
		if pg, err = s.activePage(); err != nil {
			return nil, err
		}
		s.mu.Lock()
		for i, p := range s.pages {
			if p == pg {
				n = i
			}
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	count := len(s.pages)
	s.mu.Unlock()
	if count <= 1 {
		return nil, apierr.New(apierr.InvalidRequest, "cannot close the last page", "open another with `newpage`, or close the whole session")
	}
	if err := s.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": pg.targetID}, nil); err != nil {
		return nil, browserErr("close page: %v", err)
	}
	s.waitFor(ctx, 5*time.Second, func() bool {
		for _, p := range s.pages {
			if p == pg {
				return false
			}
		}
		return true
	})
	return &api.BrowseResult{Text: fmt.Sprintf("closed page %d", n)}, nil
}

func (s *Session) vLogin(ctx context.Context) (*api.BrowseResult, error) {
	var b strings.Builder
	if s.Seed == SeedLogin {
		fmt.Fprintf(&b, "interactive login session (nothing was seeded)\nlogin page: %s\n", s.startURL)
		b.WriteString("sign in in the browser window, then continue with `url`, `title`, `text <selector>`.\n")
		b.WriteString("a human must complete any password, 2FA or captcha step; curd does not see or store what they type.\n")
	} else {
		b.WriteString("credential-seeded session: logged in from the credential sources; no interactive login is needed.\n")
	}
	if pg, err := s.activePage(); err == nil {
		if u, t, err := s.pageInfo(ctx, pg); err == nil {
			fmt.Fprintf(&b, "current page: %s (%s)\n", u, t)
		}
	}
	fmt.Fprintf(&b, "policy hosts: %s\n", strings.Join(s.PolicyHosts(), ", "))
	return &api.BrowseResult{Text: b.String(), Data: map[string]any{"seed": s.Seed, "login_url": s.startURL, "policy_hosts": s.PolicyHosts()}}, nil
}

// ---------------------------------------------------------------- navigation

func parseOpenURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil, apierr.Newf(apierr.InvalidRequest, "pass an absolute URL such as https://app.example.com/path", "invalid URL %q", raw)
	}
	return u, nil
}

// navigate loads rawurl in pg and waits for the load event. A navigation
// that curd blocks (directly or through a redirect) returns the denial.
func (s *Session) navigate(ctx context.Context, pg *page, rawurl string) error {
	u, err := parseOpenURL(rawurl)
	if err != nil {
		return err
	}
	if err := s.checkNavigable(u); err != nil {
		return err
	}
	s.mu.Lock()
	seq := s.blockSeq
	s.mu.Unlock()
	var res struct {
		LoaderID  string `json:"loaderId"`
		ErrorText string `json:"errorText"`
	}
	if err := s.call(ctx, pg.sid, "Page.navigate", map[string]any{"url": u.String()}, &res); err != nil {
		return browserErr("navigate: %v", err)
	}
	blocked := func() *apierr.Error {
		if pg.block != nil && pg.block.seq > seq {
			return pg.block.err
		}
		return nil
	}
	if res.ErrorText != "" {
		s.mu.Lock()
		be := blocked()
		s.mu.Unlock()
		if be != nil {
			return be
		}
		return browserErr("navigation failed: %s", res.ErrorText)
	}
	if res.LoaderID == "" {
		return nil // same-document navigation
	}
	ok := s.waitFor(ctx, navTimeout, func() bool { return pg.loaded[res.LoaderID] || blocked() != nil })
	s.mu.Lock()
	be := blocked()
	s.mu.Unlock()
	if be != nil {
		return be
	}
	if !ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return apierr.Newf(apierr.BrowserError, "try `waitidle` or `waitstable`; the page may still be usable", "page did not finish loading in %s", navTimeout)
	}
	return nil
}

func (s *Session) navResult(ctx context.Context, pg *page, prefix string) (*api.BrowseResult, error) {
	u, t, err := s.pageInfo(ctx, pg)
	if err != nil {
		return nil, err
	}
	return &api.BrowseResult{Text: prefix + u + "\ntitle: " + t, Data: map[string]string{"url": u, "title": t}}, nil
}

func (s *Session) vOpen(ctx context.Context, raw string) (*api.BrowseResult, error) {
	pg, err := s.activePage()
	if err != nil {
		return nil, err
	}
	if err := s.navigate(ctx, pg, raw); err != nil {
		return nil, err
	}
	return s.navResult(ctx, pg, "")
}

// waitNav waits for a history/reload navigation to finish.
func (s *Session) waitNav(ctx context.Context, pg *page, tick0, seq0 int) error {
	blocked := func() *apierr.Error {
		if pg.block != nil && pg.block.seq > seq0 {
			return pg.block.err
		}
		return nil
	}
	ok := s.waitFor(ctx, navTimeout, func() bool { return pg.navTick > tick0 || blocked() != nil })
	s.mu.Lock()
	be := blocked()
	s.mu.Unlock()
	if be != nil {
		return be
	}
	if !ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return apierr.Newf(apierr.BrowserError, "try `waitidle`", "page did not finish loading in %s", navTimeout)
	}
	return nil
}

func (s *Session) snapshotNav(pg *page) (tick, seq int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return pg.navTick, s.blockSeq
}

func (s *Session) vHistory(ctx context.Context, dir string) (*api.BrowseResult, error) {
	pg, err := s.activePage()
	if err != nil {
		return nil, err
	}
	var h struct {
		CurrentIndex int `json:"currentIndex"`
		Entries      []struct {
			ID int `json:"id"`
		} `json:"entries"`
	}
	if err := s.call(ctx, pg.sid, "Page.getNavigationHistory", nil, &h); err != nil {
		return nil, browserErr("history: %v", err)
	}
	idx := h.CurrentIndex - 1
	if dir == "forward" {
		idx = h.CurrentIndex + 1
	}
	if idx < 0 || idx >= len(h.Entries) {
		return nil, apierr.Newf(apierr.InvalidRequest, "use `open <url>` or `pages`", "no %s history entry", map[string]string{"back": "previous", "forward": "next"}[dir])
	}
	tick, seq := s.snapshotNav(pg)
	if err := s.call(ctx, pg.sid, "Page.navigateToHistoryEntry", map[string]any{"entryId": h.Entries[idx].ID}, nil); err != nil {
		return nil, browserErr("%s: %v", dir, err)
	}
	if err := s.waitNav(ctx, pg, tick, seq); err != nil {
		return nil, err
	}
	return s.navResult(ctx, pg, "")
}

func (s *Session) vReload(ctx context.Context) (*api.BrowseResult, error) {
	pg, err := s.activePage()
	if err != nil {
		return nil, err
	}
	tick, seq := s.snapshotNav(pg)
	if err := s.call(ctx, pg.sid, "Page.reload", nil, nil); err != nil {
		return nil, browserErr("reload: %v", err)
	}
	if err := s.waitNav(ctx, pg, tick, seq); err != nil {
		return nil, err
	}
	return s.navResult(ctx, pg, "")
}

func (s *Session) vWaitIdle(ctx context.Context, quiet time.Duration) (*api.BrowseResult, error) {
	deadline := time.Now().Add(waitTimeout)
	var idleSince time.Time
	for {
		s.mu.Lock()
		n := len(s.inflight)
		s.mu.Unlock()
		now := time.Now()
		if n == 0 {
			if idleSince.IsZero() {
				idleSince = now
			}
			if now.Sub(idleSince) >= quiet {
				return &api.BrowseResult{Text: fmt.Sprintf("idle (no requests in flight for %s)", quiet)}, nil
			}
		} else {
			idleSince = time.Time{}
		}
		if now.After(deadline) {
			return nil, apierr.Newf(apierr.BrowserError, "the page may be polling; use waitstable or proceed", "network not idle after %s (%d requests in flight)", waitTimeout, n)
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ---------------------------------------------------------------- DOM verbs

func (s *Session) isoContext(ctx context.Context, pg *page, force bool) (int64, error) {
	s.mu.Lock()
	id := pg.isoCtx
	s.mu.Unlock()
	if id != 0 && !force {
		return id, nil
	}
	var r struct {
		ExecutionContextID int64 `json:"executionContextId"`
	}
	if err := s.call(ctx, pg.sid, "Page.createIsolatedWorld", map[string]any{"frameId": pg.targetID, "worldName": "curd", "grantUniveralAccess": false}, &r); err != nil {
		return 0, browserErr("create isolated world: %v", err)
	}
	s.mu.Lock()
	pg.isoCtx = r.ExecutionContextID
	s.mu.Unlock()
	return r.ExecutionContextID, nil
}

// domEval runs one of the fixed functions in js.go in the active page's
// isolated world. args are passed as JSON values, never as source text.
func (s *Session) domEval(ctx context.Context, fn string, args []any, await bool, out any) error {
	pg, err := s.activePage()
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		id, err := s.isoContext(ctx, pg, attempt > 0)
		if err != nil {
			last = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		cargs := make([]map[string]any, len(args))
		for i, a := range args {
			cargs[i] = map[string]any{"value": a}
		}
		var res struct {
			Result struct {
				Value json.RawMessage `json:"value"`
			} `json:"result"`
			ExceptionDetails *struct {
				Text      string `json:"text"`
				Exception struct {
					Description string `json:"description"`
				} `json:"exception"`
			} `json:"exceptionDetails"`
		}
		err = s.call(ctx, pg.sid, "Runtime.callFunctionOn", map[string]any{
			"functionDeclaration": fn,
			"executionContextId":  id,
			"arguments":           cargs,
			"returnByValue":       true,
			"awaitPromise":        await,
		}, &res)
		if err != nil {
			var ce *cdp.Error
			if asCDP(err, &ce) {
				m := strings.ToLower(ce.Message)
				if strings.Contains(m, "context") {
					last = err
					continue
				}
			}
			return browserErr("page script: %v", err)
		}
		if res.ExceptionDetails != nil {
			d := res.ExceptionDetails.Exception.Description
			if d == "" {
				d = res.ExceptionDetails.Text
			}
			return browserErr("page script error: %s", d)
		}
		if out != nil && len(res.Result.Value) > 0 {
			if err := json.Unmarshal(res.Result.Value, out); err != nil {
				return browserErr("decode page script result: %v", err)
			}
		}
		return nil
	}
	return browserErr("page changed while running the verb (retry after `waitstable`): %v", last)
}

func asCDP(err error, target **cdp.Error) bool {
	for err != nil {
		if e, ok := err.(*cdp.Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (s *Session) vContent(ctx context.Context, verb, sel string) (*api.BrowseResult, error) {
	fn := jsText
	if verb == "html" {
		fn = jsHTML
	}
	var r struct {
		Err string `json:"err"`
		V   string `json:"v"`
		N   int    `json:"n"`
	}
	if err := s.domEval(ctx, fn, []any{sel, jsFetchCap}, false, &r); err != nil {
		return nil, err
	}
	if err := selErr(r.Err, sel); err != nil {
		return nil, err
	}
	s.refreshRedactor(ctx)
	out := s.red.String(r.V)
	truncated := r.N > len(r.V) && len(r.V) < r.N
	if len(out) > maxOutput {
		cut := maxOutput
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
		truncated = true
	}
	if truncated {
		out += fmt.Sprintf("\n[truncated: output capped at %d KiB]", maxOutput>>10)
	}
	return &api.BrowseResult{Text: out}, nil
}

func (s *Session) focus(ctx context.Context, sel string) error {
	var r struct {
		Err string `json:"err"`
	}
	if err := s.domEval(ctx, jsFocus, []any{sel}, false, &r); err != nil {
		return err
	}
	return selErr(r.Err, sel)
}

func (s *Session) vClick(ctx context.Context, sel string) (*api.BrowseResult, error) {
	var r struct {
		Err     string  `json:"err"`
		X       float64 `json:"x"`
		Y       float64 `json:"y"`
		Covered bool    `json:"covered"`
	}
	if err := s.domEval(ctx, jsClickPoint, []any{sel}, false, &r); err != nil {
		return nil, err
	}
	if err := selErr(r.Err, sel); err != nil {
		return nil, err
	}
	pg, err := s.activePage()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	seq := s.blockSeq
	s.mu.Unlock()
	mouse := func(typ string, clicks int) error {
		return s.call(ctx, pg.sid, "Input.dispatchMouseEvent", map[string]any{
			"type": typ, "x": r.X, "y": r.Y, "button": "left", "clickCount": clicks,
		}, nil)
	}
	if err := s.call(ctx, pg.sid, "Input.dispatchMouseEvent", map[string]any{"type": "mouseMoved", "x": r.X, "y": r.Y}, nil); err != nil {
		return nil, browserErr("click: %v", err)
	}
	if err := mouse("mousePressed", 1); err != nil {
		return nil, browserErr("click: %v", err)
	}
	if err := mouse("mouseReleased", 1); err != nil {
		return nil, browserErr("click: %v", err)
	}
	// Let a triggered navigation start, then wait for it to settle.
	select {
	case <-time.After(150 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.waitFor(ctx, navTimeout, func() bool { return !pg.loading })
	s.mu.Lock()
	var blocked *blockRec
	if s.lastDocBlock != nil && s.lastDocBlock.seq > seq {
		blocked = s.lastDocBlock
	}
	s.mu.Unlock()
	if blocked != nil {
		return nil, blocked.err
	}
	msg := "clicked " + sel
	if r.Covered {
		msg += " (another element covers its center; the click may have hit that instead)"
	}
	return &api.BrowseResult{Text: msg}, nil
}
