// Package broker is curd's fetch broker (spec section 8): it builds the
// upstream request with injected credentials, sends it, follows redirects
// only as the policy allows, applies Set-Cookie to the jar, and returns a
// filtered response.
//
// Nothing returned by this package, including errors, contains a cookie or
// localStorage value.
package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/jar"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/source"
)

const (
	maxHops        = 10
	defaultTimeout = 60 * time.Second
	defaultAccept  = "*/*"
	defaultLang    = "en-US,en;q=0.9"
)

// Options configures a Broker.
type Options struct {
	Sources   *source.Manager
	Test      bool           // test mode: honor policy.Test.HostMap, allow plain http, trust RootCAs
	RootCAs   *x509.CertPool // extra trusted roots (test mode only); nil = system
	UserAgent string         // Chrome-matching UA
	Timeout   time.Duration  // per upstream request; default 60s
	Now       func() time.Time
}

// Broker performs policy-governed fetches.
type Broker struct {
	opts Options
	tr   *http.Transport
	cl   *http.Client
}

type hostMapKey struct{}

// New returns a Broker.
func New(opts Options) *Broker {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	b := &Broker{opts: opts}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.Test && opts.RootCAs != nil {
		tlsCfg.RootCAs = opts.RootCAs
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	b.tr = &http.Transport{
		Proxy:                 nil, // never route credentials through an environment proxy
		TLSClientConfig:       tlsCfg,
		DialContext:           b.dial(dialer),
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	b.cl = &http.Client{
		Transport:     b.tr,
		Timeout:       opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return b
}

// dial rewrites hosts via the policy's test.host_map (test mode only).
func (b *Broker) dial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if b.opts.Test {
			if hm, _ := ctx.Value(hostMapKey{}).(map[string]string); len(hm) > 0 {
				if host, port, err := net.SplitHostPort(addr); err == nil {
					if to, ok := hm[strings.ToLower(host)]; ok {
						if h2, p2, err := net.SplitHostPort(to); err == nil {
							to, port = h2, p2
						}
						addr = net.JoinHostPort(to, port)
					}
				}
			}
		}
		return d.DialContext(ctx, network, addr)
	}
}

func (b *Broker) hostMap(p *policy.Policy) map[string]string {
	if !b.opts.Test || p.Test == nil || len(p.Test.HostMap) == 0 {
		return nil
	}
	m := make(map[string]string, len(p.Test.HostMap))
	for k, v := range p.Test.HostMap {
		m[strings.ToLower(k)] = v
	}
	return m
}

// Request is a fetch request.
type Request struct {
	Method, URL string
	Headers     []api.Header
	Body        []byte
}

// Response is a fetch result. Set-Cookie and the policy's stripped headers
// are removed from Headers.
type Response struct {
	Status          int
	Headers         []api.Header
	Body            []byte
	Truncated       bool
	URL             string   // final URL
	Hops            int      // redirects followed
	RedirectBlocked string   // why a redirect was not followed ("" if none)
	CookiesSent     []string // cookie names sent on the final hop
	InjectedHeaders []string // header names injected from localStorage
	Retried         bool     // credentials reloaded after 401/403 and request retried
}

// Plan is what a request would send, names only.
type Plan struct {
	Cookies        []string
	Injected       []string
	DroppedHeaders []string
	KeptHeaders    []string
}

func invalid(hint, format string, args ...any) *apierr.Error {
	return apierr.Newf(apierr.InvalidRequest, hint, format, args...)
}

// parseURL validates u for p.
func (b *Broker) parseURL(p *policy.Policy, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, invalid("pass an absolute URL such as https://"+firstHost(p)+"/path", "invalid request URL")
	}
	if u.User != nil {
		return nil, invalid("remove user:password@ from the URL; credentials come from the policy", "URL must not contain userinfo")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !b.opts.Test {
			return nil, invalid("use an https:// URL; plain http is refused", "plain http is not allowed")
		}
	default:
		return nil, invalid("use an https:// URL", "unsupported URL scheme %q", u.Scheme)
	}
	if !p.MatchesHost(u.Host) {
		return nil, apierr.Newf(apierr.DeniedHost, "policy "+p.Name+" covers: "+strings.Join(p.Match.Hosts, ", "),
			"host %q is not covered by policy %q", u.Hostname(), p.Name)
	}
	u.Fragment = ""
	return u, nil
}

func firstHost(p *policy.Policy) string {
	if len(p.Match.Hosts) > 0 {
		return strings.TrimPrefix(p.Match.Hosts[0], "*.")
	}
	return "example.com"
}

func (b *Broker) checkBody(p *policy.Policy, body []byte) error {
	max := p.Request.MaxBodyBytes
	if max <= 0 {
		max = policy.DefaultRequestMaxBody
	}
	if int64(len(body)) > max {
		return apierr.Newf(apierr.DeniedBodySize, fmt.Sprintf("send at most %d bytes (policy request.max_body_bytes)", max),
			"request body is %d bytes, over the policy limit of %d", len(body), max)
	}
	return nil
}

// prepared holds the headers for one hop.
type prepared struct {
	header   http.Header
	cookies  []string
	injected []string
}

// prepare builds upstream headers for u.
func (b *Broker) prepare(p *policy.Policy, e *source.Entry, u *url.URL, kept []api.Header) prepared {
	h := http.Header{}
	for _, kv := range kept {
		h.Add(kv.Name, kv.Value)
	}
	h.Del("Accept-Encoding") // let net/http negotiate and decompress gzip
	if b.opts.UserAgent != "" {
		h.Set("User-Agent", b.opts.UserAgent)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", defaultAccept)
	}
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", defaultLang)
	}
	var out prepared
	// localStorage-derived headers.
	for _, inj := range p.InjectRules() {
		if !originMatches(inj.Origin, u, b.opts.Test) {
			continue
		}
		for _, it := range e.LocalStorage {
			if it.Key != inj.Key || !sameOrigin(it.Origin, inj.Origin, b.opts.Test) {
				continue
			}
			v, err := inj.Render(it.Value)
			if err != nil {
				break
			}
			h.Set(inj.Header, v)
			out.injected = append(out.injected, http.CanonicalHeaderKey(inj.Header))
			break
		}
	}
	// Cookies from the jar.
	var parts []string
	var hdr string
	cs := e.Jar.CookiesFor(u, b.opts.Now())
	sel := cs[:0:0]
	for _, c := range cs {
		if p.CookieNameAllowed(c.Name) {
			sel = append(sel, c)
			parts = append(parts, c.Name)
		}
	}
	hdr = jar.CookieHeader(sel)
	if hdr != "" {
		h.Set("Cookie", hdr)
	} else {
		h.Del("Cookie")
	}
	out.cookies = parts
	out.header = h
	return out
}

func effPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// originMatches reports whether rule origin o (https://host[:port]) is the
// origin of u. In test mode the port is ignored.
func originMatches(o string, u *url.URL, test bool) bool {
	ou, err := url.Parse(o)
	if err != nil {
		return false
	}
	return urlOriginEq(ou, u, test)
}

func sameOrigin(a, b string, test bool) bool {
	au, err1 := url.Parse(a)
	bu, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return urlOriginEq(au, bu, test)
}

func urlOriginEq(a, b *url.URL, test bool) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return test || effPort(a) == effPort(b)
}

// Plan reports what Do would send for req on its first hop, names only.
func (b *Broker) Plan(ctx context.Context, p *policy.Policy, req Request) (*Plan, error) {
	u, err := b.parseURL(p, req.URL)
	if err != nil {
		return nil, err
	}
	if err := b.checkBody(p, req.Body); err != nil {
		return nil, err
	}
	e, err := b.opts.Sources.Get(ctx, p, false)
	if err != nil {
		return nil, err
	}
	kept, dropped := p.FilterRequestHeaders(req.Headers)
	pr := b.prepare(p, e, u, kept)
	plan := &Plan{Cookies: pr.cookies, Injected: pr.injected, DroppedHeaders: dropped}
	for _, kv := range kept {
		if strings.EqualFold(kv.Name, "Accept-Encoding") {
			plan.DroppedHeaders = append(plan.DroppedHeaders, kv.Name)
			continue
		}
		plan.KeptHeaders = append(plan.KeptHeaders, kv.Name)
	}
	return plan, nil
}

// Do performs the fetch. The caller has resolved the policy, checked the
// first request against it and authorized the grant.
func (b *Broker) Do(ctx context.Context, p *policy.Policy, req Request) (*Response, error) {
	u, err := b.parseURL(p, req.URL)
	if err != nil {
		return nil, err
	}
	if err := b.checkBody(p, req.Body); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	kept, _ := p.FilterRequestHeaders(req.Headers)
	if hm := b.hostMap(p); hm != nil {
		ctx = context.WithValue(ctx, hostMapKey{}, hm)
	}

	e, err := b.opts.Sources.Get(ctx, p, false)
	if err != nil {
		return nil, err
	}
	resp, err := b.run(ctx, p, e, method, u, kept, req.Body)
	if err != nil {
		return nil, err
	}
	if !authFailure(resp.Status) {
		return resp, nil
	}
	e, err = b.opts.Sources.Get(ctx, p, true)
	if err != nil {
		return nil, err
	}
	resp, err = b.run(ctx, p, e, method, u, kept, req.Body)
	if err != nil {
		return nil, err
	}
	resp.Retried = true
	if authFailure(resp.Status) {
		return nil, apierr.Newf(apierr.AuthExpired, "you may need to log into "+u.Hostname()+" in Chrome, then retry",
			"upstream answered %d even after reloading credentials", resp.Status).With("status", resp.Status)
	}
	return resp, nil
}

func authFailure(s int) bool { return s == http.StatusUnauthorized || s == http.StatusForbidden }

// run executes one full request, following redirects.
func (b *Broker) run(ctx context.Context, p *policy.Policy, e *source.Entry, method string, u *url.URL, kept []api.Header, body []byte) (*Response, error) {
	cur := u
	curKept := kept
	hops := 0
	for {
		pr := b.prepare(p, e, cur, curKept)
		var rd io.Reader
		if len(body) > 0 {
			rd = bytes.NewReader(body)
		}
		hreq, err := http.NewRequestWithContext(ctx, method, cur.String(), rd)
		if err != nil {
			return nil, invalid("check the URL and method", "cannot build request")
		}
		hreq.Header = pr.header
		hreq.Close = false
		hresp, err := b.cl.Do(hreq)
		if err != nil {
			return nil, upstreamErr(cur, err)
		}
		e.Jar.ApplySetCookie(cur, hresp.Header.Values("Set-Cookie"), b.opts.Now())

		if loc := hresp.Header.Get("Location"); loc != "" && isRedirect(hresp.StatusCode) {
			next, newMethod, newBody, why := b.nextHop(ctx, p, cur, hresp, method, body, hops)
			if why == "" {
				io.Copy(io.Discard, io.LimitReader(hresp.Body, 64<<10))
				hresp.Body.Close()
				if newBody == nil && len(body) > 0 {
					curKept = dropHeader(curKept, "Content-Type")
				}
				cur, method, body = next, newMethod, newBody
				hops++
				continue
			}
			out, err := b.finish(p, cur, hresp, pr, hops)
			if err != nil {
				return nil, err
			}
			out.RedirectBlocked = why
			return out, nil
		}
		return b.finish(p, cur, hresp, pr, hops)
	}
}

func dropHeader(hs []api.Header, name string) []api.Header {
	out := make([]api.Header, 0, len(hs))
	for _, h := range hs {
		if !strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}

func isRedirect(s int) bool {
	switch s {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// nextHop decides whether to follow a redirect. A non-empty why means it is
// blocked.
func (b *Broker) nextHop(ctx context.Context, p *policy.Policy, cur *url.URL, resp *http.Response, method string, body []byte, hops int) (next *url.URL, newMethod string, newBody []byte, why string) {
	if p.Redirects == policy.RedirectsNone {
		return nil, "", nil, "policy redirects: none"
	}
	if hops >= maxHops {
		return nil, "", nil, fmt.Sprintf("more than %d redirects", maxHops)
	}
	ref, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, "", nil, "invalid Location header"
	}
	next = cur.ResolveReference(ref)
	next.Fragment = ""
	if next.User != nil {
		return nil, "", nil, "redirect target contains userinfo"
	}
	if next.Scheme != "https" && !(next.Scheme == "http" && b.opts.Test) {
		return nil, "", nil, fmt.Sprintf("redirect to %s scheme is not allowed", next.Scheme)
	}
	switch p.Redirects {
	case policy.RedirectsSameHost:
		if !strings.EqualFold(next.Hostname(), cur.Hostname()) || next.Scheme != cur.Scheme || effPort(next) != effPort(cur) {
			return nil, "", nil, fmt.Sprintf("redirect to %s is not same-host (policy redirects: same-host-only)", next.Host)
		}
	case policy.RedirectsPolicy:
		if !p.MatchesHost(next.Host) {
			return nil, "", nil, fmt.Sprintf("redirect to %s is not a host of policy %s", next.Hostname(), p.Name)
		}
	default:
		return nil, "", nil, "unknown redirect mode"
	}
	newMethod, newBody = method, body
	switch resp.StatusCode {
	case 303:
		if method != http.MethodHead {
			newMethod = http.MethodGet
		}
		newBody = nil
	case 301, 302:
		if method != http.MethodGet && method != http.MethodHead {
			newMethod = http.MethodGet
			newBody = nil
		}
	}
	d := p.Check(ctx, policy.CheckRequest{Method: newMethod, URL: next, Body: newBody})
	if !d.Allowed {
		return nil, "", nil, fmt.Sprintf("policy denies redirect target (%s): %s", d.Code, d.Reason)
	}
	return next, newMethod, newBody, ""
}

// finish converts an upstream response into a Response.
func (b *Broker) finish(p *policy.Policy, cur *url.URL, hresp *http.Response, pr prepared, hops int) (*Response, error) {
	defer hresp.Body.Close()
	max := p.Response.MaxBodyBytes
	if max <= 0 {
		max = policy.DefaultResponseMaxBody
	}
	data, err := io.ReadAll(io.LimitReader(hresp.Body, max+1))
	if err != nil {
		return nil, upstreamErr(cur, err)
	}
	out := &Response{
		Status: hresp.StatusCode, URL: cur.String(), Hops: hops,
		CookiesSent: pr.cookies, InjectedHeaders: pr.injected,
	}
	if int64(len(data)) > max {
		data = data[:max]
		out.Truncated = true
	}
	out.Body = p.Redact(data)

	names := make([]string, 0, len(hresp.Header))
	for n := range hresp.Header {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		lower := strings.ToLower(n)
		// The body may have been decoded, truncated or redacted, so its
		// framing headers no longer describe it.
		if p.StripsResponseHeader(n) || lower == "content-length" || lower == "transfer-encoding" || lower == "connection" || lower == "keep-alive" {
			continue
		}
		for _, v := range hresp.Header[n] {
			out.Headers = append(out.Headers, api.Header{Name: n, Value: v})
		}
	}
	return out, nil
}

// upstreamErr maps a transport error to an UpstreamError without echoing the
// URL (net/http's url.Error includes it, query string and all).
func upstreamErr(u *url.URL, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	hint := "check the host is reachable and retry"
	var to interface{ Timeout() bool }
	if errors.As(err, &to) && to.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		hint = "the upstream timed out; retry later"
	}
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var hn x509.HostnameError
	if errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &hn) {
		hint = "the upstream TLS certificate was not trusted"
	}
	return apierr.Newf(apierr.UpstreamError, hint, "request to %s failed: %v", u.Host, err)
}
