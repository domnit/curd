// Package jar is curd's in-memory cookie jar (spec 5.4, section 8 steps 4
// and 7). It layers cookies learned from Set-Cookie responses (the overlay)
// over cookies loaded from a credential source (the base).
//
// Cookie values are secrets: they are never included in errors.
package jar

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/creds"
)

type key struct{ name, domain, path string }

func keyOf(c creds.Cookie) key {
	return key{c.Name, strings.ToLower(c.Domain), c.Path}
}

// Jar is safe for concurrent use.
type Jar struct {
	mu      sync.Mutex
	base    map[key]creds.Cookie
	overlay map[key]creds.Cookie
	// seq orders cookies of equal path length by creation time.
	seq     uint64
	created map[key]uint64
	// deleted records overlay deletions (expired Set-Cookie) so they mask
	// base cookies that are not newer.
	deleted map[key]time.Time
}

// New returns an empty jar.
func New() *Jar {
	return &Jar{
		base:    map[key]creds.Cookie{},
		overlay: map[key]creds.Cookie{},
		created: map[key]uint64{},
		deleted: map[key]time.Time{},
	}
}

// SetBase replaces the disk-loaded cookies. Overlay entries survive unless
// the new base copy of the same (name, domain, path) has a newer LastUpdate.
func (j *Jar) SetBase(cookies []creds.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.base = make(map[key]creds.Cookie, len(cookies))
	for _, c := range cookies {
		if c.Path == "" {
			c.Path = "/"
		}
		k := keyOf(c)
		j.base[k] = c
		if _, ok := j.created[k]; !ok {
			j.seq++
			j.created[k] = j.seq
		}
		if o, ok := j.overlay[k]; ok && c.LastUpdate.After(o.LastUpdate) {
			delete(j.overlay, k)
		}
		if t, ok := j.deleted[k]; ok && c.LastUpdate.After(t) {
			delete(j.deleted, k)
		}
	}
}

// ApplySetCookie processes the Set-Cookie header values of a response from u
// (RFC 6265 section 5.3). Invalid or foreign-domain cookies are ignored.
func (j *Jar) ApplySetCookie(u *url.URL, setCookie []string, now time.Time) {
	host := canonHost(u.Hostname())
	if host == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, line := range setCookie {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name == "" {
			continue
		}
		var domain string
		if d := strings.ToLower(strings.TrimPrefix(c.Domain, ".")); d != "" {
			switch {
			case net.ParseIP(host) != nil:
				// IP hosts only ever produce host-only cookies.
				if d != host {
					continue
				}
				domain = host
			case validDomainAttr(d, host):
				domain = "." + d
			default:
				continue
			}
		} else {
			domain = host
		}
		p := c.Path
		if p == "" || p[0] != '/' {
			p = defaultPath(u.Path)
		}
		out := creds.Cookie{
			Name: c.Name, Value: c.Value, Domain: domain, Path: p,
			Secure: c.Secure && u.Scheme == "https", HTTPOnly: c.HttpOnly,
			LastUpdate: now,
		}
		if c.Secure && u.Scheme != "https" {
			continue // RFC 6265bis: insecure origins may not set Secure cookies
		}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			out.SameSite = "lax"
		case http.SameSiteStrictMode:
			out.SameSite = "strict"
		case http.SameSiteNoneMode:
			out.SameSite = "none"
		}
		expired := false
		switch {
		case c.MaxAge < 0:
			expired = true
		case c.MaxAge > 0:
			out.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		case !c.Expires.IsZero():
			out.Expires = c.Expires
			expired = !c.Expires.After(now)
		}
		k := keyOf(out)
		if expired {
			delete(j.overlay, k)
			j.deleted[k] = now
			continue
		}
		delete(j.deleted, k)
		if _, ok := j.created[k]; !ok {
			j.seq++
			j.created[k] = j.seq
		}
		j.overlay[k] = out
	}
}

// validDomainAttr reports whether a Domain attribute d (lowercase, no leading
// dot) may be set by a response from host.
func validDomainAttr(d, host string) bool {
	if !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return false // single label ("com") or IP literal
	}
	return host == d || strings.HasSuffix(host, "."+d)
}

// defaultPath implements RFC 6265 section 5.1.4.
func defaultPath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	i := strings.LastIndexByte(p, '/')
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func canonHost(h string) string { return strings.ToLower(strings.TrimSuffix(h, ".")) }

func domainMatches(c creds.Cookie, host string) bool {
	d := strings.ToLower(c.Domain)
	if c.HostOnly() {
		return host == d
	}
	d = d[1:]
	return host == d || (strings.HasSuffix(host, "."+d) && net.ParseIP(host) == nil)
}

func pathMatches(cookiePath, reqPath string) bool {
	if reqPath == "" {
		reqPath = "/"
	}
	if cookiePath == "" {
		cookiePath = "/"
	}
	if reqPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || reqPath[len(cookiePath)] == '/'
}

// CookiesFor returns the cookies to send to u (RFC 6265 section 5.4):
// domain-, path- and Secure-matching, unexpired, ordered by longer path first
// then earlier creation. Overlay cookies take precedence over base cookies
// for the same (name, domain, path).
func (j *Jar) CookiesFor(u *url.URL, now time.Time) []creds.Cookie {
	host := canonHost(u.Hostname())
	https := u.Scheme == "https"
	j.mu.Lock()
	defer j.mu.Unlock()

	type item struct {
		c   creds.Cookie
		seq uint64
	}
	var items []item
	consider := func(k key, c creds.Cookie) {
		if !domainMatches(c, host) || !pathMatches(c.Path, u.Path) {
			return
		}
		if c.Secure && !https {
			return
		}
		if !c.Expires.IsZero() && !c.Expires.After(now) {
			return
		}
		items = append(items, item{c, j.created[k]})
	}
	for k, c := range j.overlay {
		consider(k, c)
	}
	for k, c := range j.base {
		if _, ok := j.overlay[k]; ok {
			continue
		}
		if t, ok := j.deleted[k]; ok && !c.LastUpdate.After(t) {
			continue
		}
		consider(k, c)
	}
	sort.Slice(items, func(a, b int) bool {
		if la, lb := len(items[a].c.Path), len(items[b].c.Path); la != lb {
			return la > lb
		}
		return items[a].seq < items[b].seq
	})
	out := make([]creds.Cookie, len(items))
	for i, it := range items {
		out[i] = it.c
	}
	return out
}

// CookieHeader renders cookies as a Cookie request header value.
func CookieHeader(cs []creds.Cookie) string {
	var b strings.Builder
	for i, c := range cs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

// Len returns the number of stored cookies (base and overlay, counting a
// (name, domain, path) once), including expired ones not yet pruned.
func (j *Jar) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := len(j.overlay)
	for k := range j.base {
		if _, ok := j.overlay[k]; !ok {
			n++
		}
	}
	return n
}

// Zero drops all cookie values.
func (j *Jar) Zero() {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, m := range []map[key]creds.Cookie{j.base, j.overlay} {
		for k, c := range m {
			c.Value = ""
			m[k] = c
		}
	}
	j.base = map[key]creds.Cookie{}
	j.overlay = map[key]creds.Cookie{}
	j.created = map[key]uint64{}
	j.deleted = map[key]time.Time{}
}
