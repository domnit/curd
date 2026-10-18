// Package redact replaces credential values the daemon holds with
// placeholders such as {cookie:session} or
// {ls:https://app.example.com:authToken} (spec section 16.2). Everything a
// browse verb or the capture API returns passes through a Redactor.
package redact

import (
	"sort"
	"strings"
	"sync"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/creds"
)

// MinSecretLen is the shortest value treated as a secret. Shorter values
// (flags like "1" or "true") would mangle unrelated text; real session
// cookies and tokens are far longer.
const MinSecretLen = 6

// Secret is one held credential value and the placeholder that replaces it.
type Secret struct {
	Value       string
	Placeholder string
}

// CookiePlaceholder returns the placeholder for a cookie name.
func CookiePlaceholder(name string) string { return "{cookie:" + name + "}" }

// LocalStoragePlaceholder returns the placeholder for a localStorage item.
func LocalStoragePlaceholder(origin, key string) string { return "{ls:" + origin + ":" + key + "}" }

// FromCredentials lists the secrets in c.
func FromCredentials(c *creds.Credentials) []Secret {
	if c == nil {
		return nil
	}
	var out []Secret
	for _, ck := range c.Cookies {
		out = append(out, Secret{ck.Value, CookiePlaceholder(ck.Name)})
	}
	for _, it := range c.LocalStorage {
		out = append(out, Secret{it.Value, LocalStoragePlaceholder(it.Origin, it.Key)})
	}
	return out
}

// Redactor replaces secret values by exact match. It is safe for concurrent
// use, and secrets can be added as they are learned (for example cookies
// minted by an interactive login).
type Redactor struct {
	mu       sync.RWMutex
	secrets  map[string]string // value -> placeholder
	replacer *strings.Replacer
}

// New returns a Redactor for secrets.
func New(secrets ...Secret) *Redactor {
	r := &Redactor{secrets: map[string]string{}}
	r.Add(secrets...)
	return r
}

// Add registers more secrets.
func (r *Redactor) Add(secrets ...Secret) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, s := range secrets {
		if len(s.Value) < MinSecretLen {
			continue
		}
		if _, ok := r.secrets[s.Value]; !ok {
			r.secrets[s.Value] = s.Placeholder
			changed = true
		}
	}
	if changed || r.replacer == nil {
		r.rebuild()
	}
}

func (r *Redactor) rebuild() {
	vals := make([]string, 0, len(r.secrets))
	for v := range r.secrets {
		vals = append(vals, v)
	}
	// Longest first so a secret containing another is replaced whole.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	var pairs []string
	for _, v := range vals {
		pairs = append(pairs, v, r.secrets[v])
		// Also catch the common URL/JSON-escaped forms.
		if e := urlEscape(v); e != v {
			pairs = append(pairs, e, r.secrets[v])
		}
	}
	r.replacer = strings.NewReplacer(pairs...)
}

// Len reports how many secrets are registered.
func (r *Redactor) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.secrets)
}

// String redacts s.
func (r *Redactor) String(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	rep := r.replacer
	r.mu.RUnlock()
	if rep == nil {
		return s
	}
	return rep.Replace(s)
}

// Bytes redacts b.
func (r *Redactor) Bytes(b []byte) []byte { return []byte(r.String(string(b))) }

// Contains reports whether s contains any registered secret. Tests and
// defensive checks use it.
func (r *Redactor) Contains(s string) bool {
	return r.String(s) != s
}

// Headers redacts header values. Cookie and Set-Cookie values are always
// replaced by placeholders per cookie name, and Authorization by
// {header:authorization}, whether or not the value is a held secret.
func (r *Redactor) Headers(h []api.Header) []api.Header {
	out := make([]api.Header, len(h))
	for i, hd := range h {
		switch strings.ToLower(hd.Name) {
		case "cookie":
			out[i] = api.Header{Name: hd.Name, Value: redactCookieHeader(hd.Value)}
		case "set-cookie":
			out[i] = api.Header{Name: hd.Name, Value: redactSetCookie(hd.Value)}
		case "authorization", "proxy-authorization":
			v := hd.Value
			scheme, _, ok := strings.Cut(v, " ")
			if ok && len(scheme) < 20 {
				v = scheme + " {header:" + strings.ToLower(hd.Name) + "}"
			} else {
				v = "{header:" + strings.ToLower(hd.Name) + "}"
			}
			// Prefer the precise placeholder when the value is held.
			if red := r.String(hd.Value); red != hd.Value {
				v = red
			}
			out[i] = api.Header{Name: hd.Name, Value: v}
		default:
			out[i] = api.Header{Name: hd.Name, Value: r.String(hd.Value)}
		}
	}
	return out
}

// CookieNames returns the cookie names in a Cookie header value.
func CookieNames(cookieHeader string) []string {
	var names []string
	for _, part := range strings.Split(cookieHeader, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func redactCookieHeader(v string) string {
	var parts []string
	for _, name := range CookieNames(v) {
		parts = append(parts, name+"="+CookiePlaceholder(name))
	}
	return strings.Join(parts, "; ")
}

func redactSetCookie(v string) string {
	first, rest, _ := strings.Cut(v, ";")
	name, _, _ := strings.Cut(strings.TrimSpace(first), "=")
	out := name + "=" + CookiePlaceholder(name)
	if rest != "" {
		out += ";" + rest
	}
	return out
}

func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[c>>4])+string("0123456789abcdef"[c&15])))
		}
	}
	return b.String()
}
