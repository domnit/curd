// Package redact replaces credential values the daemon holds with
// placeholders such as {cookie:session} or
// {ls:https://app.example.com:authToken} (spec section 16.2). Everything a
// browse verb or the capture API returns passes through a Redactor.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

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
	// Each secret is matched raw and in the encodings it commonly travels
	// in, so a value shown URL-encoded or JSON-escaped is still caught.
	forms := map[string]string{}
	keys := make([]string, 0, len(r.secrets))
	for v := range r.secrets {
		keys = append(keys, v)
	}
	sort.Strings(keys)
	for _, v := range keys {
		ph := r.secrets[v]
		for _, f := range Variants(v) {
			if _, ok := forms[f]; !ok {
				forms[f] = ph
			}
		}
	}
	// A raw secret always maps to its own placeholder, even if it equals
	// an encoded form of another secret.
	for v, ph := range r.secrets {
		forms[v] = ph
	}
	vals := make([]string, 0, len(forms))
	for v := range forms {
		vals = append(vals, v)
	}
	// Longest first so a secret containing another is replaced whole.
	sort.Slice(vals, func(i, j int) bool {
		if len(vals[i]) != len(vals[j]) {
			return len(vals[i]) > len(vals[j])
		}
		return vals[i] < vals[j]
	})
	pairs := make([]string, 0, 2*len(vals))
	for _, v := range vals {
		pairs = append(pairs, v, forms[v])
	}
	r.replacer = strings.NewReplacer(pairs...)
}

// Variants returns v and the encoded forms a secret value is matched in:
// URL query and path escaping, full %XX escaping in upper- and lowercase
// hex, and JSON string escaping (with and without HTML escaping, with "/"
// as "\/", and with every character as \uXXXX).
func Variants(v string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(v)
	add(url.QueryEscape(v))
	add(url.PathEscape(v))
	add(pctEscapeAll(v, true))
	add(pctEscapeAll(v, false))
	for _, j := range jsonForms(v) {
		add(j)
		add(strings.ReplaceAll(j, "/", `\/`))
	}
	add(jsonUEscapeAll(v, false))
	add(jsonUEscapeAll(v, true))
	return out
}

func jsonForms(v string) []string {
	var out []string
	if b, err := json.Marshal(v); err == nil {
		out = append(out, string(b[1:len(b)-1]))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) == nil {
		b := bytes.TrimSpace(buf.Bytes())
		out = append(out, string(b[1:len(b)-1]))
	}
	return out
}

func jsonUEscapeAll(v string, upper bool) string {
	var b strings.Builder
	f := "\\u%04x"
	if upper {
		f = "\\u%04X"
	}
	for _, c := range utf16.Encode([]rune(v)) {
		fmt.Fprintf(&b, f, c)
	}
	return b.String()
}

// Len reports how many secrets are registered.
func (r *Redactor) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.secrets)
}

// String redacts s. Encoded forms of each secret are replaced in place. If
// a secret still shows up after percent-decoding or JSON-unescaping the
// result (an encoding mixed in a way no listed variant covers), the decoded
// text is redacted and returned instead: fidelity is given up so that the
// value never leaks.
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
	out := rep.Replace(s)
	for range 4 {
		changed := false
		for _, dec := range decoders {
			d := dec(out)
			if d == out {
				continue
			}
			if rd := rep.Replace(d); rd != d {
				out, changed = rd, true
				break
			}
		}
		if !changed {
			break
		}
	}
	return out
}

var decoders = []func(string) string{
	func(s string) string { return pctDecode(s, false) },
	func(s string) string { return pctDecode(s, true) },
	jsonUnescape,
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// pctDecode decodes valid %XX sequences (and '+' as space when plus is set),
// leaving anything else as is.
func pctDecode(s string, plus bool) string {
	if !strings.Contains(s, "%") && !(plus && strings.Contains(s, "+")) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(h<<4 | l)
				i += 2
				continue
			}
		}
		if plus && c == '+' {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// jsonUnescape decodes JSON string escapes (\/, \", \\, \n..., \uXXXX
// including surrogate pairs) wherever they appear, leaving anything else as
// is.
func jsonUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch e := s[i+1]; e {
		case '/', '"', '\\':
			b.WriteByte(e)
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'u':
			r1, ok := hex4(s, i+2)
			if !ok {
				b.WriteByte(c)
				continue
			}
			i += 5
			if utf16.IsSurrogate(r1) {
				if i+6 < len(s) && s[i+1] == '\\' && s[i+2] == 'u' {
					if r2, ok := hex4(s, i+3); ok {
						if dr := utf16.DecodeRune(r1, r2); dr != utf8.RuneError {
							b.WriteRune(dr)
							i += 6
							continue
						}
					}
				}
			}
			b.WriteRune(r1)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hex4(s string, at int) (rune, bool) {
	if at+4 > len(s) {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		h, ok := unhex(s[at+k])
		if !ok {
			return 0, false
		}
		r = r<<4 | rune(h)
	}
	return r, true
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

// pctEscapeAll %XX-escapes every byte outside the RFC 3986 unreserved set.
func pctEscapeAll(s string, upper bool) string {
	digits := "0123456789abcdef"
	if upper {
		digits = "0123456789ABCDEF"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(digits[c>>4])
			b.WriteByte(digits[c&15])
		}
	}
	return b.String()
}
