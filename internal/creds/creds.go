// Package creds defines the credential types held in daemon memory and the
// Source interface that credential sources implement (spec section 5.5).
//
// Values in this package are secrets. They must never be logged, returned
// over RPC, or included in error messages.
package creds

import (
	"context"
	"time"
)

// Cookie is one browser cookie. Domain follows Chrome's host_key convention:
// a leading dot (".example.com") marks a domain cookie that also matches
// subdomains; no leading dot means a host-only cookie.
type Cookie struct {
	Name       string
	Value      string
	Domain     string
	Path       string
	Secure     bool
	HTTPOnly   bool
	SameSite   string    // "", "lax", "strict", "none"
	Expires    time.Time // zero means session cookie
	LastUpdate time.Time // when the source last wrote it; used for jar merge
}

// HostOnly reports whether the cookie only matches its exact host.
func (c Cookie) HostOnly() bool { return len(c.Domain) == 0 || c.Domain[0] != '.' }

// LocalStorageItem is one localStorage entry for an origin such as
// "https://app.example.com".
type LocalStorageItem struct {
	Origin string
	Key    string
	Value  string
}

// Credentials is what a Source returns.
type Credentials struct {
	Cookies      []Cookie
	LocalStorage []LocalStorageItem
	Profile      string // profile directory name the credentials came from, if any
}

// LocalStorageSpec names localStorage keys to extract for one origin.
type LocalStorageSpec struct {
	Origin string
	Keys   []string
}

// Request says what to load. Sources must load only what is asked for:
// cookies whose host matches Hosts (exact or explicit "*.suffix" wildcard,
// see MatchHost) and, if CookieNames is non-empty, whose name matches one of
// its glob patterns; and only the named localStorage keys.
type Request struct {
	Hosts        []string
	CookieNames  []string // glob patterns ('__Host-*'); empty means all
	LocalStorage []LocalStorageSpec
	Profile      string // optional pinned profile directory name ("Default", "Profile 1")
}

// Source loads credentials. Implementations: Chrome profile (cookies via
// SQLite + keychain, localStorage via LevelDB) and static fixture (test mode).
type Source interface {
	Name() string
	Load(ctx context.Context, req Request) (*Credentials, error)
}

// Zero overwrites what it can of the credential values. Go strings are
// immutable so this is best effort: it drops references so the GC can reclaim
// them.
func (c *Credentials) Zero() {
	if c == nil {
		return
	}
	for i := range c.Cookies {
		c.Cookies[i].Value = ""
	}
	for i := range c.LocalStorage {
		c.LocalStorage[i].Value = ""
	}
	c.Cookies = nil
	c.LocalStorage = nil
}
