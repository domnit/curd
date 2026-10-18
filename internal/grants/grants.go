// Package grants holds curd's in-memory grant store and session tokens
// (spec section 6.3). A token is an opaque random id pointing at a
// daemon-side grant; revocation is instant and tokens are never persisted,
// logged or listed (only ids and token hashes are).
package grants

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
)

// Grant modes.
const (
	ModeOnce    = "once"
	ModeSession = "session"
)

// Grant scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

const (
	tokenPrefix = "crd_"
	idPrefix    = "gr_"
	tokenChars  = 32
	idChars     = 10
)

// Grant is a consented capability. Token is a secret: never log it.
type Grant struct {
	ID               string // "gr_" + 10 base32 chars; safe to show
	Token            string // "crd_" + 32 base32 chars; shown once, never logged
	Policies         []string
	Scopes           []string // "read", "write" (a write grant has both)
	Mode             string   // "once" | "session"
	SessionKey       string
	SessionKeySource string
	ClientPID        int
	ClientExe        string
	Purpose          string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LastUsed         time.Time
	IdleTimeout      time.Duration
	Uses             int
	Test             bool
}

func (g *Grant) covers(policy, scope string) (policyOK, scopeOK bool) {
	for _, p := range g.Policies {
		if p == policy {
			policyOK = true
		}
	}
	for _, s := range g.Scopes {
		if s == scope {
			scopeOK = true
		}
	}
	return
}

func (g *Grant) expired(now time.Time) bool {
	if !now.Before(g.ExpiresAt) {
		return true
	}
	return g.IdleTimeout > 0 && !now.Before(g.LastUsed.Add(g.IdleTimeout))
}

func (g *Grant) clone() *Grant {
	c := *g
	c.Policies = append([]string(nil), g.Policies...)
	c.Scopes = append([]string(nil), g.Scopes...)
	return &c
}

// Options configures a Store.
type Options struct {
	Now         func() time.Time // default time.Now
	IdleTimeout time.Duration    // default 1h
	MaxTTL      time.Duration    // absolute maximum lifetime; default 24h
	Test        bool             // mark minted grants as test-mode
}

// MintSpec describes a grant to create.
type MintSpec struct {
	Policies, Scopes []string
	Mode             string        // "once" or "session" (default)
	TTL              time.Duration // clamped to MaxTTL; <=0 means MaxTTL
	SessionKey       string
	SessionKeySource string
	ClientPID        int
	ClientExe        string
	Purpose          string
}

// Store is a goroutine-safe in-memory grant store.
type Store struct {
	opts Options

	mu       sync.Mutex
	byID     map[string]*Grant
	byToken  map[string]*Grant
	onRevoke func(*Grant)
}

// NewStore returns an empty Store.
func NewStore(opts Options) *Store {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = time.Hour
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = 24 * time.Hour
	}
	return &Store{opts: opts, byID: map[string]*Grant{}, byToken: map[string]*Grant{}}
}

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func randString(n int) string {
	b := make([]byte, (n*5+7)/8)
	if _, err := rand.Read(b); err != nil {
		panic("grants: crypto/rand failed: " + err.Error())
	}
	return b32.EncodeToString(b)[:n]
}

// IsToken reports whether s has the shape of a curd session token
// ("crd_" plus 32 lowercase base32 characters). It does not check validity.
func IsToken(s string) bool {
	if !strings.HasPrefix(s, tokenPrefix) || len(s) != len(tokenPrefix)+tokenChars {
		return false
	}
	for _, r := range s[len(tokenPrefix):] {
		if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7') {
			return false
		}
	}
	return true
}

func normalizeScopes(in []string) []string {
	var read, write bool
	for _, s := range in {
		switch s {
		case ScopeRead:
			read = true
		case ScopeWrite:
			write = true
		}
	}
	if write || !read {
		read = true
	}
	out := []string{ScopeRead}
	if write {
		out = append(out, ScopeWrite)
	}
	return out
}

// OnRevoke registers fn to be called (without the store lock held) for every
// grant removed by Revoke, Sweep, expiry detected on lookup, or consumption
// of a once grant. Only one hook is kept.
func (s *Store) OnRevoke(fn func(g *Grant)) {
	s.mu.Lock()
	s.onRevoke = fn
	s.mu.Unlock()
}

func (s *Store) notify(gs []*Grant) {
	s.mu.Lock()
	fn := s.onRevoke
	s.mu.Unlock()
	if fn == nil {
		return
	}
	for _, g := range gs {
		fn(g.clone())
	}
}

// Mint creates and stores a grant. The returned Grant carries the token; this
// is the only time it should be shown.
func (s *Store) Mint(spec MintSpec) *Grant {
	now := s.opts.Now()
	ttl := spec.TTL
	if ttl <= 0 || ttl > s.opts.MaxTTL {
		ttl = s.opts.MaxTTL
	}
	mode := spec.Mode
	if mode != ModeOnce {
		mode = ModeSession
	}
	g := &Grant{
		Token:            tokenPrefix + randString(tokenChars),
		Policies:         append([]string(nil), spec.Policies...),
		Scopes:           normalizeScopes(spec.Scopes),
		Mode:             mode,
		SessionKey:       spec.SessionKey,
		SessionKeySource: spec.SessionKeySource,
		ClientPID:        spec.ClientPID,
		ClientExe:        spec.ClientExe,
		Purpose:          spec.Purpose,
		CreatedAt:        now,
		ExpiresAt:        now.Add(ttl),
		LastUsed:         now,
		IdleTimeout:      s.opts.IdleTimeout,
		Test:             s.opts.Test,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		g.ID = idPrefix + randString(idChars)
		if _, dup := s.byID[g.ID]; !dup {
			break
		}
	}
	s.byID[g.ID] = g
	s.byToken[g.Token] = g
	return g.clone()
}

func (s *Store) removeLocked(g *Grant) {
	delete(s.byID, g.ID)
	delete(s.byToken, g.Token)
}

// lookup finds the grant for the request. Callers hold s.mu. Expired grants
// met on the way are removed and returned in dead.
func (s *Store) lookup(token, sessionKey, policy, scope string, now time.Time) (g *Grant, dead []*Grant, err error) {
	missing := func(g *Grant) *apierr.Error {
		if pOK, _ := g.covers(policy, scope); !pOK {
			return apierr.Newf(apierr.DeniedNoGrant,
				fmt.Sprintf("request access with `curd grants request %s%s`", policy, writeFlag(scope)),
				"grant %s does not cover policy %q", g.ID, policy)
		}
		return apierr.Newf(apierr.DeniedNoGrant,
			fmt.Sprintf("request %s access with `curd grants request %s%s`", scope, policy, writeFlag(scope)),
			"grant %s does not include the %s scope for policy %q", g.ID, scope, policy)
	}
	if token != "" {
		t := s.byToken[token]
		if t == nil {
			return nil, nil, apierr.New(apierr.InvalidToken, "unknown, revoked or expired session token",
				fmt.Sprintf("drop the token to be prompted again, or run `curd grants request %s%s`", policy, writeFlag(scope)))
		}
		if t.expired(now) {
			s.removeLocked(t)
			return nil, []*Grant{t}, apierr.New(apierr.InvalidToken, "unknown, revoked or expired session token",
				fmt.Sprintf("run `curd grants request %s%s` for a fresh grant", policy, writeFlag(scope)))
		}
		if p, sc := t.covers(policy, scope); !p || !sc {
			return nil, nil, missing(t)
		}
		return t, nil, nil
	}
	var best *Grant
	for _, c := range s.byID {
		if c.SessionKey != sessionKey {
			continue
		}
		if c.expired(now) {
			s.removeLocked(c)
			dead = append(dead, c)
			continue
		}
		if p, sc := c.covers(policy, scope); !p || !sc {
			continue
		}
		// Prefer session grants over once grants, then the newest.
		if best == nil || (best.Mode == ModeOnce && c.Mode != ModeOnce) ||
			(best.Mode == c.Mode && c.CreatedAt.After(best.CreatedAt)) {
			best = c
		}
	}
	if best == nil {
		return nil, dead, apierr.Newf(apierr.DeniedNoGrant,
			fmt.Sprintf("request access with `curd grants request %s%s`", policy, writeFlag(scope)),
			"no active grant covers policy %q with %s scope for this session", policy, scope)
	}
	return best, dead, nil
}

func writeFlag(scope string) string {
	if scope == ScopeWrite {
		return " --write"
	}
	return ""
}

// Authorize finds the grant for a request and records the use: Uses is
// incremented, LastUsed advances, and a "once" grant is consumed. With a
// token it must be valid and cover policy+scope; without one, an active grant
// with the same SessionKey is used. The returned Grant is a snapshot.
func (s *Store) Authorize(token, sessionKey, policy, scope string) (*Grant, error) {
	now := s.opts.Now()
	s.mu.Lock()
	g, dead, err := s.lookup(token, sessionKey, policy, scope, now)
	var consumed *Grant
	var out *Grant
	if err == nil {
		g.Uses++
		g.LastUsed = now
		out = g.clone()
		if g.Mode == ModeOnce {
			s.removeLocked(g)
			consumed = g
		}
	}
	s.mu.Unlock()
	if consumed != nil {
		dead = append(dead, consumed)
	}
	s.notify(dead)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Peek is like Authorize but records no use and consumes nothing.
func (s *Store) Peek(token, sessionKey, policy, scope string) (*Grant, error) {
	now := s.opts.Now()
	s.mu.Lock()
	g, dead, err := s.lookup(token, sessionKey, policy, scope, now)
	var out *Grant
	if err == nil {
		out = g.clone()
	}
	s.mu.Unlock()
	s.notify(dead)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns a snapshot of the live grant with the given id or token.
func (s *Store) Get(idOrToken string) (*Grant, bool) {
	now := s.opts.Now()
	s.mu.Lock()
	g := s.byID[idOrToken]
	if g == nil {
		g = s.byToken[idOrToken]
	}
	var dead []*Grant
	if g != nil && g.expired(now) {
		s.removeLocked(g)
		dead = []*Grant{g}
		g = nil
	}
	var out *Grant
	if g != nil {
		out = g.clone()
	}
	s.mu.Unlock()
	s.notify(dead)
	return out, out != nil
}

// Info converts g to its token-free wire form.
func (s *Store) Info(g *Grant) api.GrantInfo {
	idle := g.LastUsed.Add(g.IdleTimeout)
	if g.IdleTimeout <= 0 || idle.After(g.ExpiresAt) {
		idle = g.ExpiresAt
	}
	return api.GrantInfo{
		ID:               g.ID,
		TokenHash:        audit.HashToken(g.Token),
		Policies:         append([]string(nil), g.Policies...),
		Scopes:           append([]string(nil), g.Scopes...),
		Mode:             g.Mode,
		SessionKey:       g.SessionKey,
		SessionKeySource: g.SessionKeySource,
		ClientPID:        g.ClientPID,
		ClientExe:        g.ClientExe,
		CreatedAt:        g.CreatedAt,
		ExpiresAt:        g.ExpiresAt,
		IdleExpiresAt:    idle,
		Uses:             g.Uses,
		Test:             g.Test,
	}
}

// List returns the live grants, oldest first. Tokens are never included.
func (s *Store) List() []api.GrantInfo {
	s.Sweep()
	s.mu.Lock()
	gs := make([]*Grant, 0, len(s.byID))
	for _, g := range s.byID {
		gs = append(gs, g.clone())
	}
	s.mu.Unlock()
	sort.Slice(gs, func(i, j int) bool {
		if gs[i].CreatedAt.Equal(gs[j].CreatedAt) {
			return gs[i].ID < gs[j].ID
		}
		return gs[i].CreatedAt.Before(gs[j].CreatedAt)
	})
	out := make([]api.GrantInfo, len(gs))
	for i, g := range gs {
		out[i] = s.Info(g)
	}
	return out
}

// Revoke removes the grant with the given id or token, or every grant for
// "all". It returns the revoked grant ids.
func (s *Store) Revoke(idOrToken string) []string {
	s.mu.Lock()
	var gone []*Grant
	if idOrToken == "all" {
		for _, g := range s.byID {
			gone = append(gone, g)
		}
	} else if g := s.byID[idOrToken]; g != nil {
		gone = append(gone, g)
	} else if g := s.byToken[idOrToken]; g != nil {
		gone = append(gone, g)
	}
	ids := make([]string, 0, len(gone))
	for _, g := range gone {
		s.removeLocked(g)
		ids = append(ids, g.ID)
	}
	s.mu.Unlock()
	sort.Strings(ids)
	s.notify(gone)
	return ids
}

// Sweep drops expired grants (absolute or idle), calling the OnRevoke hook
// for each.
func (s *Store) Sweep() {
	now := s.opts.Now()
	s.mu.Lock()
	var dead []*Grant
	for _, g := range s.byID {
		if g.expired(now) {
			dead = append(dead, g)
		}
	}
	for _, g := range dead {
		s.removeLocked(g)
	}
	s.mu.Unlock()
	s.notify(dead)
}

// Len returns the number of stored grants (including any not yet swept).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}
