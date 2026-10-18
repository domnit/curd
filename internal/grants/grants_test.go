package grants

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domnit/curd/internal/apierr"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStore() (*Store, *clock) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return NewStore(Options{Now: c.Now, IdleTimeout: 10 * time.Minute, MaxTTL: time.Hour}), c
}

func TestMintShape(t *testing.T) {
	s, _ := newStore()
	g := s.Mint(MintSpec{Policies: []string{"a"}, TTL: 24 * time.Hour})
	if !IsToken(g.Token) || !strings.HasPrefix(g.ID, "gr_") || len(g.ID) != 13 {
		t.Fatalf("bad id/token: %q %q", g.ID, g.Token)
	}
	if got := g.ExpiresAt.Sub(g.CreatedAt); got != time.Hour {
		t.Fatalf("ttl not clamped: %v", got)
	}
	if g.Mode != "session" || !reflect.DeepEqual(g.Scopes, []string{"read"}) {
		t.Fatalf("defaults: %+v", g)
	}
	for _, bad := range []string{"", "crd_", "crd_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "xxx_abcdefghijklmnopqrstuvwxyz234567", "crd_abcdefghijklmnopqrstuvwxyz23456", "crd_abcdefghijklmnopqrstuvwxyz234561"} {
		if IsToken(bad) {
			t.Errorf("IsToken(%q)", bad)
		}
	}
	if g2 := s.Mint(MintSpec{}); g2.Token == g.Token || g2.ID == g.ID {
		t.Fatal("not unique")
	}
}

func TestScopes(t *testing.T) {
	s, _ := newStore()
	w := s.Mint(MintSpec{Policies: []string{"a"}, Scopes: []string{"write"}})
	if !reflect.DeepEqual(w.Scopes, []string{"read", "write"}) {
		t.Fatalf("%v", w.Scopes)
	}
	if _, err := s.Authorize(w.Token, "", "a", "read"); err != nil {
		t.Fatalf("write must imply read: %v", err)
	}
	r := s.Mint(MintSpec{Policies: []string{"a"}, Scopes: []string{"read"}})
	_, err := s.Authorize(r.Token, "", "a", "write")
	ae := apierr.As(err)
	if ae.Code != apierr.DeniedNoGrant || !strings.Contains(ae.Hint, "--write") || strings.Contains(ae.Error(), r.Token) {
		t.Fatalf("got %v", err)
	}
	_, err = s.Authorize(r.Token, "", "other", "read")
	if apierr.CodeOf(err) != apierr.DeniedNoGrant || !strings.Contains(apierr.As(err).Hint, "curd grants request other") {
		t.Fatalf("got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	s, c := newStore()
	var revoked []string
	s.OnRevoke(func(g *Grant) { revoked = append(revoked, g.ID) })
	g := s.Mint(MintSpec{Policies: []string{"a"}})

	c.Add(9 * time.Minute)
	if _, err := s.Authorize(g.Token, "", "a", "read"); err != nil { // refreshes idle
		t.Fatal(err)
	}
	c.Add(9 * time.Minute)
	if _, err := s.Authorize(g.Token, "", "a", "read"); err != nil {
		t.Fatalf("idle should have been extended: %v", err)
	}
	c.Add(11 * time.Minute) // idle exceeded
	if _, err := s.Authorize(g.Token, "", "a", "read"); apierr.CodeOf(err) != apierr.InvalidToken {
		t.Fatalf("idle expiry: %v", err)
	}
	if len(revoked) != 1 || revoked[0] != g.ID {
		t.Fatalf("hook: %v", revoked)
	}

	// Absolute expiry despite activity.
	g2 := s.Mint(MintSpec{Policies: []string{"a"}, TTL: 30 * time.Minute})
	for i := 0; i < 5; i++ {
		c.Add(5 * time.Minute)
		if _, err := s.Authorize(g2.Token, "", "a", "read"); err != nil {
			t.Fatal(err)
		}
	}
	c.Add(5 * time.Minute)
	if _, err := s.Authorize(g2.Token, "", "a", "read"); apierr.CodeOf(err) != apierr.InvalidToken {
		t.Fatalf("absolute expiry: %v", err)
	}
}

func TestSweepCallsHook(t *testing.T) {
	s, c := newStore()
	var revoked []string
	s.OnRevoke(func(g *Grant) { revoked = append(revoked, g.ID) })
	a := s.Mint(MintSpec{Policies: []string{"a"}})
	c.Add(5 * time.Minute)
	b := s.Mint(MintSpec{Policies: []string{"a"}})
	c.Add(6 * time.Minute) // a idle-expired, b not
	s.Sweep()
	if s.Len() != 1 || !reflect.DeepEqual(revoked, []string{a.ID}) {
		t.Fatalf("len %d revoked %v", s.Len(), revoked)
	}
	if _, ok := s.Get(b.ID); !ok {
		t.Fatal("b should live")
	}
	c.Add(time.Hour)
	if _, ok := s.Get(b.ID); ok {
		t.Fatal("b should be gone")
	}
	if len(revoked) != 2 {
		t.Fatalf("hook after Get expiry: %v", revoked)
	}
}

func TestOnce(t *testing.T) {
	s, _ := newStore()
	n := 0
	s.OnRevoke(func(*Grant) { n++ })
	g := s.Mint(MintSpec{Policies: []string{"a"}, Mode: "once"})
	if _, err := s.Peek(g.Token, "", "a", "read"); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatal("peek consumed")
	}
	got, err := s.Authorize(g.Token, "", "a", "read")
	if err != nil || got.Uses != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := s.Authorize(g.Token, "", "a", "read"); apierr.CodeOf(err) != apierr.InvalidToken {
		t.Fatalf("second use: %v", err)
	}
	if n != 1 {
		t.Fatalf("hook count %d", n)
	}
}

func TestSessionKeyIsolation(t *testing.T) {
	s, _ := newStore()
	g := s.Mint(MintSpec{Policies: []string{"a"}, SessionKey: "chat1"})
	got, err := s.Authorize("", "chat1", "a", "read")
	if err != nil || got.ID != g.ID || got.Uses != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	for _, key := range []string{"chat2", "", "chat"} {
		if _, err := s.Authorize("", key, "a", "read"); apierr.CodeOf(err) != apierr.DeniedNoGrant {
			t.Fatalf("key %q: %v", key, err)
		}
	}
	empty := s.Mint(MintSpec{Policies: []string{"a"}})
	if got, err := s.Authorize("", "", "a", "read"); err != nil || got.ID != empty.ID {
		t.Fatalf("empty key: %v", err)
	}
	if _, err := s.Authorize("", "chat1", "b", "read"); apierr.CodeOf(err) != apierr.DeniedNoGrant {
		t.Fatal("policy not covered")
	}
	if _, err := s.Authorize("", "chat1", "a", "write"); apierr.CodeOf(err) != apierr.DeniedNoGrant {
		t.Fatal("write not covered")
	}
}

func TestRevoke(t *testing.T) {
	s, _ := newStore()
	var hooked []string
	s.OnRevoke(func(g *Grant) { hooked = append(hooked, g.ID) })
	a := s.Mint(MintSpec{Policies: []string{"a"}})
	b := s.Mint(MintSpec{Policies: []string{"a"}})
	c := s.Mint(MintSpec{Policies: []string{"a"}})
	if got := s.Revoke(a.ID); !reflect.DeepEqual(got, []string{a.ID}) {
		t.Fatal(got)
	}
	if got := s.Revoke(b.Token); !reflect.DeepEqual(got, []string{b.ID}) {
		t.Fatal(got)
	}
	if got := s.Revoke("nope"); len(got) != 0 {
		t.Fatal(got)
	}
	if got := s.Revoke("all"); !reflect.DeepEqual(got, []string{c.ID}) {
		t.Fatal(got)
	}
	if s.Len() != 0 || len(hooked) != 3 {
		t.Fatalf("len %d hooks %v", s.Len(), hooked)
	}
	if _, err := s.Authorize(a.Token, "", "a", "read"); apierr.CodeOf(err) != apierr.InvalidToken {
		t.Fatal("revoked token still works")
	}
}

func TestListNeverLeaksToken(t *testing.T) {
	s, _ := newStore()
	g := s.Mint(MintSpec{Policies: []string{"a"}, SessionKey: "k", ClientPID: 5})
	list := s.List()
	if len(list) != 1 {
		t.Fatal(list)
	}
	li := list[0]
	if li.ID != g.ID || li.TokenHash == "" || strings.Contains(li.TokenHash, g.Token) || !strings.HasPrefix(li.TokenHash, "sha256:") {
		t.Fatalf("%+v", li)
	}
	if li.IdleExpiresAt.After(li.ExpiresAt) || li.IdleExpiresAt.Before(li.CreatedAt) {
		t.Fatalf("idle expiry %+v", li)
	}
}

func TestConcurrentOnce(t *testing.T) {
	s, _ := newStore()
	g := s.Mint(MintSpec{Policies: []string{"a"}, Mode: "once"})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Authorize(g.Token, "", "a", "read"); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("once grant used %d times", ok)
	}
}

func TestInternalGrantAndTouch(t *testing.T) {
	s := NewStore(Options{})
	g := s.Mint(MintSpec{Policies: []string{"app"}, Scopes: []string{ScopeRead}, SessionKey: "k", Internal: true})
	// Never found by session-key matching...
	if _, err := s.Authorize("", "k", "app", ScopeRead); err == nil {
		t.Fatal("internal grant matched by session key")
	}
	if _, err := s.Peek("", "k", "app", ScopeRead); err == nil {
		t.Fatal("internal grant peeked by session key")
	}
	// ...but reachable by id and token.
	if _, ok := s.Get(g.ID); !ok {
		t.Fatal("no lookup by id")
	}
	if _, err := s.Authorize(g.Token, "", "app", ScopeRead); err != nil {
		t.Fatal(err)
	}
	if !s.Touch(g.ID) || s.Touch("gr_nosuch") {
		t.Fatal("Touch result wrong")
	}
	// Touch never consumes a once grant.
	o := s.Mint(MintSpec{Policies: []string{"app"}, Mode: ModeOnce, SessionKey: "k"})
	if !s.Touch(o.ID) {
		t.Fatal("once grant gone after Touch")
	}
	if _, ok := s.Get(o.ID); !ok {
		t.Fatal("Touch consumed a once grant")
	}
	s.Revoke(g.ID)
	if s.Touch(g.ID) {
		t.Fatal("Touch revived a revoked grant")
	}
}
