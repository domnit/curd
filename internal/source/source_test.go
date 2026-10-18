package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/policy"
)

func mustPolicy(t *testing.T, y string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const polYAML = `
name: dash
match:
  hosts: [app.example.com]
credentials:
  cookies: [session, '__Host-*']
  local_storage:
    - origin: https://app.example.com
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET]
    paths: ['^/.*$']
`

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type countSource struct {
	loads atomic.Int32
	gate  chan struct{}
	err   error
	last  creds.Request
	mu    sync.Mutex
}

func (s *countSource) Name() string { return "chrome" }
func (s *countSource) Load(ctx context.Context, req creds.Request) (*creds.Credentials, error) {
	s.loads.Add(1)
	s.mu.Lock()
	s.last = req
	s.mu.Unlock()
	if s.gate != nil {
		<-s.gate
	}
	if s.err != nil {
		return nil, s.err
	}
	return &creds.Credentials{
		Cookies:      []creds.Cookie{{Name: "session", Value: "SECRETVALUE", Domain: "app.example.com", Path: "/"}},
		LocalStorage: []creds.LocalStorageItem{{Origin: "https://app.example.com", Key: "authToken", Value: "TOK"}},
		Profile:      "Default",
	}, nil
}

func TestRequestFor(t *testing.T) {
	p := mustPolicy(t, polYAML+"profile: Profile 1\n")
	r := RequestFor(p)
	if r.Profile != "Profile 1" || len(r.Hosts) != 1 || len(r.CookieNames) != 2 ||
		len(r.LocalStorage) != 1 || r.LocalStorage[0].Keys[0] != "authToken" {
		t.Fatalf("%+v", r)
	}
}

func TestTTLAndForce(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	src := &countSource{}
	m := NewManager(src, Options{TTL: time.Minute, Now: clk.Now})
	p := mustPolicy(t, polYAML)
	ctx := context.Background()
	e1, err := m.Get(ctx, p, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, p, false); err != nil {
		t.Fatal(err)
	}
	if src.loads.Load() != 1 || m.Loads("dash") != 1 {
		t.Fatalf("loads %d", src.loads.Load())
	}
	clk.Add(59 * time.Second)
	m.Get(ctx, p, false)
	if src.loads.Load() != 1 {
		t.Fatal("reloaded too early")
	}
	clk.Add(2 * time.Second)
	e2, _ := m.Get(ctx, p, false)
	if src.loads.Load() != 2 {
		t.Fatal("no TTL reload")
	}
	if e1.Jar != e2.Jar {
		t.Fatal("jar must persist across reloads")
	}
	if _, err := m.Get(ctx, p, true); err != nil || src.loads.Load() != 3 {
		t.Fatalf("force: %v %d", err, src.loads.Load())
	}
	if m.Loads("dash") != 3 || m.Loads("nope") != 0 {
		t.Fatal("Loads")
	}
}

func TestRequestChangeReloads(t *testing.T) {
	src := &countSource{}
	m := NewManager(src, Options{})
	p := mustPolicy(t, polYAML)
	m.Get(context.Background(), p, false)
	p2 := mustPolicy(t, strings.Replace(polYAML, "[session, '__Host-*']", "[session]", 1))
	m.Get(context.Background(), p2, false)
	if src.loads.Load() != 2 {
		t.Fatal("changed request should reload")
	}
	m.Get(context.Background(), p2, false)
	if src.loads.Load() != 2 {
		t.Fatal("unchanged request should not reload")
	}
}

func TestSingleflight(t *testing.T) {
	src := &countSource{gate: make(chan struct{})}
	m := NewManager(src, Options{})
	p := mustPolicy(t, polYAML)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Get(context.Background(), p, false); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(src.gate)
	wg.Wait()
	if n := src.loads.Load(); n != 1 {
		t.Fatalf("loads = %d, want 1", n)
	}
}

func TestLoadErrorIsSourceError(t *testing.T) {
	src := &countSource{err: errors.New("keychain denied")}
	m := NewManager(src, Options{})
	p := mustPolicy(t, polYAML)
	_, err := m.Get(context.Background(), p, false)
	ae := apierr.As(err)
	if ae.Code != apierr.SourceError || !strings.Contains(ae.Hint, "logged into app.example.com") {
		t.Fatalf("%v", err)
	}
	st := m.Status()
	if len(st) != 1 || st[0].OK || st[0].Error == "" {
		t.Fatalf("%+v", st)
	}
	// recovers
	src.err = nil
	if _, err := m.Get(context.Background(), p, false); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); !st[0].OK || st[0].Cookies != 1 || st[0].LocalStorage != 1 || st[0].Profile != "Default" {
		t.Fatalf("%+v", st)
	}
}

func TestZero(t *testing.T) {
	src := &countSource{}
	m := NewManager(src, Options{})
	p := mustPolicy(t, polYAML)
	e, _ := m.Get(context.Background(), p, false)
	m.Zero()
	if e.Jar.Len() != 0 {
		t.Fatal("jar not zeroed")
	}
	m.Get(context.Background(), p, false)
	if src.loads.Load() != 2 {
		t.Fatal("expected reload after Zero")
	}
}

func writeStatic(t *testing.T, f *StaticFile) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "static.yaml")
	if err := WriteStaticFile(p, f); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStaticFiltering(t *testing.T) {
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	p := writeStatic(t, &StaticFile{
		Cookies: []StaticCookie{
			{Name: "session", Value: "a", Domain: "app.example.com", Secure: true, HTTPOnly: true, SameSite: "Lax", Expires: exp},
			{Name: "__Host-x", Value: "b", Domain: "app.example.com"},
			{Name: "tracking", Value: "c", Domain: "app.example.com"},
			{Name: "session", Value: "d", Domain: ".example.com", Path: "/api"},
			{Name: "session", Value: "e", Domain: "other.example.net"},
			{Name: "session", Value: "f", Domain: ".example.net"},
		},
		LocalStorage: []StaticLocalStorage{
			{Origin: "https://app.example.com", Key: "authToken", Value: "t"},
			{Origin: "https://app.example.com", Key: "other", Value: "o"},
			{Origin: "https://evil.example.org", Key: "authToken", Value: "x"},
		},
	})
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	s := NewStatic(p)
	pol := mustPolicy(t, polYAML)
	c, err := s.Load(context.Background(), RequestFor(pol))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ck := range c.Cookies {
		got = append(got, ck.Name+"="+ck.Value+"@"+ck.Domain+ck.Path)
	}
	want := "session=a@app.example.com/,__Host-x=b@app.example.com/,session=d@.example.com/api"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
	a := c.Cookies[0]
	if !a.Secure || !a.HTTPOnly || a.SameSite != "lax" || !a.Expires.Equal(exp) {
		t.Fatalf("%+v", a)
	}
	if len(c.LocalStorage) != 1 || c.LocalStorage[0].Key != "authToken" {
		t.Fatalf("%+v", c.LocalStorage)
	}
	// No name allowlist: all relevant cookies.
	c, _ = s.Load(context.Background(), creds.Request{Hosts: []string{"app.example.com"}})
	if len(c.Cookies) != 4 || len(c.LocalStorage) != 0 {
		t.Fatalf("%d cookies %d ls", len(c.Cookies), len(c.LocalStorage))
	}
	// Wildcard host.
	c, _ = s.Load(context.Background(), creds.Request{Hosts: []string{"*.example.net"}})
	if len(c.Cookies) != 2 {
		t.Fatalf("%d", len(c.Cookies))
	}
}

func TestStaticRereadAndErrors(t *testing.T) {
	f := &StaticFile{Cookies: []StaticCookie{{Name: "session", Value: "one", Domain: "app.example.com"}}}
	p := writeStatic(t, f)
	s := NewStatic(p)
	req := creds.Request{Hosts: []string{"app.example.com"}}
	c, _ := s.Load(context.Background(), req)
	if c.Cookies[0].Value != "one" {
		t.Fatal()
	}
	f.Cookies[0].Value = "two"
	WriteStaticFile(p, f)
	c, _ = s.Load(context.Background(), req)
	if c.Cookies[0].Value != "two" {
		t.Fatal("not re-read")
	}
	// invalid YAML never echoes values
	os.WriteFile(p, []byte("cookies:\n  - name: s\n    value: TOPSECRET\n    bogus: 1\n"), 0o600)
	_, err := s.Load(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("%v", err)
	}
	if _, err := NewStatic(filepath.Join(t.TempDir(), "missing")).Load(context.Background(), req); err == nil {
		t.Fatal("expected error")
	}
}
