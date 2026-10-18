// Package source turns a creds.Source into per-policy cached credentials
// (spec 5.4): TTL refresh, reload on demand, one cookie jar per policy that
// survives reloads, and singleflight loading.
//
// Nothing in this package puts credential values into errors or status.
package source

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/jar"
	"github.com/domnit/curd/internal/policy"
)

// DefaultTTL is how long loaded credentials are used before a reload.
const DefaultTTL = 5 * time.Minute

// Options configures a Manager.
type Options struct {
	TTL time.Duration    // default DefaultTTL
	Now func() time.Time // default time.Now
}

// Entry is a snapshot of one policy's credentials. Jar is shared by all
// snapshots of the same policy. LocalStorage must be treated as read-only.
type Entry struct {
	Jar          *jar.Jar
	LocalStorage []creds.LocalStorageItem
	LoadedAt     time.Time
	Profile      string
}

type call struct {
	done  chan struct{}
	entry *Entry
	err   error
}

type slot struct {
	jar     *jar.Jar
	entry   *Entry
	reqKey  string
	loading *call
	loads   int
	lastErr string
	lastTry time.Time
	cookies int
}

// Manager caches credentials per policy.
type Manager struct {
	src creds.Source
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	slots map[string]*slot
}

// NewManager returns a Manager loading from src.
func NewManager(src creds.Source, opts Options) *Manager {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{src: src, ttl: opts.TTL, now: opts.Now, slots: map[string]*slot{}}
}

// RequestFor builds the credential request for a policy.
func RequestFor(p *policy.Policy) creds.Request {
	req := creds.Request{
		Hosts:       append([]string(nil), p.Match.Hosts...),
		CookieNames: append([]string(nil), p.Credentials.Cookies...),
		Profile:     p.Profile,
	}
	for _, ls := range p.Credentials.LocalStorage {
		req.LocalStorage = append(req.LocalStorage, creds.LocalStorageSpec{
			Origin: ls.Origin, Keys: append([]string(nil), ls.Keys...),
		})
	}
	return req
}

func requestKey(r creds.Request) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// Get returns the policy's credentials, loading them if there is no fresh
// entry, the policy's credential request changed, or force is set. Concurrent
// loads for one policy are shared.
func (m *Manager) Get(ctx context.Context, p *policy.Policy, force bool) (*Entry, error) {
	req := RequestFor(p)
	key := requestKey(req)

	m.mu.Lock()
	s := m.slots[p.Name]
	if s == nil {
		s = &slot{jar: jar.New()}
		m.slots[p.Name] = s
	}
	if !force && s.entry != nil && s.reqKey == key && m.now().Sub(s.entry.LoadedAt) < m.ttl {
		e := s.entry
		m.mu.Unlock()
		return e, nil
	}
	if c := s.loading; c != nil {
		m.mu.Unlock()
		select {
		case <-c.done:
			return c.entry, c.err
		case <-ctx.Done():
			return nil, apierr.New(apierr.SourceError, "cancelled while loading credentials", "retry the request")
		}
	}
	c := &call{done: make(chan struct{})}
	s.loading = c
	m.mu.Unlock()

	loaded, err := m.src.Load(ctx, req)

	m.mu.Lock()
	s.loading = nil
	s.lastTry = m.now()
	if err != nil {
		s.lastErr = scrubErr(err)
		c.err = m.wrapErr(p, err)
	} else {
		s.lastErr = ""
		s.loads++
		s.jar.SetBase(loaded.Cookies)
		s.cookies = len(loaded.Cookies)
		s.entry = &Entry{
			Jar:          s.jar,
			LocalStorage: append([]creds.LocalStorageItem(nil), loaded.LocalStorage...),
			LoadedAt:     m.now(),
			Profile:      loaded.Profile,
		}
		s.reqKey = key
		c.entry = s.entry
	}
	m.mu.Unlock()
	if loaded != nil {
		loaded.Zero()
	}
	close(c.done)
	return c.entry, c.err
}

func scrubErr(err error) string { return apierr.As(err).Message }

func (m *Manager) wrapErr(p *policy.Policy, err error) error {
	host := ""
	if len(p.Match.Hosts) > 0 {
		host = p.Match.Hosts[0]
	}
	hint := "is Chrome installed and are you logged into " + host + " in it?"
	if m.src.Name() == "static" {
		hint = "check the static fixture file used for test mode"
	}
	if ae, ok := err.(*apierr.Error); ok {
		out := *ae
		out.Code = apierr.SourceError
		if out.Hint == "" {
			out.Hint = hint
		}
		return &out
	}
	return apierr.Newf(apierr.SourceError, hint, "loading credentials for policy %q from source %s failed: %v", p.Name, m.src.Name(), err)
}

// Loads returns how many successful loads the policy has had.
func (m *Manager) Loads(policyName string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.slots[policyName]; s != nil {
		return s.loads
	}
	return 0
}

// Status reports, per policy that has been used, counts only. Name is the
// policy name.
func (m *Manager) Status() []api.SourceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.slots))
	for n := range m.slots {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []api.SourceStatus
	for _, n := range names {
		s := m.slots[n]
		st := api.SourceStatus{Name: n, OK: s.entry != nil && s.lastErr == "", Error: s.lastErr}
		if s.entry != nil {
			st.LastLoad = s.entry.LoadedAt
			st.Profile = s.entry.Profile
			st.Cookies = s.cookies
			st.LocalStorage = len(s.entry.LocalStorage)
		}
		out = append(out, st)
	}
	return out
}

// Zero drops all held credentials.
func (m *Manager) Zero() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.slots {
		s.jar.Zero()
		if s.entry != nil {
			for i := range s.entry.LocalStorage {
				s.entry.LocalStorage[i].Value = ""
			}
			s.entry.LocalStorage = nil
		}
		s.entry = nil
		s.reqKey = ""
		s.cookies = 0
	}
}
