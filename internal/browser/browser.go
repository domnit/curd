// Package browser runs ephemeral, authenticated browser sessions (spec
// section 9). curd holds the sole CDP connection (a pipe) and never exposes
// it: agents drive the browser only through the first-party verbs of
// Session.Do (spec 9.6). All pages live in one off-the-record browser
// context, every request is intercepted with the Fetch domain and checked
// against the session's policies (spec 9.3, 16.5), and the temp profile is
// deleted when the session ends (spec 9.4).
package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/redact"
)

// DefaultTTL is the session lifetime when OpenSpec.TTL is zero.
const DefaultTTL = 30 * time.Minute

// Seed modes.
const (
	SeedHoist = "hoist"
	SeedLogin = "login"
)

// CredentialLoader loads the credentials one policy grants. The daemon
// supplies it (from the source manager).
type CredentialLoader func(ctx context.Context, p *policy.Policy) (*creds.Credentials, error)

// Recorder receives raw CDP network events for capture. It is implemented by
// the capture package and may be nil.
type Recorder interface {
	// HandleEvent receives every Network.* event from every page, frame and
	// worker session.
	HandleEvent(cdpSessionID string, ev cdp.Event)
	// MarkBlocked records a request that curd failed instead of sending.
	MarkBlocked(networkRequestID, reason string, blockedWrite bool, req BlockedRequest)
}

// BlockedRequest describes a request curd blocked. Values are raw; the
// recorder redacts them.
type BlockedRequest struct {
	Method       string
	URL          string
	ResourceType string
	Headers      []api.Header
	PostData     []byte
}

// BodyFetcher fetches a body from the browser for the recorder: a response
// body or a request's post data. The bool reports base64 encoding.
type BodyFetcher func(ctx context.Context, cdpSessionID, requestID string) ([]byte, bool, error)

// RecorderFactory builds the Recorder for one session. body fetches response
// bodies, postData fetches request bodies.
type RecorderFactory func(sessionID string, red *redact.Redactor, body BodyFetcher, postData BodyFetcher) Recorder

// SessionEvent is an audit hook record. It never carries secret values:
// every string passes through the session's redactor.
type SessionEvent struct {
	Type         string // "open", "close", "verb", "blocked"
	SessionID    string
	Owner        string
	Time         time.Time
	Verb         string // verb events
	Detail       string // redacted: URL for open, selector for DOM verbs
	Error        string // verb events: error code, if any
	Method       string // blocked events
	URL          string // blocked events (redacted)
	Host         string // blocked events
	Reason       string // blocked events
	BlockedWrite bool   // blocked events: a write was refused
	Explore      bool
	Seed         string
	Test         bool
}

// Options configures a Manager.
type Options struct {
	Binary    string // chrome binary; "" = chrome.FindBinary()
	Test      bool   // test mode: headless, mock keychain, HostMap, http allowed, leak assertion
	Headless  bool   // production default false (interactive login needs a window)
	HostMap   map[string]string
	TempRoot  string // where temp user-data-dirs go (default os.TempDir())
	Load      CredentialLoader
	Recorders RecorderFactory // nil = no capture
	Now       func() time.Time
	OnEvent   func(SessionEvent)
}

// OpenSpec describes one session.
type OpenSpec struct {
	Policies    []*policy.Policy
	Owner       string // grant id
	TTL         time.Duration
	AllowWrites bool
	Seed        string // "hoist" | "login"
	LoginURL    string
	Explore     bool
	// HostMap adds to Options.HostMap for this session (test mode only); the
	// daemon passes the union of the session policies' test.host_map.
	HostMap map[string]string
}

// Manager owns the live sessions.
type Manager struct {
	opts Options

	mu       sync.Mutex
	sessions map[string]*Session
	order    []string // open order
	leaks    []string
}

// NewManager returns a Manager.
func NewManager(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.TempRoot == "" {
		opts.TempRoot = os.TempDir()
	}
	return &Manager{opts: opts, sessions: map[string]*Session{}}
}

func newID() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "bs_" + hex.EncodeToString(b[:])
}

// Open starts a session: launches the browser, creates the off-the-record
// context, installs interception, seeds credentials and (for login mode)
// navigates to the login page.
func (m *Manager) Open(ctx context.Context, spec OpenSpec) (*Session, error) {
	if len(spec.Policies) == 0 {
		return nil, apierr.New(apierr.InvalidRequest, "a browser session needs at least one policy", "pass the policy names the session may use")
	}
	for _, p := range spec.Policies {
		if p == nil {
			return nil, apierr.New(apierr.InvalidRequest, "nil policy", "")
		}
	}
	if spec.Seed == "" {
		spec.Seed = SeedHoist
	}
	if spec.Seed != SeedHoist && spec.Seed != SeedLogin {
		return nil, apierr.Newf(apierr.InvalidRequest, `use "hoist" or "login"`, "unknown seed mode %q", spec.Seed)
	}
	if spec.Seed == SeedHoist && m.opts.Load == nil {
		return nil, apierr.New(apierr.Internal, "no credential loader configured for hoist sessions", "use seed login, or configure a credential source")
	}
	if (len(m.opts.HostMap) > 0 || len(spec.HostMap) > 0) && !m.opts.Test {
		return nil, apierr.New(apierr.Internal, "host_map is refused outside test mode", "")
	}
	if spec.TTL <= 0 {
		spec.TTL = DefaultTTL
	}
	s, err := newSession(m, spec)
	if err != nil {
		return nil, err
	}
	if err := s.start(ctx); err != nil {
		s.shutdown(context.Background(), "open failed")
		return nil, err
	}
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.order = append(m.order, s.ID)
	m.mu.Unlock()
	s.emit(SessionEvent{Type: "open", Detail: s.red.String(s.startURL)})
	// Expire on TTL, or when the browser dies.
	s.timer = time.AfterFunc(time.Until(s.ExpiresAt), func() { _ = m.Close(context.Background(), s.ID) })
	go func() {
		select {
		case <-s.br.Exited():
			_ = m.Close(context.Background(), s.ID)
		case <-s.done:
		}
	}()
	return s, nil
}

// Get returns an open session.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Latest returns owner's most recently opened session.
func (m *Manager) Latest(owner string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.order) - 1; i >= 0; i-- {
		if s := m.sessions[m.order[i]]; s != nil && s.owner == owner {
			return s, true
		}
	}
	return nil, false
}

// Close ends a session and deletes its profile. Closing an unknown or already
// closed session is not an error.
func (m *Manager) Close(ctx context.Context, id string) error {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	for i, o := range m.order {
		if o == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.shutdown(ctx, "closed")
}

// CloseOwner closes every session opened for a grant (revoked or expired).
func (m *Manager) CloseOwner(ctx context.Context, owner string) {
	m.mu.Lock()
	var ids []string
	for id, s := range m.sessions {
		if s.owner == owner {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	m.closeAll(ctx, ids)
}

// CloseAll closes every session.
func (m *Manager) CloseAll(ctx context.Context) {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	m.closeAll(ctx, ids)
}

func (m *Manager) closeAll(ctx context.Context, ids []string) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Close(ctx, id)
		}()
	}
	wg.Wait()
}

// Len reports the number of open sessions.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// LeakFindings lists test-mode profile assertion failures (spec 9.4): places
// where an injected secret was found in a session's profile.
func (m *Manager) LeakFindings() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]string(nil), m.leaks...)
	sort.Strings(out)
	return out
}

func (m *Manager) addLeaks(f []string) {
	if len(f) == 0 {
		return
	}
	m.mu.Lock()
	m.leaks = append(m.leaks, f...)
	m.mu.Unlock()
}

var errSessionClosed = apierr.New(apierr.NotFound, "browser session is closed", "open a new session")

func browserErr(format string, args ...any) *apierr.Error {
	return apierr.Newf(apierr.BrowserError, "", format, args...)
}

// isGone reports whether err means the target or session no longer exists.
func isGone(err error) bool {
	var ce *cdp.Error
	if errors.As(err, &ce) {
		m := strings.ToLower(ce.Message)
		return strings.Contains(m, "not found") || strings.Contains(m, "no target") || strings.Contains(m, "no session") || strings.Contains(m, "closed")
	}
	return errors.Is(err, cdp.ErrClosed)
}
