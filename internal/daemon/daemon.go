// Package daemon wires curd's long-lived process: the unix-socket RPC
// server, grants, consent, policies, credential sources, the fetch broker
// and the audit log (spec sections 4 to 12 and 15).
//
// Method handlers live in separate files (fetch.go, grants.go, policies.go,
// status.go, browser.go, distill.go). Other components can plug in through
// Register, OnShutdown and OnGrantRevoked.
package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/broker"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/grants"
	"github.com/domnit/curd/internal/rpc"
	"github.com/domnit/curd/internal/source"
)

// fallbackVersion is used to build a User-Agent when the installed Chrome's
// version cannot be determined.
const fallbackVersion = "146"

// sweepInterval is how often expired grants are dropped.
const sweepInterval = 30 * time.Second

// Daemon is one curd instance. Create it with New and serve with Run.
type Daemon struct {
	cfg     Config
	log     Logger
	started time.Time

	srv       *rpc.Server
	audit     *audit.Log
	grants    *grants.Store
	policies  *policyStore
	src       creds.Source
	sources   *source.Manager
	broker    *broker.Broker
	prompter  consent.Prompter
	scripted  *consent.Scripted // non-nil in test mode
	userAgent string

	prompts promptGroup
	bs      *browserState // browser sessions, capture and drafts

	mu            sync.Mutex
	onShutdown    []func()
	onRevoked     []func(*grants.Grant)
	sessionCount  func() int
	cancel        context.CancelFunc
	ran           bool
	shutdownTimer *time.Timer
}

// New validates cfg (enforcing the test/production isolation rules), opens
// the audit log and builds every component. It does not listen yet.
func New(cfg Config) (*Daemon, error) {
	if cfg.Logger == nil {
		cfg.Logger = nopLogger{}
	}
	if cfg.Mode == config.ModeProd && cfg.KeychainMode == "" {
		uc, err := LoadUserConfig(cfg.Paths.ConfigDir)
		if err != nil {
			return nil, err
		}
		cfg.KeychainMode = uc.Keychain
	}
	if cfg.Mode == config.ModeTest && cfg.KeychainMode == "" {
		cfg.KeychainMode = "mock"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	test := cfg.Mode == config.ModeTest
	if err := cfg.Paths.EnsureDirs(); err != nil {
		return nil, fmt.Errorf("create directories: %w", err)
	}
	al, err := audit.Open(cfg.Paths.AuditLog, audit.Options{Test: test})
	if err != nil {
		return nil, err
	}
	d := &Daemon{cfg: cfg, log: cfg.Logger, audit: al, srv: rpc.NewServer()}
	ok := false
	defer func() {
		if !ok {
			al.Close()
		}
	}()

	d.policies = newPolicyStore(cfg.Paths.PolicyDir, test)
	d.grants = grants.NewStore(grants.Options{Test: test})
	d.grants.OnRevoke(d.grantEnded)

	var pool *x509.CertPool
	if test {
		tc := cfg.Test
		if tc.CACert != "" {
			pem, err := os.ReadFile(tc.CACert)
			if err != nil {
				return nil, fmt.Errorf("read test CA certificate: %w", err)
			}
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("test CA certificate %s contains no certificates", tc.CACert)
			}
		}
		if d.scripted, err = consent.NewScripted(tc.Consent); err != nil {
			return nil, err
		}
		d.prompter = d.scripted
		switch tc.Source.Kind {
		case SourceStatic:
			if _, err := source.LoadStaticFile(tc.Source.File); err != nil {
				return nil, err
			}
			d.src = source.NewStatic(tc.Source.File)
		case SourceChrome:
			d.src, err = source.NewChrome(source.ChromeOptions{
				UserDataDir: tc.Source.UserDataDir,
				Keys:        chrome.MockProvider(),
				KeyMode:     source.KeychainAlwaysAllow,
				Test:        true,
			})
			if err != nil {
				return nil, err
			}
		}
		d.userAgent = userAgentFor(tc.Source.UserDataDir, tc.ChromeBinary)
	} else {
		d.prompter = consent.NewNative()
		d.src, err = source.NewChrome(source.ChromeOptions{KeyMode: cfg.KeychainMode})
		if err != nil {
			return nil, err
		}
		bin, _ := chrome.FindBinary()
		d.userAgent = userAgentFor(chrome.DefaultUserDataDir(), bin)
	}
	d.sources = source.NewManager(d.src, source.Options{})
	d.broker = broker.New(broker.Options{
		Sources:   d.sources,
		Test:      test,
		RootCAs:   pool,
		UserAgent: d.userAgent,
	})
	d.registerBuiltins()
	ok = true
	return d, nil
}

func userAgentFor(userDataDir, binary string) string {
	v, err := chrome.Version(userDataDir, binary)
	if err != nil || v == "" {
		v = fallbackVersion
	}
	return chrome.UserAgent(v)
}

// Run serves the socket until ctx is done or a shutdown RPC arrives. On exit
// it runs the OnShutdown hooks, zeroes credentials and closes the audit log.
// A Daemon can be run once.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.ran {
		d.mu.Unlock()
		return errors.New("daemon already ran")
	}
	d.ran = true
	ctx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.started = time.Now()
	d.mu.Unlock()
	defer cancel()

	d.writeAudit(audit.Record{Event: "daemon_start", Decision: "allow"})
	go d.sweepLoop(ctx)
	if pf, ok := d.src.(interface {
		Prefetch(context.Context) error
	}); ok && d.cfg.Mode == config.ModeProd && d.cfg.KeychainMode == source.KeychainPrompt {
		go func() {
			if err := pf.Prefetch(ctx); err != nil && ctx.Err() == nil {
				d.log.Printf("keychain key prefetch failed: %v", apierrMessage(err))
			}
		}()
	}

	err := d.srv.Serve(ctx, d.cfg.Paths.Socket)
	d.shutdown()
	return err
}

// shutdown releases everything the daemon holds.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	hooks := append([]func(){}, d.onShutdown...)
	if d.shutdownTimer != nil {
		d.shutdownTimer.Stop()
	}
	d.mu.Unlock()
	for i := len(hooks) - 1; i >= 0; i-- {
		hooks[i]()
	}
	d.sources.Zero()
	d.writeAudit(audit.Record{Event: "daemon_stop", Decision: "allow"})
	d.audit.Close()
}

// Stop asks a running daemon to shut down.
func (d *Daemon) Stop() {
	d.mu.Lock()
	c := d.cancel
	d.mu.Unlock()
	if c != nil {
		c()
	}
}

func (d *Daemon) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.grants.Sweep()
		}
	}
}

// Register adds or replaces an RPC method handler. It may be called before
// or after Run starts.
func (d *Daemon) Register(method string, h rpc.Handler) { d.register(method, h) }

func (d *Daemon) register(method string, h rpc.Handler) { d.srv.Register(method, h) }

// OnShutdown registers fn to run when the daemon stops (for example to close
// browser sessions). Hooks run in reverse registration order, before
// credentials are zeroed and the audit log is closed.
func (d *Daemon) OnShutdown(fn func()) {
	d.mu.Lock()
	d.onShutdown = append(d.onShutdown, fn)
	d.mu.Unlock()
}

// OnGrantRevoked registers fn to run for every grant that ends: revoked,
// expired or consumed (once). Browser sessions use it to close themselves
// when their grant goes away. fn must not call back into the grant store
// while holding locks that the store's callers hold.
func (d *Daemon) OnGrantRevoked(fn func(*grants.Grant)) {
	d.mu.Lock()
	d.onRevoked = append(d.onRevoked, fn)
	d.mu.Unlock()
}

// SetSessionCounter lets the browser session manager report how many
// sessions are open, for status.
func (d *Daemon) SetSessionCounter(fn func() int) {
	d.mu.Lock()
	d.sessionCount = fn
	d.mu.Unlock()
}

func (d *Daemon) grantEnded(g *grants.Grant) {
	d.writeAudit(audit.Record{
		Event: "grant_end", GrantID: g.ID, TokenHash: audit.HashToken(g.Token),
		SessionKey: g.SessionKey, Policy: joinPolicies(g.Policies),
	})
	d.mu.Lock()
	hooks := append([]func(*grants.Grant){}, d.onRevoked...)
	d.mu.Unlock()
	for _, h := range hooks {
		h(g)
	}
}

// Accessors for components wired later.

// Config returns the (validated) configuration.
func (d *Daemon) Config() Config { return d.cfg }

// Test reports whether this is a test-mode instance.
func (d *Daemon) Test() bool { return d.cfg.Mode == config.ModeTest }

// Audit returns the audit log.
func (d *Daemon) Audit() *audit.Log { return d.audit }

// Grants returns the grant store.
func (d *Daemon) Grants() *grants.Store { return d.grants }

// Sources returns the credential cache.
func (d *Daemon) Sources() *source.Manager { return d.sources }

// Broker returns the fetch broker.
func (d *Daemon) Broker() *broker.Broker { return d.broker }

// Prompter returns the consent prompter (native or scripted).
func (d *Daemon) Prompter() consent.Prompter { return d.prompter }

// UserAgent returns the Chrome-matching User-Agent used for upstream requests.
func (d *Daemon) UserAgent() string { return d.userAgent }

func (d *Daemon) writeAudit(r audit.Record) {
	if err := d.audit.Write(r); err != nil {
		d.log.Printf("audit write failed: %v", err)
	}
}
