package daemon

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/rpc"
)

// MethodTestConsentFailures is a test-mode-only RPC reporting scripted
// consent violations (unexpected or mismatched prompts).
const MethodTestConsentFailures = "test.consent_failures"

// ConsentFailuresResult is the result of MethodTestConsentFailures.
type ConsentFailuresResult struct {
	Failures  []string `json:"failures"`
	Remaining int      `json:"remaining"` // scripted prompts never asked
	// Leaks lists browser-profile assertion failures (spec 9.4): an injected
	// credential found in a session's profile. Asking closes every open
	// browser session first so their profiles are scanned.
	Leaks []string `json:"leaks"`
}

func (d *Daemon) registerBuiltins() {
	d.registerFetchHandlers()
	d.registerGrantHandlers()
	d.registerPolicyHandlers()
	d.register(api.MethodStatus, d.handleStatus)
	d.register(api.MethodAuditTail, d.handleAuditTail)
	d.register(api.MethodShutdown, d.handleShutdown)
	d.registerBrowser()
	if d.scripted != nil {
		d.register(MethodTestConsentFailures, func(ctx context.Context, _ rpc.Peer, _ json.RawMessage) (any, error) {
			f := d.scripted.Failures()
			if f == nil {
				f = []string{}
			}
			d.bs.mgr.CloseAll(ctx)
			leaks := d.bs.mgr.LeakFindings()
			if leaks == nil {
				leaks = []string{}
			}
			return ConsentFailuresResult{Failures: f, Remaining: d.scripted.Remaining(), Leaks: leaks}, nil
		})
	}
}

func (d *Daemon) handleStatus(context.Context, rpc.Peer, json.RawMessage) (any, error) {
	d.mu.Lock()
	counter := d.sessionCount
	started := d.started
	d.mu.Unlock()
	sessions := 0
	if counter != nil {
		sessions = counter()
	}
	d.grants.Sweep()
	srcs := d.sources.Status()
	if srcs == nil {
		srcs = []api.SourceStatus{}
	}
	return api.StatusResult{
		Version: d.cfg.Version, Mode: string(d.cfg.Mode), PID: os.Getpid(), Socket: d.cfg.Paths.Socket,
		Started: started, Policies: d.policies.current().statuses, Sources: srcs,
		Grants: d.grants.Len(), Sessions: sessions, Keychain: d.cfg.KeychainMode,
	}, nil
}

func (d *Daemon) handleAuditTail(_ context.Context, _ rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.AuditTailParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.N <= 0 {
		p.N = 20
	}
	recs, err := d.audit.Tail(p.N)
	if err != nil {
		return nil, apierr.New(apierr.Internal, err.Error(), "")
	}
	return api.AuditTailResult{Records: recs}, nil
}

// handleShutdown stops the daemon. Test mode stops unprompted. Production
// currently only audits the request (with the caller's pid and exe, tagged
// "unconfirmed"): a native confirmation needs a new consent.Kind, which the
// consent package does not have yet. d.cfg.Mode is fixed at startup, so
// callers cannot pick the path.
func (d *Daemon) handleShutdown(ctx context.Context, peer rpc.Peer, _ json.RawMessage) (any, error) {
	rec := audit.Record{Event: "shutdown", ClientPID: peer.PID, ClientExe: peer.Exe, Decision: "allow"}
	if !d.Test() {
		// Stopping the daemon lets the caller restart it with a different
		// environment, so the user confirms it.
		cl := clientOf(peer)
		ans, err := d.prompter.Ask(ctx, consent.Prompt{Kind: consent.KindShutdown, ClientName: cl.Name, ClientPID: cl.PID})
		if err != nil || ans != consent.Approve {
			rec.Decision, rec.Code = "deny", apierr.DeniedNoGrant
			d.writeAudit(rec)
			return nil, apierr.New(apierr.DeniedNoGrant, "the user declined to stop the daemon",
				"ask the user to stop it, or leave it running; grants and sessions end with it")
		}
		d.log.Printf("shutdown confirmed for pid %d (%s)", peer.PID, peer.Exe)
	}
	d.writeAudit(rec)
	// Let the response reach the client before the connections are closed.
	d.mu.Lock()
	d.shutdownTimer = time.AfterFunc(100*time.Millisecond, d.Stop)
	d.mu.Unlock()
	return map[string]bool{"ok": true}, nil
}
