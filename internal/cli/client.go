package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/rpc"
)

// tokenValue returns the session token: --token, else $CURD_TOKEN.
func (g *globals) tokenValue() string {
	if g.token != "" {
		return g.token
	}
	return os.Getenv(config.EnvToken)
}

// socketPath returns the daemon socket this invocation talks to.
func (g *globals) socketPath() string {
	if g.socket != "" {
		return g.socket
	}
	return config.ClientSocket()
}

// autostartAllowed reports whether a missing daemon may be started: only the
// production daemon, and only when nothing points the CLI elsewhere.
func (g *globals) autostartAllowed() bool {
	return g.socket == "" && os.Getenv(config.EnvSocket) == "" && os.Getenv(config.EnvNoAutostart) == ""
}

// caller builds the identity block sent with every credentialed call.
func (g *globals) caller() api.Caller {
	key, src := resolveSessionKey(g.sessionKey)
	return api.Caller{Token: g.tokenValue(), SessionKey: key, SessionKeySource: src, NoPrompt: g.noPrompt}
}

// resolveSessionKey implements spec 6.3: $CURD_SESSION_KEY, then
// --session-key, then the git toplevel, then the controlling tty, else none
// (uid-global).
func resolveSessionKey(flag string) (key, source string) {
	if v := os.Getenv(config.EnvSessionKey); v != "" {
		return v, "env"
	}
	if flag != "" {
		return flag, "flag"
	}
	if v := gitToplevel(); v != "" {
		return v, "git"
	}
	if v := ttyName(); v != "" {
		return v, "tty"
	}
	return "", ""
}

func gitToplevel() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ttyName returns the name of the terminal one of the standard streams is
// attached to, e.g. /dev/ttys003.
func ttyName() string {
	for _, f := range []*os.File{os.Stdin, os.Stderr, os.Stdout} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, "tty")
		cmd.Stdin = f
		out, err := cmd.Output()
		cancel()
		if name := strings.TrimSpace(string(out)); err == nil && strings.HasPrefix(name, "/dev/") {
			return name
		}
	}
	return ""
}

// dial connects to the daemon, starting it if allowed and missing.
func (g *globals) dial(ctx context.Context) (*rpc.Client, error) {
	sock := g.socketPath()
	c, err := rpc.Dial(sock)
	if err == nil {
		return c, nil
	}
	if !g.autostartAllowed() {
		return nil, err
	}
	if err := startDaemon(ctx, sock); err != nil {
		return nil, err
	}
	return rpc.Dial(sock)
}

// call performs one RPC.
func (g *globals) call(ctx context.Context, method string, params, result any) error {
	c, err := g.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, method, params, result)
}

// startDaemon launches `curd daemon` detached and waits for its socket.
func startDaemon(ctx context.Context, sock string) error {
	exe, err := os.Executable()
	if err != nil {
		return apierr.Newf(apierr.DaemonDown, "start it yourself with `curd daemon`", "cannot find the curd executable to start the daemon: %v", err)
	}
	paths := config.ProdPaths()
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		return apierr.Newf(apierr.DaemonDown, "start it yourself with `curd daemon`", "cannot create %s: %v", paths.StateDir, err)
	}
	logPath := filepath.Join(paths.StateDir, "daemon.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return apierr.Newf(apierr.DaemonDown, "start it yourself with `curd daemon`", "cannot open %s: %v", logPath, err)
	}
	defer lf.Close()
	cmd := exec.Command(exe, "daemon")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, lf, lf
	detachProcess(cmd)
	if err := cmd.Start(); err != nil {
		return apierr.Newf(apierr.DaemonDown, "start it yourself with `curd daemon`", "cannot start the daemon: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := rpc.Dial(sock); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			// It may have lost a race with another autostart; check once more.
			if c, err := rpc.Dial(sock); err == nil {
				c.Close()
				return nil
			}
			return apierr.Newf(apierr.DaemonDown, "see "+logPath+" for the reason, or run `curd daemon` in a terminal",
				"the daemon exited right after starting")
		case <-time.After(50 * time.Millisecond):
		}
	}
	return apierr.New(apierr.DaemonDown, fmt.Sprintf("the daemon did not create %s within 10s", sock), "see "+logPath+", or run `curd daemon` in a terminal")
}
