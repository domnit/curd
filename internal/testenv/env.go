// Package testenv implements `curd test-env` (spec 15.7): it builds
// fixtures, starts the mock upstream and a test-mode daemon in the
// background, and tears everything down again.
package testenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/daemon"
	"github.com/domnit/curd/internal/fixture"
	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/rpc"
	"github.com/domnit/curd/internal/source"
)

// EnvTestDir is the environment variable naming the default test root.
const EnvTestDir = "CURD_TEST_DIR"

// Fixture kinds.
const (
	FixtureStatic = "static"
	FixtureChrome = "chrome"
)

// maxSocketPath is a conservative limit for unix socket paths (104 on macOS,
// 108 on Linux); curd needs some slack for a temp name next to the socket.
const maxSocketPath = 90

const startTimeout = 15 * time.Second

// UpOptions configures Up.
type UpOptions struct {
	// Dir is the test root. Default: $CURD_TEST_DIR, else
	// <tmp>/curd-test-<uid>.
	Dir string
	// Consent is allow-all (default), deny-all or script:<file>.
	Consent string
	// Fixture is static (default) or chrome.
	Fixture string
	// Exe is the curd binary used for the background processes. Default:
	// the running executable.
	Exe string
}

// Env describes a running test environment.
type Env struct {
	Dir        string
	Socket     string
	TLSPort    int
	HTTPPort   int
	ControlURL string
	DaemonPID  int
	MockPID    int
}

// DefaultDir returns the default test root.
func DefaultDir() string {
	if d := os.Getenv(EnvTestDir); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("curd-test-%d", os.Getuid()))
}

// Vars returns the environment variables a client needs, in print order.
func (e *Env) Vars() [][2]string {
	return [][2]string{
		{config.EnvSocket, e.Socket},
		{EnvTestDir, e.Dir},
		{"CURD_TEST_BASE", fmt.Sprintf("https://%s:%d", mockup.HostApp, e.TLSPort)},
		{"CURD_TEST_API", fmt.Sprintf("https://%s:%d", mockup.HostAPI, e.TLSPort)},
		{"CURD_TEST_CONTROL", e.ControlURL},
		{config.EnvNoAutostart, "1"},
	}
}

// Lines renders Vars as KEY=VALUE lines.
func (e *Env) Lines() string {
	var b strings.Builder
	for _, kv := range e.Vars() {
		b.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	return b.String()
}

func (o *UpOptions) defaults() error {
	if o.Dir == "" {
		o.Dir = DefaultDir()
	}
	abs, err := filepath.Abs(o.Dir)
	if err != nil {
		return err
	}
	o.Dir = abs
	if o.Consent == "" {
		o.Consent = "allow-all"
	}
	if p, ok := strings.CutPrefix(o.Consent, "script:"); ok {
		a, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		o.Consent = "script:" + a
	}
	if _, err := consent.NewScripted(o.Consent); err != nil {
		return err
	}
	switch o.Fixture {
	case "":
		o.Fixture = FixtureStatic
	case FixtureStatic, FixtureChrome:
	default:
		return fmt.Errorf("unknown fixture %q (want static or chrome)", o.Fixture)
	}
	if o.Exe == "" {
		if o.Exe, err = os.Executable(); err != nil {
			return err
		}
	}
	return nil
}

// Up builds the fixtures and starts the mock upstream and the test daemon.
func Up(ctx context.Context, o UpOptions) (env *Env, err error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	paths := config.TestPaths(o.Dir)
	if len(paths.Socket) > maxSocketPath {
		return nil, fmt.Errorf("test dir %s is too long for a unix socket path; pass a shorter --dir", o.Dir)
	}
	if _, err := os.Stat(filepath.Join(o.Dir, "testenv.yaml")); err == nil {
		if c, err := net.Dial("unix", paths.Socket); err == nil {
			c.Close()
			return nil, fmt.Errorf("a test environment is already running in %s; stop it with `curd test-env down --dir %s`", o.Dir, o.Dir)
		}
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}

	var started []*proc
	defer func() {
		if err != nil {
			for _, p := range started {
				p.kill()
			}
		}
	}()

	// Mock upstream.
	infoPath := filepath.Join(o.Dir, "mockup.json")
	_ = os.Remove(infoPath)
	mock, err := startProc(o.Exe, []string{"test-env", "mockup", "--info", infoPath, "--cert-dir", o.Dir}, filepath.Join(o.Dir, "mockup.log"), o.Dir)
	if err != nil {
		return nil, fmt.Errorf("start mock upstream: %w", err)
	}
	started = append(started, mock)
	var info mockup.Info
	if err := waitFor(ctx, startTimeout, mock, func() bool {
		in, err := mockup.ReadInfo(infoPath)
		if err != nil || in.TLSPort == 0 {
			return false
		}
		info = in
		return true
	}); err != nil {
		return nil, fmt.Errorf("mock upstream did not start: %w\n%s", err, tailLog(filepath.Join(o.Dir, "mockup.log")))
	}

	if err := WritePolicies(paths.PolicyDir, info.TLSPort); err != nil {
		return nil, err
	}

	tc := &daemon.TestConfig{
		Dir: o.Dir, Consent: o.Consent, CACert: filepath.Join(o.Dir, "cert.pem"),
	}
	switch o.Fixture {
	case FixtureStatic:
		file := filepath.Join(o.Dir, "fixture.yaml")
		if err := source.WriteStaticFile(file, StaticFixture(info.TLSPort)); err != nil {
			return nil, err
		}
		tc.Source = daemon.TestSource{Kind: daemon.SourceStatic, File: file}
	case FixtureChrome:
		bin, err := chrome.FindBinary()
		if err != nil {
			return nil, fmt.Errorf("--fixture chrome needs a Chrome or Chromium binary: %w", err)
		}
		profile := filepath.Join(o.Dir, "chrome-profile")
		err = fixture.BuildChromeProfile(ctx, fixture.BuildOptions{
			Binary: bin, UserDataDir: profile,
			Cookies: FixtureCookies(), LocalStorage: FixtureLocalStorage(info.TLSPort),
		})
		if err != nil {
			return nil, fmt.Errorf("build Chrome fixture profile: %w", err)
		}
		tc.ChromeBinary = bin
		tc.Source = daemon.TestSource{Kind: daemon.SourceChrome, UserDataDir: profile, KeyProvider: "mock"}
	}
	cfgPath := filepath.Join(o.Dir, "testenv.yaml")
	if err := tc.Write(cfgPath); err != nil {
		return nil, err
	}

	dm, err := startProc(o.Exe, []string{"daemon", "--test", "--test-config", cfgPath}, filepath.Join(o.Dir, "daemon.log"), o.Dir)
	if err != nil {
		return nil, fmt.Errorf("start test daemon: %w", err)
	}
	started = append(started, dm)
	if err := waitFor(ctx, startTimeout, dm, func() bool {
		c, err := net.Dial("unix", paths.Socket)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}); err != nil {
		return nil, fmt.Errorf("test daemon did not start: %w\n%s", err, tailLog(filepath.Join(o.Dir, "daemon.log")))
	}
	if err := os.WriteFile(filepath.Join(o.Dir, "daemon.pid"), []byte(strconv.Itoa(dm.pid)), 0o600); err != nil {
		return nil, err
	}

	env = &Env{
		Dir: o.Dir, Socket: paths.Socket, TLSPort: info.TLSPort, HTTPPort: info.HTTPPort,
		ControlURL: info.ControlURL, DaemonPID: dm.pid, MockPID: mock.pid,
	}
	if err := os.WriteFile(filepath.Join(o.Dir, "env"), []byte(env.Lines()), 0o600); err != nil {
		return nil, err
	}
	return env, nil
}

// Down stops the test daemon and the mock upstream and deletes dir. It
// refuses to delete a directory that Up did not set up.
func Down(dir string) error {
	if dir == "" {
		dir = DefaultDir()
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "testenv.yaml")); err != nil {
		return fmt.Errorf("%s is not a curd test environment (no testenv.yaml); nothing removed", dir)
	}
	paths := config.TestPaths(dir)

	// Ask the daemon to stop gracefully (zeroes credentials, closes audit).
	if c, err := rpc.Dial(paths.Socket); err == nil {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.Call(cctx, "shutdown", nil, nil)
		cancel()
		c.Close()
	}
	if pid := readPID(filepath.Join(dir, "daemon.pid")); pid > 0 {
		if !waitGone(pid, 5*time.Second) {
			signal(pid, sigKill)
			waitGone(pid, 2*time.Second)
		}
	}
	if in, err := mockup.ReadInfo(filepath.Join(dir, "mockup.json")); err == nil && in.PID > 0 {
		signal(in.PID, sigTerm)
		if !waitGone(in.PID, 5*time.Second) {
			signal(in.PID, sigKill)
			waitGone(in.PID, 2*time.Second)
		}
	}
	return os.RemoveAll(dir)
}

// ConsentFailures asks the test daemon for scripted-consent violations.
func ConsentFailures(socket string) (daemon.ConsentFailuresResult, error) {
	var res daemon.ConsentFailuresResult
	c, err := rpc.Dial(socket)
	if err != nil {
		return res, err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return res, c.Call(ctx, daemon.MethodTestConsentFailures, nil, &res)
}

// Run does Up, runs argv with the test environment, then Down. It returns the
// command's exit status; scripted-consent violations turn a zero status into
// 1 and are printed to stderr.
func Run(ctx context.Context, o UpOptions, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(argv) == 0 {
		return 1, errors.New("no command given: curd test-env run [flags] -- <command...>")
	}
	env, err := Up(ctx, o)
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := Down(env.Dir); err != nil {
			fmt.Fprintf(stderr, "curd: test-env: teardown: %v\n", err)
		}
	}()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = childEnv(os.Environ(), env)
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
			if code < 0 {
				code = 128 + 9 // killed by a signal
			}
		} else {
			return 1, fmt.Errorf("run %s: %w", argv[0], err)
		}
	}
	if res, err := ConsentFailures(env.Socket); err == nil {
		if len(res.Failures) > 0 {
			fmt.Fprintln(stderr, "curd: test-env: the consent script was violated:")
			for _, f := range res.Failures {
				fmt.Fprintln(stderr, "  - "+f)
			}
		}
		if len(res.Leaks) > 0 {
			fmt.Fprintln(stderr, "curd: test-env: a credential leaked into a browser profile (spec 9.4):")
			for _, f := range res.Leaks {
				fmt.Fprintln(stderr, "  - "+f)
			}
		}
		if (len(res.Failures) > 0 || len(res.Leaks) > 0) && code == 0 {
			code = 1
		}
	}
	return code, nil
}

// childEnv adds the test variables to base and drops CURD_TOKEN, which
// belongs to some other daemon.
func childEnv(base []string, env *Env) []string {
	drop := map[string]bool{config.EnvToken: true}
	set := map[string]bool{}
	for _, kv := range env.Vars() {
		drop[kv[0]] = true
		set[kv[0]] = true
	}
	out := make([]string, 0, len(base)+len(set))
	for _, e := range base {
		k, _, _ := strings.Cut(e, "=")
		if !drop[k] {
			out = append(out, e)
		}
	}
	for _, kv := range env.Vars() {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func waitGone(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return !alive(pid)
}

// proc is a background child process.
type proc struct {
	cmd  *exec.Cmd
	pid  int
	done chan struct{}
}

func startProc(exe string, args []string, logPath, dir string) (*proc, error) {
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Env = append(os.Environ(), config.EnvNoAutostart+"=1")
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{cmd: cmd, pid: cmd.Process.Pid, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *proc) kill() {
	signal(p.pid, sigKill)
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
	}
}

// waitFor polls ready until it returns true, p exits or the timeout passes.
func waitFor(ctx context.Context, timeout time.Duration, p *proc, ready func() bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if ready() {
			return nil
		}
		select {
		case <-p.done:
			return errors.New("the process exited")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
	}
}

func tailLog(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return "--- " + filepath.Base(path) + " ---\n" + strings.Join(lines, "\n")
}
