package chrome

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/domnit/curd/internal/cdp"
)

// LaunchOptions configures Launch.
type LaunchOptions struct {
	Binary       string    // path to Chrome; FindBinary() if empty
	UserDataDir  string    // required
	Headless     bool      // --headless=new
	MockKeychain bool      // test only: fixed, publicly known cookie key (see MockProvider)
	ExtraArgs    []string  // appended after the standard flags
	Stderr       io.Writer // browser stderr; discarded if nil
}

// Browser is a running Chrome controlled over a debugging pipe.
type Browser struct {
	Conn *cdp.Conn
	Cmd  *exec.Cmd

	exited  chan struct{}
	waitErr error
}

// Launch starts Chrome with --remote-debugging-pipe (never a TCP port). The
// browser's lifetime is not tied to ctx; call Close. ctx only bounds startup.
func Launch(ctx context.Context, o LaunchOptions) (*Browser, error) {
	if o.UserDataDir == "" {
		return nil, errors.New("chrome: LaunchOptions.UserDataDir is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bin := o.Binary
	if bin == "" {
		var err error
		if bin, err = FindBinary(); err != nil {
			return nil, err
		}
	}
	args := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + o.UserDataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
		"--disable-background-networking",
		"--disable-component-update",
	}
	if o.Headless {
		args = append(args, "--headless=new")
	}
	if o.MockKeychain {
		if runtime.GOOS == "darwin" {
			args = append(args, "--use-mock-keychain")
		} else {
			args = append(args, "--password-store=basic")
		}
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		args = append(args, "--no-sandbox")
	}
	args = append(args, o.ExtraArgs...)

	// fd 3: browser reads commands; fd 4: browser writes responses.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		cmdR.Close()
		cmdW.Close()
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	cmd.Stderr = o.Stderr
	cmd.SysProcAttr = newProcessGroup()
	if err := cmd.Start(); err != nil {
		cmdR.Close()
		cmdW.Close()
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("chrome: start %s: %w", bin, err)
	}
	cmdR.Close()
	outW.Close()

	b := &Browser{Cmd: cmd, exited: make(chan struct{})}
	b.Conn = cdp.NewConn(outR, cmdW)
	go func() {
		b.waitErr = cmd.Wait()
		close(b.exited)
		b.Conn.Close()
	}()
	return b, nil
}

// Wait blocks until the browser process exits and returns its exit error.
func (b *Browser) Wait() error {
	<-b.exited
	return b.waitErr
}

// Exited is closed when the browser process has exited.
func (b *Browser) Exited() <-chan struct{} { return b.exited }

// Close asks the browser to quit (Browser.close), waits for the process to
// exit so profile data is flushed, and kills its process group if it has not
// exited when ctx ends or after 15 seconds, whichever is first.
func (b *Browser) Close(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_ = b.Conn.Call(cctx, "", "Browser.close", nil, nil)
	cancel()

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-b.exited:
		killGroup(b.Cmd)
		return nil
	case <-timer.C:
	case <-ctx.Done():
	}
	killGroup(b.Cmd)
	<-b.exited
	return errors.New("chrome: browser did not exit cleanly; killed")
}
