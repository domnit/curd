// Package cli implements the `curd` command line (spec section 7.3). The
// help and error text is a tested interface: curd's main user is an agent
// that cannot see the spec, so the CLI carries the mental model and every
// failure names the next action (spec 7.5).
package cli

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/apierr"
)

// Version is the curd version; override with -ldflags "-X .../cli.Version=...".
var Version = "dev"

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitDenied      = 2  // denied_*, invalid_token, auth_expired
	ExitUnreachable = 3  // the daemon cannot be reached
	ExitFetchFail   = 22 // fetch --fail with an HTTP status >= 400
)

//go:embed text/root.txt
var rootLong string

// globals are the flags every command shares.
type globals struct {
	token      string
	sessionKey string
	socket     string
	json       bool
	noPrompt   bool
}

// exitErr carries an exit code. If err is nil nothing is printed.
type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitErr) Unwrap() error { return e.err }

// Execute runs the CLI with os.Args and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

// Run executes the CLI with explicit arguments and streams.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	g := &globals{}
	root := newRoot(g)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	return report(stderr, err, g.json)
}

// report prints err and returns its exit code.
func report(w io.Writer, err error, asJSON bool) int {
	var ee *exitErr
	if errors.As(err, &ee) {
		if ee.err != nil {
			printError(w, ee.err, asJSON)
		}
		return ee.code
	}
	printError(w, err, asJSON)
	return codeFor(err)
}

// codeFor maps an error to an exit code.
func codeFor(err error) int {
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		return ExitError
	}
	switch {
	case ae.Code == apierr.DaemonDown:
		return ExitUnreachable
	case strings.HasPrefix(ae.Code, "denied_"), ae.Code == apierr.InvalidToken, ae.Code == apierr.AuthExpired:
		return ExitDenied
	}
	return ExitError
}

// printError writes "curd: <code>: <message>" and "hint: <hint>", or the
// error object as JSON.
func printError(w io.Writer, err error, asJSON bool) {
	var ae *apierr.Error
	if !errors.As(err, &ae) {
		ae = &apierr.Error{Code: "error", Message: err.Error()}
		if strings.HasPrefix(err.Error(), "unknown command") || strings.HasPrefix(err.Error(), "unknown flag") ||
			strings.HasPrefix(err.Error(), "unknown shorthand flag") || strings.Contains(err.Error(), "required flag") {
			ae.Hint = "run `curd --help` or `curd <command> --help` for usage"
		}
	}
	if asJSON {
		b, _ := json.Marshal(ae)
		fmt.Fprintln(w, string(b))
		return
	}
	if ae.Code == "error" {
		fmt.Fprintf(w, "curd: %s\n", ae.Message)
	} else {
		fmt.Fprintf(w, "curd: %s: %s\n", ae.Code, ae.Message)
	}
	if ae.Hint != "" {
		fmt.Fprintf(w, "hint: %s\n", ae.Hint)
	}
}

func newRoot(g *globals) *cobra.Command {
	root := &cobra.Command{
		Use:           "curd",
		Short:         "Use your browser logins from scripts and agents without ever seeing the credentials",
		Long:          strings.TrimSpace(rootLong),
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("curd {{.Version}}\n")
	pf := root.PersistentFlags()
	pf.StringVar(&g.token, "token", "", "session token (crd_...) to use; default $CURD_TOKEN")
	pf.StringVar(&g.sessionKey, "session-key", "", "label that groups calls into one session for grant reuse; default $CURD_SESSION_KEY, else the git repo root or tty")
	pf.StringVar(&g.socket, "socket", "", "daemon socket path; default $CURD_SOCKET, else ~/.local/run/curd.sock")
	pf.BoolVar(&g.json, "json", false, "machine-readable JSON output (errors too)")
	pf.BoolVar(&g.noPrompt, "no-prompt", false, "never open a consent dialog; fail with denied_no_grant instead")

	for _, c := range []*cobra.Command{
		newFetchCmd(g), newGrantsCmd(g), newPoliciesCmd(g), newAuditCmd(g),
		newStatusCmd(g), newDaemonCmd(g), newRunCmd(g), newSetupCmd(g), newGuideCmd(),
		newSessionCmd(g), newBrowseCmd(g), newDistillCmd(g), newTestEnvCmd(g),
	} {
		root.AddCommand(c)
	}
	return root
}
