package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/testenv"
)

func newTestEnvCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test-env",
		Short: "Run curd against synthetic credentials and a mock upstream (no real profile, keychain or dialogs)",
		Long: `Test mode runs curd end to end with no real Chrome profile, no keychain, no real
logins and no human at the consent dialog. It is for developing and testing
policies, scripts and skills, and for CI.

  curd test-env up [--dir D] [--consent allow-all|deny-all|script:F] [--fixture static|chrome]
  curd test-env down [--dir D]
  curd test-env run [up flags] -- <command...>

"up" writes sample policies, starts a mock upstream (https://app.example.com:PORT
and https://api.example.com:PORT, mapped to 127.0.0.1) that records every request,
builds a fixture credential set, and starts a separate test daemon (own socket,
policies and audit log; scripted consent; audit records tagged test). It prints
the environment to use, one KEY=VALUE per line:

  CURD_SOCKET          the test daemon's socket (all curd commands pick it up)
  CURD_TEST_DIR        the test root (policies/, state/audit.jsonl, daemon.log)
  CURD_TEST_BASE       https://app.example.com:PORT  (cookie-authenticated site)
  CURD_TEST_API        https://api.example.com:PORT  (bearer token from localStorage)
  CURD_TEST_CONTROL    the mock's control URL: GET /requests lists what it saw
  CURD_NO_AUTOSTART=1  never start a production daemon

Use it like:  export $(curd test-env up) ; curd fetch "$CURD_TEST_BASE/api/me"

"run" does up, runs your command with that environment, then down, and exits
with the command's status (non-zero if the consent script was violated).

Consent: allow-all approves every prompt for a session, deny-all denies all, and
script:<file> answers prompts in order and fails the run on an unexpected one:

  prompts:
    - expect: {kind: grant, policies: [app], scope: read}
      answer: session          # once | session | deny | approve

The test daemon refuses real profiles and keychains, and the production daemon
refuses test configuration.`,
	}
	var o testenv.UpOptions
	addUpFlags := func(c *cobra.Command) {
		c.Flags().StringVar(&o.Dir, "dir", "", "test root (default $CURD_TEST_DIR or <tmp>/curd-test-<uid>)")
		c.Flags().StringVar(&o.Consent, "consent", "allow-all", "allow-all, deny-all or script:<file>")
		c.Flags().StringVar(&o.Fixture, "fixture", "static", "credential source: static (fast) or chrome (a Chrome-made profile; needs Chrome/Chromium)")
	}
	up := &cobra.Command{
		Use:   "up [--dir D] [--consent MODE] [--fixture static|chrome]",
		Short: "Start the mock upstream and a test daemon; print the environment",
		Long:  `Start the test environment in the background (see "curd test-env --help") and print the KEY=VALUE environment lines, also saved in <dir>/env.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := testenv.Up(cmd.Context(), o)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), env.Lines())
			fmt.Fprintf(cmd.ErrOrStderr(), "curd: test environment up in %s; stop it with `curd test-env down --dir %s`\n", env.Dir, env.Dir)
			return nil
		},
	}
	addUpFlags(up)

	var downDir string
	down := &cobra.Command{
		Use:   "down [--dir D]",
		Short: "Stop the test daemon and mock upstream and delete the test directory",
		Long:  `Ask the test daemon to shut down, stop the mock upstream and delete the test directory (only if "up" created it).`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := testenv.Down(downDir); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "test environment removed")
			return nil
		},
	}
	down.Flags().StringVar(&downDir, "dir", "", "test root (default $CURD_TEST_DIR or <tmp>/curd-test-<uid>)")

	run := &cobra.Command{
		Use:   "run [up flags] -- <command...>",
		Short: "up, run a command with the test environment, then down",
		Long: `Start the test environment, run the command with CURD_SOCKET and the other
variables set, tear everything down and exit with the command's status. If the
consent script was violated the failures are printed and the exit status is
non-zero. This is the entry point for CI and for agents.

  curd test-env run -- sh -c 'curd fetch "$CURD_TEST_BASE/api/me"'`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 0 || dash >= len(args) {
				return errors.New("put the command after --, e.g. curd test-env run -- sh -c 'curd status'")
			}
			code, err := testenv.Run(cmd.Context(), o, args[dash:], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if code != 0 {
				return &exitErr{code: code}
			}
			return nil
		},
	}
	addUpFlags(run)

	mock := &cobra.Command{
		Use:                "mockup",
		Hidden:             true,
		Short:              "internal: run the mock upstream in the foreground",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if code := mockup.Main(args); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.AddCommand(up, down, run, mock)
	return cmd
}
