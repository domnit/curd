package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/daemon"
	"github.com/domnit/curd/internal/rpc"
)

func newDaemonCmd(g *globals) *cobra.Command {
	var test bool
	var testConfig string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the long-lived curd daemon (normally started automatically)",
		Long: `Run the curd daemon in the foreground: it listens on the unix socket
(~/.local/run/curd.sock, mode 0600, same-uid peers only), holds credentials in
memory, enforces policies and grants, shows the consent dialogs and writes the
audit log. You rarely start it by hand: any command that needs it starts it
(detached, logging to ~/.local/state/curd/daemon.log) when the socket is
missing, unless CURD_SOCKET or CURD_NO_AUTOSTART is set.

Keychain: set "keychain: prompt|always-allow|strict" in ~/.config/curd/config.yaml
(default prompt: one keychain dialog per daemon start; see "curd setup").

Test mode (curd daemon --test --test-config <file>) is a separate instance with
its own socket, policies, audit log, scripted consent and synthetic
credentials; it never touches the real Chrome profile or keychain. The config
file is written by "curd test-env up". The daemon refuses a mixed
configuration at startup.

Stop it with "curd daemon stop".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := daemon.Config{Version: Version, Logger: log.New(os.Stderr, "curd daemon: ", log.LstdFlags)}
			if test {
				if testConfig == "" {
					return errors.New("test mode needs --test-config <file> (written by `curd test-env up`)")
				}
				tc, err := daemon.LoadTestConfig(testConfig)
				if err != nil {
					return err
				}
				cfg.Mode, cfg.Test, cfg.Paths = config.ModeTest, tc, config.TestPaths(tc.Dir)
			} else {
				if testConfig != "" {
					return errors.New("--test-config is only valid together with --test; the production daemon refuses test configuration")
				}
				cfg.Mode, cfg.Paths = config.ModeProd, config.ProdPaths()
			}
			d, err := daemon.New(cfg)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "curd daemon: %s mode, listening on %s\n", cfg.Mode, cfg.Paths.Socket)
			return d.Run(cmd.Context())
		},
	}
	cmd.Flags().BoolVar(&test, "test", false, "run a test-mode instance (needs --test-config)")
	cmd.Flags().StringVar(&testConfig, "test-config", "", "test-mode configuration file (YAML)")

	cmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Ask the running daemon to shut down",
		Long: `Send the daemon a shutdown request: it closes browser sessions, zeroes the
credentials it holds, closes the audit log and exits. Grants end with it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sock := g.socketPath()
			c, err := rpc.Dial(sock)
			if err != nil {
				fmt.Fprintln(cmd.OutOrStdout(), "curd daemon is not running")
				return nil
			}
			defer c.Close()
			if err := c.Call(cmd.Context(), api.MethodShutdown, nil, nil); err != nil {
				return err
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if cc, err := rpc.Dial(sock); err != nil {
					fmt.Fprintln(cmd.OutOrStdout(), "curd daemon stopped")
					return nil
				} else {
					cc.Close()
				}
				select {
				case <-cmd.Context().Done():
					return context.Canceled
				case <-time.After(50 * time.Millisecond):
				}
			}
			return errors.New("the daemon accepted the shutdown request but is still running")
		},
	})
	return cmd
}
