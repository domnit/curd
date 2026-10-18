package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"context"
	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/config"
)

func newRunCmd(g *globals) *cobra.Command {
	var policies []string
	var write bool
	var ttl string
	cmd := &cobra.Command{
		Use:   "run [--policy <name>]... [--write] [--ttl 8h] -- <command...>",
		Short: "Run a command with a pre-approved grant in CURD_TOKEN, then revoke it",
		Long: `Convenience for launching an agent or script: ask the user for a grant (the
dialog shows the command line), run the command with the session token in its
environment as CURD_TOKEN (and CURD_SOCKET if you pointed curd at a socket),
then revoke the grant when it exits. curd exits with the command's exit code.

It is not required for an agent that is already running: that agent just calls
"curd fetch" and is asked on first use.

  curd run --policy app -- ./scripts/sync.sh
  curd run --policy app --policy api --write -- make deploy

The grant is bound to the token only; other processes do not share it through
the session key.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 0 || dash >= len(args) {
				return fmt.Errorf("put the command after --, e.g. curd run --policy app -- ./script.sh")
			}
			policies = append(policies, args[:dash]...)
			argv := args[dash:]
			if len(policies) == 0 {
				return fmt.Errorf("name the policies the command may use: curd run --policy <name> -- %s (list them with `curd policies ls`)", argv[0])
			}
			scopes := []string{"read"}
			if write {
				scopes = append(scopes, "write")
			}
			var nonce [6]byte
			_, _ = rand.Read(nonce[:])
			caller := g.caller()
			caller.Token = ""
			caller.SessionKey, caller.SessionKeySource = "run:"+hex.EncodeToString(nonce[:]), "run"
			p := api.GrantsRequestParams{
				Caller: caller, Policies: policies, Scopes: scopes, TTL: ttl, Mode: "session",
				Purpose: "curd run -- " + strings.Join(argv, " "),
			}
			var res api.GrantsRequestResult
			if err := g.call(cmd.Context(), api.MethodGrantsRequest, p, &res); err != nil {
				return err
			}
			defer func() {
				rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = g.call(rctx, api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: res.Grant.ID}, nil)
			}()

			child := exec.Command(argv[0], argv[1:]...)
			child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
			if f, ok := cmd.InOrStdin().(*os.File); ok {
				child.Stdin = f
			}
			child.Env = append(os.Environ(), config.EnvToken+"="+res.Token, config.EnvSocket+"="+g.socketPath())
			if err := child.Start(); err != nil {
				return fmt.Errorf("cannot run %s: %w", argv[0], err)
			}
			sigs := make(chan os.Signal, 4)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			go func() {
				for s := range sigs {
					_ = child.Process.Signal(s)
				}
			}()
			err := child.Wait()
			signal.Stop(sigs)
			close(sigs)
			if err == nil {
				return nil
			}
			if ee, ok := err.(*exec.ExitError); ok {
				code := ee.ExitCode()
				if code < 0 {
					code = 128 + 15
					if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
						code = 128 + int(ws.Signal())
					}
				}
				return &exitErr{code: code}
			}
			return err
		},
	}
	fl := cmd.Flags()
	fl.StringArrayVarP(&policies, "policy", "p", nil, "policy the command may use (repeatable)")
	fl.BoolVar(&write, "write", false, "also request the write scope")
	fl.StringVar(&ttl, "ttl", "", "grant lifetime such as 30m or 8h (default: the policies' ttl_default)")
	return cmd
}
