package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
)

func newGrantsCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grants",
		Short: "List, request and revoke grants (what is currently authorized)",
		Long: `A grant says what is currently authorized, for whom and until when. It is created
when the user approves a consent dialog and is identified by a session token
(crd_...) and an id (gr_...).

  - Scope: read is the default; write is never implied by read and always needs
    its own approval.
  - Mode: "once" covers a single request; "session" lasts until its expiry (or
    the daemon exits) and is shared by later calls with the same session key.
  - You normally do not need these commands: "curd fetch" asks for consent on
    first use. Use them to authorize ahead of time, to hand a token to another
    process, or to revoke access.`,
	}
	cmd.AddCommand(newGrantsLsCmd(g), newGrantsRequestCmd(g), newGrantsRevokeCmd(g))
	return cmd
}

func newGrantsLsCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List active grants",
		Long: `List the active grants: id, policies, scopes, mode, session key, expiry and use
count. Tokens are never shown. With --token (or CURD_TOKEN) only that token's
grant is listed. Use --json for machine-readable output.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.GrantsListResult
			p := api.GrantsListParams{Caller: api.Caller{Token: g.tokenValue()}}
			if err := g.call(cmd.Context(), api.MethodGrantsList, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			if len(res.Grants) == 0 {
				fmt.Fprintln(out, "no active grants. The first `curd fetch` to a site asks the user; or run `curd grants request <policy>`.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tPOLICIES\tSCOPE\tMODE\tSESSION KEY\tEXPIRES\tUSES")
			for _, gi := range res.Grants {
				key := "(uid-global)"
				if gi.SessionKey != "" {
					key = gi.SessionKey
					if gi.SessionKeySource != "" {
						key += " (" + gi.SessionKeySource + ")"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", gi.ID, strings.Join(gi.Policies, ","),
					strings.Join(gi.Scopes, ","), gi.Mode, key, fmtTime(gi.ExpiresAt), gi.Uses)
			}
			return tw.Flush()
		},
	}
}

func newGrantsRequestCmd(g *globals) *cobra.Command {
	var write, once bool
	var ttl, purpose string
	cmd := &cobra.Command{
		Use:   "request <policy>... [--write] [--ttl 8h] [--once]",
		Short: "Ask the user for a grant and print its session token",
		Long: `Ask the user (native consent dialog) for access to one or more policies and
print the session token on stdout (everything else goes to stderr), so a script
can do:  export CURD_TOKEN=$(curd grants request app)

  --write   also request the write scope (a separate, explicit approval)
  --ttl     requested lifetime, e.g. 30m, 8h, 2d (default: the policy's ttl_default)
  --once    the grant covers a single request only

The grant is also reused implicitly by later calls with the same session key,
so passing the token is optional. Fails with denied_no_grant if the user says
no or --no-prompt is given.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scopes := []string{"read"}
			if write {
				scopes = append(scopes, "write")
			}
			mode := "session"
			if once {
				mode = "once"
			}
			p := api.GrantsRequestParams{Caller: g.caller(), Policies: args, Scopes: scopes, TTL: ttl, Mode: mode, Purpose: purpose}
			// An explicit request never reuses a token; it asks for a fresh grant.
			p.Token = ""
			var res api.GrantsRequestResult
			if err := g.call(cmd.Context(), api.MethodGrantsRequest, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			gi := res.Grant
			fmt.Fprintf(cmd.ErrOrStderr(), "curd: granted %s access to %s (grant %s, %s, expires %s)\n",
				strings.Join(gi.Scopes[len(gi.Scopes)-1:], ""), strings.Join(gi.Policies, ","), gi.ID, gi.Mode, fmtTime(gi.ExpiresAt))
			fmt.Fprintln(cmd.ErrOrStderr(), "curd: pass the token with --token or CURD_TOKEN; calls from the same session key also reuse the grant automatically")
			fmt.Fprintln(out, res.Token)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&write, "write", false, "also request the write scope")
	fl.BoolVar(&once, "once", false, "single-request grant")
	fl.StringVar(&ttl, "ttl", "", "requested lifetime such as 30m, 8h or 2d")
	fl.StringVar(&purpose, "purpose", "", "short reason shown in the consent dialog")
	return cmd
}

func newGrantsRevokeCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id|token|all>",
		Short: "Revoke a grant (or every grant) immediately",
		Long: `Revoke a grant by id (gr_...), by token (crd_...), or every grant with "all".
Revocation is instant: the next call that relied on the grant asks for consent
again, and any browser session opened under it is closed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.GrantsRevokeResult
			if err := g.call(cmd.Context(), api.MethodGrantsRevoke, api.GrantsRevokeParams{TokenOrID: args[0]}, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			if len(res.Revoked) == 0 {
				fmt.Fprintln(out, "no grants to revoke")
			}
			for _, id := range res.Revoked {
				fmt.Fprintf(out, "revoked %s\n", id)
			}
			return nil
		},
	}
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return apierr.New(apierr.Internal, err.Error(), "")
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
