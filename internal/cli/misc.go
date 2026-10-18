package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
)

func newAuditCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the audit log",
		Long: `Every request, consent outcome and grant change is logged to
~/.local/state/curd/audit.jsonl: time, client pid and executable, grant id,
policy, method, host, path (query redacted), decision, status, bytes and
duration. Headers, bodies, cookies and token values are never logged.`,
	}
	var n int
	tail := &cobra.Command{
		Use:   "tail [-n 20]",
		Short: "Show the most recent audit records",
		Long: `Show the last N audit records, oldest first, one per line. With --json each
line is the raw JSON record.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.AuditTailResult
			if err := g.call(cmd.Context(), api.MethodAuditTail, api.AuditTailParams{N: n}, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, r := range res.Records {
				if g.json {
					if err := writeJSON(out, r); err != nil {
						return err
					}
					continue
				}
				fmt.Fprintln(out, formatAudit(r))
			}
			return nil
		},
	}
	tail.Flags().IntVarP(&n, "lines", "n", 20, "number of records")
	cmd.AddCommand(tail)
	return cmd
}

func formatAudit(r map[string]any) string {
	s := func(k string) string {
		if v, ok := r[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	parts := []string{s("ts"), s("event")}
	if d := s("decision"); d != "" {
		parts = append(parts, d)
	}
	for _, k := range []string{"policy", "method", "host", "path", "verb"} {
		if v := s(k); v != "" {
			parts = append(parts, v)
		}
	}
	if v := s("status"); v != "" {
		parts = append(parts, "status="+v)
	}
	if v := s("code"); v != "" {
		parts = append(parts, "code="+v)
	}
	if v := s("grant_id"); v != "" {
		parts = append(parts, "grant="+v)
	}
	if v := s("duration_ms"); v != "" {
		parts = append(parts, v+"ms")
	}
	if v := s("tags"); v != "" {
		parts = append(parts, v)
	}
	if r["test"] == true {
		parts = append(parts, "[test]")
	}
	return strings.Join(parts, " ")
}

func newStatusCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon health, policies, sources and grants",
		Long: `Show the running daemon: mode (prod or test), pid, socket, keychain mode,
policies with their status, credential source health (counts only, never
values) and the number of grants and browser sessions. Starts the daemon if it
is not running (production only).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.StatusResult
			if err := g.call(cmd.Context(), api.MethodStatus, nil, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			fmt.Fprintf(out, "curd daemon %s (%s mode), pid %d, started %s\n", res.Version, res.Mode, res.PID, fmtTime(res.Started))
			fmt.Fprintf(out, "socket:   %s\n", res.Socket)
			if res.Keychain != "" {
				fmt.Fprintf(out, "keychain: %s\n", res.Keychain)
			}
			fmt.Fprintf(out, "grants:   %d active, %d browser sessions\n", res.Grants, res.Sessions)
			active := 0
			for _, p := range res.Policies {
				if p.Status == "active" {
					active++
				}
			}
			fmt.Fprintf(out, "policies: %d (%d active)\n", len(res.Policies), active)
			sort.Slice(res.Policies, func(i, j int) bool { return res.Policies[i].Name < res.Policies[j].Name })
			for _, p := range res.Policies {
				line := fmt.Sprintf("  %s [%s] %s", p.Name, p.Status, strings.Join(p.Hosts, ", "))
				if p.Error != "" {
					line += " - " + p.Error
				}
				fmt.Fprintln(out, line)
			}
			for _, s := range res.Sources {
				state := "ok"
				if !s.OK {
					state = "error: " + s.Error
				}
				fmt.Fprintf(out, "source %s: %s (%d cookies, %d localStorage items, loaded %s)\n", s.Name, state, s.Cookies, s.LocalStorage, fmtTime(s.LastLoad))
			}
			if len(res.Sources) == 0 {
				fmt.Fprintln(out, "sources:  none loaded yet (credentials are read on first use)")
			}
			return nil
		},
	}
}
