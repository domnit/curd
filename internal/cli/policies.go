package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/policy"
)

func newPoliciesCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "List, show, create, validate and approve site policies",
		Long: `A policy is a YAML file per site that says what is possible: which hosts it
covers, which cookies / localStorage tokens are used, and which methods and
paths are allowed (with optional body inspectors such as graphql_query_only).
Policies live in ~/.config/curd/policies/<name>.yaml and are reloaded when the
files change, so there is nothing to restart.

  curd policies ls                       what exists, and the allowed requests
  curd policies show <name>              the policy file
  curd policies new <name> --host <h>    write a read-only starter template
  curd policies validate <file>          check a file before relying on it
  curd policies approve <name>           activate a draft (the user confirms)

Drafts (<name>.draft.yaml, status: draft) are what "curd distill" produces.
They are inert until "curd policies approve" and a native confirmation.`,
	}
	cmd.AddCommand(newPoliciesLsCmd(g), newPoliciesShowCmd(g), newPoliciesNewCmd(g), newPoliciesValidateCmd(), newPoliciesApproveCmd(g))
	return cmd
}

func newPoliciesLsCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List policies, their hosts and allowed requests",
		Long: `List every policy: name, status (active, draft or error), the hosts it covers
and its allow rules ("GET,HEAD ^/api/.* [read]"). A policy marked [write]
needs a write grant. Policies that fail to load show the error. Start here to
orient yourself before fetching.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.PoliciesListResult
			if err := g.call(cmd.Context(), api.MethodPoliciesList, nil, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			if len(res.Policies) == 0 {
				fmt.Fprintln(out, "no policies yet. Create one with `curd policies new <name> --host <host>`, edit it, then `curd fetch <name> <url>`.")
				return nil
			}
			for _, p := range res.Policies {
				fmt.Fprintf(out, "%s  [%s]  %s\n", p.Name, p.Status, strings.Join(p.Hosts, ", "))
				for _, r := range p.Rules {
					fmt.Fprintf(out, "    allow %s\n", r)
				}
				if p.Error != "" {
					fmt.Fprintf(out, "    error: %s\n", p.Error)
				}
				if p.Status == policy.StatusDraft {
					fmt.Fprintf(out, "    inert until approved: curd policies approve %s\n", p.Name)
				}
			}
			return nil
		},
	}
}

func newPoliciesShowCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Print a policy file",
		Long:  `Print the YAML of a policy (active, draft or broken) with its status. With --json, the status and YAML are returned as an object.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.PoliciesShowResult
			if err := g.call(cmd.Context(), api.MethodPoliciesShow, api.PoliciesShowParams{Name: args[0]}, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			fmt.Fprintf(out, "# %s [%s] %s\n", res.Status.Name, res.Status.Status, res.Status.File)
			if res.Status.Error != "" {
				fmt.Fprintf(out, "# error: %s\n", res.Status.Error)
			}
			fmt.Fprint(out, res.YAML)
			if !strings.HasSuffix(res.YAML, "\n") {
				fmt.Fprintln(out)
			}
			return nil
		},
	}
}

var policyNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// policyDirFor returns where the daemon the CLI talks to keeps its policies.
func policyDirFor(g *globals) string {
	sock := g.socketPath()
	if filepath.Base(sock) == "curd-test.sock" {
		return config.TestPaths(filepath.Dir(sock)).PolicyDir
	}
	return config.ProdPaths().PolicyDir
}

func policyTemplate(name string, hosts []string) string {
	first := strings.TrimPrefix(hosts[0], "*.")
	quoted := make([]string, len(hosts))
	for i, h := range hosts {
		quoted[i] = "'" + h + "'"
	}
	return fmt.Sprintf(`# curd policy for %[3]s.
# This is a read-only starter: it allows GET and HEAD under /. Tighten the
# paths to what you actually need, then check it with `+"`curd policies validate`"+`.
# Changes take effect immediately; no restart needed.
name: %[1]s
match:
  hosts: [%[2]s]          # exact hostnames or explicit wildcards such as '*.example.com'
credentials:
  # Which of the user's Chrome cookies may be sent (names or globs).
  # Default when omitted: every cookie that matches the host.
  # cookies: [session, '__Host-*']
  # Tokens kept in localStorage can be sent as a header:
  # local_storage:
  #   - origin: https://%[4]s
  #     keys: [authToken]
  #     inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET, HEAD]       # read scope (the default grant)
    paths: ['^/.*$']           # regexps over the URL path, anchored with ^ and $
  # Writes need their own rule and a separate write grant. Example:
  # - methods: [POST]
  #   paths: ['^/api/upload$']
  #   scope: write
  # GraphQL endpoints tunnel everything through one POST; allow only queries:
  # - methods: [POST]
  #   paths: ['^/graphql$']
  #   inspect: graphql_query_only
request:
  header_allowlist: [accept, content-type]   # other caller headers are dropped
  max_body_bytes: 1048576
response:
  max_body_bytes: 10485760
redirects: same-host-only      # none | same-host-only | policy-hosts
ttl_default: 8h                # default grant lifetime
`, name, strings.Join(quoted, ", "), strings.Join(hosts, ", "), first)
}

func newPoliciesNewCmd(g *globals) *cobra.Command {
	var hosts []string
	var dir string
	cmd := &cobra.Command{
		Use:   "new <name> --host <host> [--host <host>...]",
		Short: "Write a read-only starter policy and print its path",
		Long: `Create <policy dir>/<name>.yaml from a commented template that allows GET and
HEAD only, and print its path. Edit it to tighten the paths (and add rules for
writes if you need them), check it with "curd policies validate <file>", then
use it: "curd fetch <name> <url>". Refuses to overwrite an existing file.

Hosts are exact ("app.example.com") or explicit wildcards ("*.example.com");
a wildcard does not match the bare domain.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !policyNameOK.MatchString(name) {
				return fmt.Errorf("invalid policy name %q: use letters, digits, '-' and '_'", name)
			}
			if len(hosts) == 0 {
				return errors.New("at least one --host is required, e.g. curd policies new " + name + " --host app.example.com")
			}
			if dir == "" {
				dir = policyDirFor(g)
			}
			data := policyTemplate(name, hosts)
			path := filepath.Join(dir, name+".yaml")
			if _, err := policy.Parse([]byte(data), path); err != nil {
				return fmt.Errorf("the generated policy is invalid (check --host values): %w", err)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				if os.IsExist(err) {
					return fmt.Errorf("%s already exists; edit it, or pick another name (refusing to overwrite)", path)
				}
				return err
			}
			if _, err := f.WriteString(data); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
			fmt.Fprintf(cmd.ErrOrStderr(), "curd: wrote a read-only template. Edit it, run `curd policies validate %s`, then `curd fetch %s <url>`\n", path, name)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&hosts, "host", nil, "host the policy covers (repeatable): exact or '*.example.com'")
	cmd.Flags().StringVar(&dir, "dir", "", "policy directory (default: the daemon's)")
	return cmd
}

func newPoliciesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Check a policy file offline",
		Long: `Parse and validate a policy file without a daemon. Reports the first error, or
the policy name, hosts and rules plus any warnings (for example a path regexp
that is not anchored with ^ and $). The policy name must match the file name
(<name>.yaml or <name>.draft.yaml). Exit 1 if invalid.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			p, err := policy.Parse(data, args[0])
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ok: policy %q covers %s (%d allow rules)\n", p.Name, strings.Join(p.Match.Hosts, ", "), len(p.Allow))
			for i := range p.Allow {
				fmt.Fprintf(out, "  allow %s\n", p.Allow[i].Summary())
			}
			for _, w := range p.Warnings {
				fmt.Fprintf(out, "warning: %s\n", w)
			}
			if p.Test != nil {
				fmt.Fprintln(out, "warning: has a test: section; the production daemon refuses such a policy")
			}
			if p.IsDraft() {
				fmt.Fprintf(out, "note: this is a draft; activate it with `curd policies approve %s`\n", p.Name)
			}
			return nil
		},
	}
}

func newPoliciesApproveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "approve <name>",
		Short: "Activate a draft policy after the user confirms it",
		Long: `Turn <name>.draft.yaml into the active <name>.yaml. The daemon shows a native
confirmation dialog listing the hosts and allowed requests; only the user's
approval activates the policy (an agent cannot approve its own draft). Refuses
if an active policy with that name already exists.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var st api.PolicyStatus
			if err := g.call(cmd.Context(), api.MethodPolicyApprove, api.PolicyApproveParams{Name: args[0]}, &st); err != nil {
				return err
			}
			if g.json {
				return writeJSON(cmd.OutOrStdout(), st)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approved: policy %s is now active (%s)\n", st.Name, st.File)
			return nil
		},
	}
}
