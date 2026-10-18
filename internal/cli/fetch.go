package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
)

type fetchFlags struct {
	method     string
	headers    []string
	data       []string
	dataBinary []string
	jsonBody   string
	include    bool
	output     string
	fail       bool
	silent     bool
	write      bool
	explain    bool
}

const fetchLong = `Make an HTTP request through the curd daemon, which adds the credentials
(cookies, localStorage tokens) of the matching policy. You never see or send
credentials yourself.

  curd fetch [<policy>] <url> [flags]

The policy is optional: when omitted it is chosen by the URL's host. Name it
when several policies cover the host.

What happens, in order:
  1. The policy must cover the host (denied_no_policy / denied_host).
  2. The method, path and body must be allowed by the policy
     (denied_method / denied_path / denied_inspector). Reads are the default;
     a request that a policy marks as a write needs a write grant.
  3. A grant must cover the request. With none, the user is shown a consent
     dialog (unless --no-prompt). On approval a grant is minted and a session
     token is printed to stderr; later calls in the same session (same git
     repo or terminal, or --session-key / CURD_SESSION_KEY) reuse it
     automatically. Pass it explicitly with --token or CURD_TOKEN.
  4. curd sends the request with the injected credentials. Headers you pass
     with -H are filtered by the policy; Cookie, Authorization and Host from
     the caller are always dropped. Redirects are followed only as the policy
     allows. A 401/403 triggers one credential reload and retry; if it still
     fails you get auth_expired (log into the site in Chrome, then retry).
  5. The response body goes to stdout, unchanged. Set-Cookie is never shown.

Flags follow curl: -X, -H (repeatable), -d/--data, --data-binary (@file or
@- for stdin), -i, -o, -f, -s. --json-body sets the body and Content-Type
application/json. With --json the whole result is printed as JSON, including
a body_text field when the body is UTF-8.

Exit status: 0 on success, 2 when denied (the hint says how to fix it), 3 when
the daemon is unreachable, 22 with --fail on an HTTP status >= 400.

Examples:
  curd fetch https://app.example.com/api/me
  curd fetch app https://app.example.com/api/items?limit=10 -H 'Accept: application/json'
  curd fetch api https://api.example.com/graphql --json-body '{"query":"{ viewer { login } }"}'
  curd fetch --write app -X POST https://app.example.com/api/upload --data-binary @report.csv
  curd fetch --explain https://app.example.com/api/me      # dry run: nothing is sent`

func newFetchCmd(g *globals) *cobra.Command {
	var f fetchFlags
	cmd := &cobra.Command{
		Use:   "fetch [<policy>] <url>",
		Short: "Make an authenticated request through the daemon (curl-style flags)",
		Long:  fetchLong,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return fmt.Errorf("usage: curd fetch [<policy>] <url> [flags] (got %d arguments)", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error { return runFetch(cmd, g, &f, args) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.method, "request", "X", "", "HTTP method (default GET, or POST when a body is given)")
	fl.StringArrayVarP(&f.headers, "header", "H", nil, "request header 'Name: value' (repeatable); Cookie, Authorization and Host are dropped")
	fl.StringArrayVarP(&f.data, "data", "d", nil, "request body (repeatable, joined with &); @file reads a file, @- stdin; sent as-is")
	fl.StringArrayVar(&f.dataBinary, "data-binary", nil, "request body sent exactly as given; @file reads a file, @- stdin")
	fl.StringVar(&f.jsonBody, "json-body", "", "JSON request body; sets Content-Type: application/json (and Accept)")
	fl.BoolVarP(&f.include, "include", "i", false, "print the status line and response headers before the body")
	fl.StringVarP(&f.output, "output", "o", "", "write the response to this file instead of stdout")
	fl.BoolVarP(&f.fail, "fail", "f", false, "exit 22 without printing the body on an HTTP status >= 400")
	fl.BoolVarP(&f.silent, "silent", "s", false, "suppress curd's notes on stderr (errors are still shown)")
	fl.BoolVar(&f.write, "write", false, "ask for a write grant up front (needed for requests the policy marks as writes)")
	fl.BoolVar(&f.explain, "explain", false, "dry run: report the policy, rule, grant and credentials that would apply; send nothing")
	return cmd
}

func readBody(cmd *cobra.Command, spec string) ([]byte, error) {
	switch {
	case spec == "@-":
		return io.ReadAll(cmd.InOrStdin())
	case strings.HasPrefix(spec, "@"):
		b, err := os.ReadFile(spec[1:])
		if err != nil {
			return nil, fmt.Errorf("read body file: %w", err)
		}
		return b, nil
	}
	return []byte(spec), nil
}

func buildBody(cmd *cobra.Command, f *fetchFlags) ([]byte, string, error) {
	n := 0
	for _, set := range []bool{f.jsonBody != "", len(f.data) > 0, len(f.dataBinary) > 0} {
		if set {
			n++
		}
	}
	if n > 1 {
		return nil, "", fmt.Errorf("use only one of --data, --data-binary and --json-body")
	}
	switch {
	case f.jsonBody != "":
		b, err := readBody(cmd, f.jsonBody)
		return b, "application/json", err
	case len(f.dataBinary) > 0:
		var out []byte
		for _, d := range f.dataBinary {
			b, err := readBody(cmd, d)
			if err != nil {
				return nil, "", err
			}
			out = append(out, b...)
		}
		return out, "", nil
	case len(f.data) > 0:
		var parts []string
		for _, d := range f.data {
			b, err := readBody(cmd, d)
			if err != nil {
				return nil, "", err
			}
			parts = append(parts, string(b))
		}
		return []byte(strings.Join(parts, "&")), "application/x-www-form-urlencoded", nil
	}
	return nil, "", nil
}

func parseHeaders(raw []string) ([]api.Header, error) {
	var out []api.Header
	for _, h := range raw {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid header %q: use 'Name: value'", h)
		}
		out = append(out, api.Header{Name: name, Value: strings.TrimSpace(value)})
	}
	return out, nil
}

func hasHeader(hs []api.Header, name string) bool {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}

// fetchJSON is the --json output: the daemon's result plus a readable body.
type fetchJSON struct {
	api.FetchResult
	BodyText *string `json:"body_text,omitempty"`
}

func runFetch(cmd *cobra.Command, g *globals, f *fetchFlags, args []string) error {
	var policyName, url string
	if len(args) == 2 {
		policyName, url = args[0], args[1]
	} else {
		url = args[0]
	}
	if !strings.Contains(url, "://") {
		return apierr.Newf(apierr.InvalidRequest, "pass an absolute URL, optionally after the policy name: curd fetch [<policy>] https://host/path",
			"%q is not an absolute URL", url)
	}
	hdrs, err := parseHeaders(f.headers)
	if err != nil {
		return err
	}
	body, ctype, err := buildBody(cmd, f)
	if err != nil {
		return err
	}
	if ctype != "" && !hasHeader(hdrs, "Content-Type") {
		hdrs = append(hdrs, api.Header{Name: "Content-Type", Value: ctype})
	}
	if f.jsonBody != "" && !hasHeader(hdrs, "Accept") {
		hdrs = append(hdrs, api.Header{Name: "Accept", Value: "application/json"})
	}
	method := strings.ToUpper(f.method)
	if method == "" {
		method = http.MethodGet
		if len(body) > 0 {
			method = http.MethodPost
		}
	}

	params := api.FetchParams{
		Caller: g.caller(), Policy: policyName, Method: method, URL: url,
		Headers: hdrs, Body: body, Explain: f.explain, Write: f.write,
	}
	var res api.FetchResult
	if err := g.call(cmd.Context(), api.MethodFetch, params, &res); err != nil {
		return err
	}
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()

	if res.Explain != nil {
		return printExplain(out, g.json, &res)
	}
	note := func(format string, a ...any) {
		if !f.silent {
			fmt.Fprintf(errw, "curd: "+format+"\n", a...)
		}
	}
	if res.Granted != nil && res.NewToken != "" {
		gi := res.Granted
		scope := "read"
		for _, s := range gi.Scopes {
			if s == "write" {
				scope = "write"
			}
		}
		if gi.Mode == "once" {
			note("granted %s access to %s (grant %s, once: this request only)", scope, res.Policy, gi.ID)
		} else {
			note("granted %s access to %s (grant %s, %s, expires %s). token: %s",
				scope, res.Policy, gi.ID, gi.Mode, gi.ExpiresAt.Local().Format("2006-01-02 15:04"), res.NewToken)
			note("later calls in this session reuse the grant automatically; to share it with another process pass it as CURD_TOKEN=%s or --token", res.NewToken)
		}
	}
	if res.RedirectBlocked != "" {
		note("redirect not followed: %s (the redirect response is shown as is)", res.RedirectBlocked)
	}
	if res.Truncated {
		note("warning: the response was truncated at the policy's response.max_body_bytes")
	}

	failed := f.fail && res.Status >= 400
	if g.json {
		j := fetchJSON{FetchResult: res}
		if utf8.Valid(res.Body) {
			s := string(res.Body)
			j.BodyText = &s
		}
		b, _ := json.Marshal(j)
		fmt.Fprintln(out, string(b))
	} else if !failed {
		w := out
		if f.output != "" {
			file, err := os.Create(f.output)
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer file.Close()
			w = file
		}
		if f.include {
			fmt.Fprintf(w, "HTTP/1.1 %d %s\n", res.Status, http.StatusText(res.Status))
			for _, h := range res.Headers {
				fmt.Fprintf(w, "%s: %s\n", h.Name, h.Value)
			}
			fmt.Fprintln(w)
		}
		if _, err := w.Write(res.Body); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
	if failed {
		if f.silent {
			return &exitErr{code: ExitFetchFail}
		}
		return &exitErr{code: ExitFetchFail, err: fmt.Errorf("the request failed with HTTP status %d (--fail)", res.Status)}
	}
	return nil
}

func printExplain(w io.Writer, asJSON bool, res *api.FetchResult) error {
	ex := res.Explain
	if asJSON {
		b, _ := json.Marshal(ex)
		fmt.Fprintln(w, string(b))
		return nil
	}
	fmt.Fprintf(w, "policy:   %s\n", ex.Policy)
	if ex.Rule != "" {
		fmt.Fprintf(w, "rule:     %s\n", ex.Rule)
	}
	fmt.Fprintf(w, "scope:    %s\n", ex.Scope)
	if ex.GrantID != "" {
		fmt.Fprintf(w, "grant:    %s\n", ex.GrantID)
	} else {
		fmt.Fprintln(w, "grant:    none yet")
	}
	if ex.Allowed {
		fmt.Fprintln(w, "allowed:  yes")
	} else {
		fmt.Fprintf(w, "allowed:  no (%s)\n", ex.Code)
	}
	fmt.Fprintf(w, "reason:   %s\n", ex.Reason)
	if len(ex.Cookies) > 0 {
		fmt.Fprintf(w, "cookies:  %s (names only)\n", strings.Join(ex.Cookies, ", "))
	}
	if len(ex.Injected) > 0 {
		fmt.Fprintf(w, "headers:  %s (injected from localStorage)\n", strings.Join(ex.Injected, ", "))
	}
	if ex.Hint != "" {
		fmt.Fprintf(w, "hint:     %s\n", ex.Hint)
	}
	fmt.Fprintln(w, "nothing was sent upstream (--explain)")
	return nil
}

// fmtTime formats a timestamp for people.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}
