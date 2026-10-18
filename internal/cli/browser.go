package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/domnit/curd/internal/api"
)

func newSessionCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Open or close an ephemeral, pre-authenticated browser session",
		Long: `A browser session is a short-lived Chrome that curd starts for you, logged in
as the user for the policies you name. curd holds the only connection to it;
you drive it with "curd browse <verb>" and never get raw browser access or the
credentials. Use it when you need the real UI: to find out how a site's API
works (then "curd distill"), or to do something only the UI offers.

Opening a session needs a grant covering its policies, so the user is asked
the same way as for "curd fetch". Sessions are read-only unless opened with
--write: writes the page attempts are blocked and recorded as blocked_write.
Sessions end at their TTL, on "curd session close", or when their grant is
revoked.`,
	}
	var ttl, seed, loginURL string
	var write, explore bool
	open := &cobra.Command{
		Use:   "open <policy>... [--ttl 30m] [--write]",
		Short: "Start a browser session for one or more policies",
		Long: `Start the session and print its id and expiry. Later "curd browse" calls use the
most recent session unless you pass --session <id>.

  --ttl        session lifetime, e.g. 30m (default: short)
  --write      allow writes the page makes (also needs a write grant); use only
               on a throwaway account or workspace
  --seed       how the browser gets its login: "hoist" copies the Chrome
               profile's cookies/localStorage for the policies into the
               in-memory browser context; "login" starts logged out and lets the
               user sign in interactively (nothing is copied)
  --login-url  first page for interactive login
  --explore    tag the audit records "explore" (the session is for capturing
               a site's API)`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := api.OpenSessionParams{
				Caller: g.caller(), Policies: args, TTL: ttl, AllowWrites: write,
				Seed: seed, LoginURL: loginURL, Explore: explore,
			}
			var res api.OpenSessionResult
			if err := g.call(cmd.Context(), api.MethodOpenSession, p, &res); err != nil {
				return err
			}
			if g.json {
				return writeJSON(cmd.OutOrStdout(), res)
			}
			if res.NewToken != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "curd: granted access (token: %s)\n", res.NewToken)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (expires %s, seed %s)\n", res.SessionID, fmtTime(res.ExpiresAt), res.Seed)
			return nil
		},
	}
	open.Flags().StringVar(&ttl, "ttl", "", "session lifetime such as 30m")
	open.Flags().BoolVar(&write, "write", false, "let the page's writes through (needs a write grant)")
	open.Flags().StringVar(&seed, "seed", "", "login method: hoist or login")
	open.Flags().StringVar(&loginURL, "login-url", "", "first page for interactive login")
	open.Flags().BoolVar(&explore, "explore", false, "tag audit records as exploration")
	closeCmd := &cobra.Command{
		Use:   "close [session-id]",
		Short: "Close a browser session and delete its temporary profile",
		Long:  `Close the given session, or the most recent one if no id is given. The browser process is killed and its temporary profile and captured traffic are deleted.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := api.CloseSessionParams{Caller: g.caller()}
			if len(args) == 1 {
				p.SessionID = args[0]
			}
			if err := g.call(cmd.Context(), api.MethodCloseSession, p, nil); err != nil {
				return err
			}
			if !g.json {
				fmt.Fprintln(cmd.OutOrStdout(), "session closed")
			}
			return nil
		},
	}
	cmd.AddCommand(open, closeCmd)
	return cmd
}

type verbSpec struct {
	use, short, long string
	minArgs, maxArgs int
	screenshot       bool
}

var browseVerbs = []verbSpec{
	{"open <url>", "Navigate to a URL (it must be on a policy host)", "Navigate the current page to <url>. Navigation to hosts outside the session's policies is blocked (denied_host). Waits for the load to finish.", 1, 1, false},
	{"back", "Go back in history", "Go back one entry in the page history.", 0, 0, false},
	{"forward", "Go forward in history", "Go forward one entry in the page history.", 0, 0, false},
	{"reload", "Reload the page", "Reload the current page.", 0, 0, false},
	{"url", "Print the current URL", "Print the URL of the current page (credentials in it, if any, are replaced by placeholders).", 0, 0, false},
	{"title", "Print the page title", "Print the title of the current page.", 0, 0, false},
	{"text <selector>", "Print the visible text of an element (CSS selector)", "Print the text content of the first element matching the CSS selector. Output is redacted: held credential values are replaced by placeholders.", 1, 1, false},
	{"html <selector>", "Print the HTML of an element (CSS selector)", "Print the outer HTML of the first element matching the CSS selector (redacted).", 1, 1, false},
	{"exists <selector>", "Report whether a selector matches an element", "Print true or false: whether the CSS selector matches an element in the page.", 1, 1, false},
	{"visible <selector>", "Report whether an element is visible", "Print true or false: whether the first match is visible.", 1, 1, false},
	{"click <selector>", "Click an element", "Click the first element matching the CSS selector. Writes the click triggers (POST, mutations) are blocked in a read-only session and recorded as blocked_write.", 1, 1, false},
	{"type <selector> <text>", "Type text into an element", "Focus the element and type the text (all remaining arguments are joined with spaces).", 2, -1, false},
	{"focus <selector>", "Focus an element", "Focus the first element matching the CSS selector.", 1, 1, false},
	{"waitstable", "Wait until the page layout stops changing", "Block until the DOM has been stable for a short while.", 0, 0, false},
	{"waitidle", "Wait until the network is idle", "Block until the page has no requests in flight for a short while.", 0, 0, false},
	{"screenshot [-o file.png]", "Save a PNG screenshot of the page", "Capture the visible page as a PNG. Use -o to name the file; without -o the PNG is written to stdout when it is not a terminal.", 0, 0, true},
	{"pages", "List open pages", "List the pages (tabs) of the session with their index, URL and title.", 0, 0, false},
	{"newpage [url]", "Open a new page", "Open a new page in the session's browser context, optionally navigating to a URL.", 0, 1, false},
	{"closepage [index]", "Close a page", "Close the page with the given index (see \"pages\"), default the current one.", 0, 1, false},
	{"js <expression>", "Evaluate JavaScript (gated: not available by default)", "Arbitrary JavaScript could read cookies and localStorage, so this verb is gated: it needs an explicit js grant, is refused on any origin that has credentials loaded, and every evaluation is audited. Prefer the structured verbs.", 1, -1, false},
}

func newBrowseCmd(g *globals) *cobra.Command {
	var sessionID string
	cmd := &cobra.Command{
		Use:   "browse <verb> [args]",
		Short: "Drive the session's browser with a small set of safe verbs",
		Long: `Drive the browser of a session ("curd session open ..."). Only these verbs
exist; curd never exposes raw browser control, so there is no way to read
cookies or storage, and everything returned is redacted.

  open <url>  back  forward  reload  url  title
  text <sel>  html <sel>  exists <sel>  visible <sel>
  click <sel>  type <sel> <text>  focus <sel>
  waitstable  waitidle  screenshot [-o file.png]
  pages  newpage [url]  closepage [index]
  capture list|get|find-source|export     read the recorded network traffic

Selectors are CSS selectors. Navigation outside the session's policy hosts is
blocked, and a read-only session blocks the page's writes (recorded as
blocked_write). Use --session <id> to pick a session; the default is your most
recent one.

Typical exploration: session open -> browse open <url> -> click around ->
browse capture list -> distill draft -> distill verify -> policies approve.
See "curd guide" section 7.`,
	}
	cmd.PersistentFlags().StringVar(&sessionID, "session", "", "session id (default: your most recent session)")
	for _, v := range browseVerbs {
		v := v
		verb := strings.Fields(v.use)[0]
		c := &cobra.Command{
			Use: v.use, Short: v.short, Long: v.long,
			Args: func(cmd *cobra.Command, args []string) error {
				if len(args) < v.minArgs || (v.maxArgs >= 0 && len(args) > v.maxArgs) {
					return fmt.Errorf("usage: curd browse %s", v.use)
				}
				return nil
			},
		}
		var shot string
		if v.screenshot {
			c.Flags().StringVarP(&shot, "output", "o", "", "write the PNG to this file")
		}
		c.RunE = func(cmd *cobra.Command, args []string) error {
			var res api.BrowseResult
			p := api.BrowseParams{Caller: g.caller(), SessionID: sessionID, Verb: verb, Args: args}
			if err := g.call(cmd.Context(), api.MethodBrowse, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if v.screenshot {
				return writeScreenshot(cmd, out, shot, res.PNG)
			}
			if g.json {
				return writeJSON(out, res)
			}
			if res.Text != "" {
				fmt.Fprintln(out, strings.TrimRight(res.Text, "\n"))
			}
			return nil
		}
		cmd.AddCommand(c)
	}
	cmd.AddCommand(newCaptureCmd(g, &sessionID))
	return cmd
}

func writeScreenshot(cmd *cobra.Command, out io.Writer, file string, png []byte) error {
	if len(png) == 0 {
		return fmt.Errorf("the browser returned no image")
	}
	if file != "" {
		if err := os.WriteFile(file, png, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "saved %s (%d bytes)\n", file, len(png))
		return nil
	}
	if f, ok := out.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return fmt.Errorf("refusing to write a PNG to the terminal; use -o file.png")
		}
	}
	_, err := out.Write(png)
	return err
}

func newCaptureCmd(g *globals, sessionID *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capture <list|get|find-source|export>",
		Short: "Read the traffic recorded during a browser session (credentials redacted)",
		Long: `While a session runs, curd records every request the browser makes (URLs,
headers, bodies, initiator). You read it here; Cookie, Authorization and
Set-Cookie values and anything equal to a held credential are replaced by
placeholders such as {cookie:session} or {ls:https://app.example.com:authToken}.
A secret created by the site during the session (a fresh CSRF token) stays
visible: you need it to understand the request flow.

  curd browse capture list [--url-contains /api] [--method POST]
  curd browse capture get <id> [--parts request_headers,response_body]
  curd browse capture find-source <value>
  curd browse capture export [ids...] -o session.har

Writes the page tried while the session was read-only appear with
blocked_write: you learn their shape without executing them.`,
	}
	var f api.CaptureFilter
	list := &cobra.Command{
		Use:   "list [--method M] [--url-contains S] [--type T] [--host H] [--status N]",
		Short: "List captured requests (id, method, URL, status, type, size, initiator)",
		Long: `List captured requests, oldest first. Filter with --method, --url-contains,
--type (Document, XHR, Fetch, Script, ...), --host and --status. Ids (c1, c2,
...) are what "capture get", "capture export" and "distill draft" take.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.CaptureListResult
			p := api.CaptureListParams{Caller: g.caller(), SessionID: *sessionID, Filter: f}
			if err := g.call(cmd.Context(), api.MethodCaptureList, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tMETHOD\tSTATUS\tTYPE\tSIZE\tURL\tNOTES")
			for _, e := range res.Entries {
				notes := e.Initiator
				if e.BlockedWrite {
					notes = "blocked_write " + notes
				}
				if e.Blocked != "" {
					notes = "blocked: " + e.Blocked + " " + notes
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\t%s\n", e.ID, e.Method, e.Status, e.ResourceType, e.Size, e.URL, notes)
			}
			return tw.Flush()
		},
	}
	list.Flags().StringVar(&f.Method, "method", "", "only this HTTP method")
	list.Flags().StringVar(&f.URLContains, "url-contains", "", "only URLs containing this text")
	list.Flags().StringVar(&f.Type, "type", "", "only this resource type (Document, XHR, Fetch, ...)")
	list.Flags().StringVar(&f.Host, "host", "", "only this host")
	list.Flags().IntVar(&f.Status, "status", 0, "only this HTTP status")

	var parts []string
	get := &cobra.Command{
		Use:   "get <id> [--parts request_headers,request_body,response_headers,response_body]",
		Short: "Show one captured request and its response (redacted)",
		Long:  `Show one captured exchange. Without --parts everything is shown: request headers and body, response headers and body. Large bodies are truncated (body_truncated); binary bodies are base64.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var d api.CaptureDetail
			p := api.CaptureGetParams{Caller: g.caller(), ID: args[0], Parts: parts}
			if err := g.call(cmd.Context(), api.MethodCaptureGet, p, &d); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, d)
			}
			fmt.Fprintf(out, "%s %s %s -> %d (%s, %d bytes)\n", d.ID, d.Method, d.URL, d.Status, d.ResourceType, d.Size)
			if len(d.RequestHeaders) > 0 {
				fmt.Fprintln(out, "\nrequest headers:")
				for _, h := range d.RequestHeaders {
					fmt.Fprintf(out, "  %s: %s\n", h.Name, h.Value)
				}
			}
			if d.RequestBody != "" {
				fmt.Fprintf(out, "\nrequest body:\n%s\n", d.RequestBody)
			}
			if len(d.ResponseHeaders) > 0 {
				fmt.Fprintln(out, "\nresponse headers:")
				for _, h := range d.ResponseHeaders {
					fmt.Fprintf(out, "  %s: %s\n", h.Name, h.Value)
				}
			}
			if d.ResponseBody != "" {
				fmt.Fprintf(out, "\nresponse body:\n%s\n", d.ResponseBody)
			}
			if d.BodyTruncated {
				fmt.Fprintln(out, "\n(body truncated)")
			}
			return nil
		},
	}
	get.Flags().StringSliceVar(&parts, "parts", nil, "request_headers, request_body, response_headers, response_body (comma-separated)")

	find := &cobra.Command{
		Use:   "find-source <value>",
		Short: "Find which earlier response or page produced a value (e.g. a CSRF token)",
		Long: `Search the capture for the first places a non-credential value appears (response
bodies, headers, URLs, page content), earliest first. Use it to trace request
dependencies: where did this CSRF token or id come from, so that "curd fetch"
can obtain it itself.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.CaptureFindResult
			p := api.CaptureFindParams{Caller: g.caller(), SessionID: *sessionID, Value: args[0]}
			if err := g.call(cmd.Context(), api.MethodCaptureFind, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			if len(res.Sources) == 0 {
				fmt.Fprintln(out, "no match")
			}
			for _, s := range res.Sources {
				fmt.Fprintf(out, "%s  %s  %s\n", s.ID, s.Location, s.Context)
			}
			return nil
		},
	}

	var outFile string
	export := &cobra.Command{
		Use:   "export [ids...] [-o file.har]",
		Short: "Export captured requests as a redacted HAR file",
		Long:  `Export the given capture ids (default: all) as a HAR 1.2 document with credentials replaced by placeholders. Writes to -o or stdout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.CaptureExportResult
			p := api.CaptureExportParams{Caller: g.caller(), SessionID: *sessionID, IDs: args}
			if err := g.call(cmd.Context(), api.MethodCaptureExport, p, &res); err != nil {
				return err
			}
			if outFile != "" {
				f, err := os.Create(outFile)
				if err != nil {
					return err
				}
				defer f.Close()
				if err := writeJSON(f, res.HAR); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "curd: wrote %s\n", outFile)
				return nil
			}
			return writeJSON(cmd.OutOrStdout(), res.HAR)
		},
	}
	export.Flags().StringVarP(&outFile, "output", "o", "", "write the HAR here instead of stdout")
	cmd.AddCommand(list, get, find, export)
	return cmd
}

func newDistillCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "distill",
		Short: "Turn captured traffic into a draft policy and verify it with plain fetches",
		Long: `After exploring a site in a browser session, distill the requests that matter
into a narrow policy plus the "curd fetch" commands that replace the browser.

  curd distill draft <name> <capture ids...>     write <name>.draft.yaml
  curd distill verify <name> [ids...]            replay with plain curd fetch, diff

The draft is the narrowest policy that covers the selected requests: method +
path regexp (numeric and UUID segments generalized), only the cookie names that
were actually sent, localStorage inject_as rules where a header equalled a held
value, graphql_query_only for GraphQL, and captured writes as DISABLED entries.
It has status: draft and is inert until the user approves it
("curd policies approve <name>").

Verification uses the real Chrome login through the broker, so what verifies is
what ships. Fix what differs (a CSRF token, a dynamic parameter, a header) and
verify again.`,
	}
	var session string
	draft := &cobra.Command{
		Use:   "draft <name> <capture-id>...",
		Short: "Generate a draft policy and curd fetch commands from captured requests",
		Long: `Generate <policy dir>/<name>.draft.yaml (status: draft) from the selected capture
ids and print it with the matching "curd fetch" commands. Captured non-GET
requests become disabled write entries; enable them in the file only if the
task needs them. Nothing is active until "curd policies approve <name>".`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.DistillDraftResult
			p := api.DistillDraftParams{Caller: g.caller(), SessionID: session, Name: args[0], IDs: args[1:]}
			if err := g.call(cmd.Context(), api.MethodDistillDraft, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				return writeJSON(out, res)
			}
			fmt.Fprintf(out, "# draft written to %s\n%s", res.Path, res.YAML)
			if len(res.Commands) > 0 {
				fmt.Fprintln(out, "\n# commands")
				for _, c := range res.Commands {
					fmt.Fprintln(out, c)
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "curd: the draft is inert. Verify it with `curd distill verify %s`, then have the user run `curd policies approve %s`\n", res.Name, res.Name)
			return nil
		},
	}
	draft.Flags().StringVar(&session, "session", "", "session id (default: your most recent session)")

	var minimize bool
	verify := &cobra.Command{
		Use:   "verify <name> [capture-id...] [--minimize]",
		Short: "Replay a draft's requests with plain curd fetch and diff against the capture",
		Long: `Replay each captured request through the fetch broker under the draft policy
(no browser, the real Chrome login) and compare status and response shape with
what the browser saw. Prints per-request results; exit 1 if any request does not
verify. --minimize drops headers one at a time to find the smallest
request.header_allowlist. The (possibly narrowed) draft is saved back.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res api.DistillVerifyResult
			p := api.DistillVerifyParams{Caller: g.caller(), Draft: args[0], IDs: args[1:], Minimize: minimize}
			if err := g.call(cmd.Context(), api.MethodDistillVerify, p, &res); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if g.json {
				if err := writeJSON(out, res); err != nil {
					return err
				}
			} else {
				for _, it := range res.Items {
					state := "ok"
					switch {
					case it.Skipped != "":
						state = "skipped: " + it.Skipped
					case !it.OK:
						state = "FAILED"
						if it.Error != "" {
							state += " (" + it.Error + ")"
						}
					}
					fmt.Fprintf(out, "%s %s %s: %s (captured %d, replay %d)\n", it.ID, it.Method, it.URL, state, it.CapturedStatus, it.ReplayStatus)
					for _, d := range it.ShapeDiff {
						fmt.Fprintf(out, "    differs: %s\n", d)
					}
					if len(it.NeededHeaders) > 0 {
						fmt.Fprintf(out, "    needed headers: %s\n", strings.Join(it.NeededHeaders, ", "))
					}
				}
			}
			if !res.OK {
				return &exitErr{code: ExitError, err: fmt.Errorf("verification failed: fix the differences above and run `curd distill verify %s` again", args[0])}
			}
			return nil
		},
	}
	verify.Flags().BoolVar(&minimize, "minimize", false, "drop headers one at a time to find the minimal allowlist")
	cmd.AddCommand(draft, verify)
	return cmd
}
