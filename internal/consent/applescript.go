package consent

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	maxFieldRunes  = 80
	maxDetailRunes = 160
	maxListRunes   = 200
	giveUpSeconds  = 300
)

// sanitize removes control characters and newlines from untrusted text and
// truncates it to max runes, so it cannot forge extra dialog lines.
func sanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			r = ' '
		}
		if n >= max {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// escapeAS escapes s for inclusion in a double-quoted AppleScript string.
func escapeAS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "this session"
	}
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "1m"
	}
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

// joinList joins sanitized items within maxListRunes. Items that do not fit
// are never dropped silently: the list ends with "(+K more)".
func joinList(items []string) string { return joinListMax(items, maxListRunes, maxFieldRunes) }

func joinListMax(items []string, budget, itemMax int) string {
	clean := make([]string, 0, len(items))
	for _, it := range items {
		if c := sanitize(it, itemMax); c != "" {
			clean = append(clean, c)
		}
	}
	var b strings.Builder
	n := 0
	for i, c := range clean {
		l := len([]rune(c))
		if i > 0 && n+2+l > budget {
			fmt.Fprintf(&b, " (+%d more)", len(clean)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
			n += 2
		}
		b.WriteString(c)
		n += l
	}
	return b.String()
}

// Limits for the approve dialog.
const (
	maxRuleLines = 12
	maxRuleRunes = 120
	maxPathRunes = 200
)

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// policyLines renders a PolicySummary. Long lists show their first entries
// and "+K more"; a final line gives every count so nothing is hidden.
func policyLines(name string, hosts []string, ps *PolicySummary) []string {
	var out []string
	clean := func(l []string, max int) []string {
		var r []string
		for _, x := range l {
			if c := sanitize(x, max); c != "" {
				r = append(r, c)
			}
		}
		return r
	}
	rules := clean(ps.Rules, maxRuleRunes)
	out = append(out, fmt.Sprintf("Rules (%d):", len(rules)))
	for i, r := range rules {
		if i == maxRuleLines && len(rules) > maxRuleLines+1 {
			out = append(out, fmt.Sprintf("  ... +%d more rules (see curd policies show %s)", len(rules)-i, sanitize(name, maxFieldRunes)))
			break
		}
		out = append(out, "  - "+r)
	}
	switch {
	case ps.CookiesNone:
		out = append(out, "Cookies: none")
	case len(ps.Cookies) == 0:
		out = append(out, "Cookies: ALL cookies for these domains")
	default:
		out = append(out, "Cookies: "+joinList(ps.Cookies))
	}
	if len(ps.LocalStorage) == 0 {
		out = append(out, "localStorage: none")
	} else {
		out = append(out, "localStorage: "+joinListMax(ps.LocalStorage, maxListRunes, maxRuleRunes))
	}
	if len(ps.HeaderAllowlist) == 0 {
		out = append(out, "Request headers allowed: default ("+joinList(ps.DefaultHeaders)+")")
	} else {
		out = append(out, "Request headers allowed: "+joinList(ps.HeaderAllowlist))
	}
	if r := sanitize(ps.Redirects, maxFieldRunes); r != "" {
		out = append(out, "Redirects: "+r)
	}
	for _, e := range clean(ps.ExecInspectors, maxPathRunes) {
		out = append(out, "Runs exec inspector: "+e)
	}
	cookies := "all cookies"
	switch {
	case ps.CookiesNone:
		cookies = "no cookies"
	case len(ps.Cookies) > 0:
		cookies = plural(len(ps.Cookies), "cookie pattern", "cookie patterns")
	}
	out = append(out, "Summary: "+strings.Join([]string{
		plural(len(hosts), "domain", "domains"),
		plural(len(rules), "rule", "rules"),
		cookies,
		plural(len(ps.LocalStorage), "localStorage item", "localStorage items"),
		plural(len(ps.HeaderAllowlist), "allowlisted header", "allowlisted headers"),
		plural(len(ps.ExecInspectors), "exec inspector", "exec inspectors"),
	}, ", "))
	return out
}

// BuildScript returns the AppleScript source for p. It is pure so it can be
// tested on any OS. Every interpolated string is sanitized and escaped.
func BuildScript(p Prompt) string {
	var lines []string // each a ready-to-embed AppleScript string literal
	lit := func(s string) { lines = append(lines, `"`+escapeAS(s)+`"`) }
	field := func(label, v string, max int) {
		if v = sanitize(v, max); v != "" {
			lit(label + ": " + v)
		}
	}

	var buttons, cancel string
	icon := ""
	switch p.Kind {
	case KindApprovePolicy:
		lit("Approve a new or changed curd policy?")
		lit("")
		if l := joinList(p.Policies); l != "" {
			lit("Policy: " + l)
		}
		if l := joinList(p.Hosts); l != "" {
			lit("Domains: " + l)
		}
		if p.Policy != nil {
			name := ""
			if len(p.Policies) > 0 {
				name = p.Policies[0]
			}
			for _, l := range policyLines(name, p.Hosts, p.Policy) {
				lit(l)
			}
		}
		field("Details", p.Detail, maxDetailRunes)
		field("Purpose", p.Purpose, maxFieldRunes)
		buttons = `{"Cancel", "Approve"}`
		cancel = "Cancel"
	case KindShutdown:
		lit("Stop the curd daemon?")
		lit("")
		lit("This ends every grant and browser session.")
		client := sanitize(p.ClientName, maxFieldRunes)
		if client == "" {
			client = "unknown process"
		}
		if p.ClientPID > 0 {
			lit(fmt.Sprintf("Requested by: %s (pid %d)", client, p.ClientPID))
		} else {
			lit("Requested by: " + client)
		}
		buttons = `{"Cancel", "Approve"}`
		cancel = "Cancel"
	default:
		write := p.Scope == "write"
		if write {
			lit("Allow WRITE access?")
		} else {
			lit("Allow read access?")
		}
		lit("")
		if l := joinList(p.Hosts); l != "" {
			lit("Domains: " + l)
		}
		if l := joinList(p.Policies); l != "" {
			lit("Policies: " + l)
		}
		client := sanitize(p.ClientName, maxFieldRunes)
		if client == "" {
			client = "unknown process"
		}
		if p.ClientPID > 0 {
			lit(fmt.Sprintf("Requested by: %s (pid %d)", client, p.ClientPID))
		} else {
			lit("Requested by: " + client)
		}
		if write {
			lit("Scope: WRITE")
			lit("WARNING: this lets the client change data using your logged-in sessions.")
		} else {
			lit("Scope: read")
		}
		field("Session", p.SessionKey, maxFieldRunes)
		field("Purpose", p.Purpose, maxFieldRunes)
		field("Request", p.Detail, maxDetailRunes)
		if p.Duration > 0 {
			lit("Duration: " + formatDuration(p.Duration))
		}
		allow := `"Allow for ` + escapeAS(formatDuration(p.Duration)) + `"`
		if p.Duration <= 0 {
			allow = `"Allow for session"`
		}
		buttons = `{"Deny", "Allow once", ` + allow + `}`
		cancel = "Deny"
		if write {
			icon = " with icon caution"
		}
	}

	text := strings.Join(lines, ` & return & `)
	// No default button: macOS does not bind Esc to a cancel button that is
	// also the default, so setting both made Esc do nothing.
	return fmt.Sprintf(`display dialog %s with title "curd" buttons %s cancel button %q%s giving up after %d`,
		text, buttons, cancel, icon, giveUpSeconds)
}

// ParseOutput maps osascript's stdout (for example
// "button returned:Allow once, gave up:false") to an Answer. Anything
// unrecognized, including a timeout, is Deny.
func ParseOutput(out string) Answer {
	out = strings.TrimSpace(out)
	if strings.Contains(out, "gave up:true") {
		return Deny
	}
	const key = "button returned:"
	i := strings.Index(out, key)
	if i < 0 {
		return Deny
	}
	btn := out[i+len(key):]
	if j := strings.Index(btn, ", gave up:"); j >= 0 {
		btn = btn[:j]
	}
	btn = strings.TrimSpace(btn)
	switch {
	case btn == "Allow once":
		return Once
	case strings.HasPrefix(btn, "Allow for "):
		return Session
	case btn == "Approve":
		return Approve
	default:
		return Deny
	}
}
