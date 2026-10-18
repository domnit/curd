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

func joinList(items []string) string {
	clean := make([]string, 0, len(items))
	for _, it := range items {
		if c := sanitize(it, maxFieldRunes); c != "" {
			clean = append(clean, c)
		}
	}
	return sanitize(strings.Join(clean, ", "), maxListRunes)
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

	var buttons, cancel, def string
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
		field("Details", p.Detail, maxDetailRunes)
		field("Purpose", p.Purpose, maxFieldRunes)
		buttons = `{"Cancel", "Approve"}`
		cancel, def = "Cancel", "Cancel"
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
		cancel, def = "Deny", "Deny"
		if write {
			icon = " with icon caution"
		}
	}

	text := strings.Join(lines, ` & return & `)
	return fmt.Sprintf(`display dialog %s with title "curd" buttons %s default button %q cancel button %q%s giving up after %d`,
		text, buttons, def, cancel, icon, giveUpSeconds)
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
