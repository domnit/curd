package policy

import (
	"strings"

	"github.com/domnit/curd/internal/api"
)

// alwaysDropped are request headers a caller may never set: credentials the
// daemon injects itself, and hop-by-hop or framing headers.
var alwaysDropped = map[string]bool{
	"cookie":              true,
	"authorization":       true,
	"host":                true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
	"proxy-connection":    true,
	"connection":          true,
	"keep-alive":          true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"content-length":      true,
	"transfer-encoding":   true,
}

// methodOverrideHeaders let a request claim a different method than the one
// the policy checked; they may never be allowlisted.
var methodOverrideHeaders = map[string]bool{
	"x-http-method-override": true,
	"x-http-method":          true,
	"x-method-override":      true,
}

var defaultHeaderAllowlist = []string{"accept", "accept-language", "content-type"}

// DefaultHeaderAllowlist returns the caller headers kept when a policy has
// no request.header_allowlist.
func DefaultHeaderAllowlist() []string { return append([]string(nil), defaultHeaderAllowlist...) }

// FilterRequestHeaders keeps only the caller headers the policy allows.
// dropped holds the names (never values) of removed headers.
func (p *Policy) FilterRequestHeaders(h []api.Header) (kept []api.Header, dropped []string) {
	allow := p.Request.HeaderAllowlist
	if len(allow) == 0 {
		allow = defaultHeaderAllowlist
	}
	for _, hd := range h {
		name := strings.ToLower(strings.TrimSpace(hd.Name))
		if name == "" || alwaysDropped[name] || !listed(allow, name) || strings.ContainsAny(hd.Value, "\r\n\x00") {
			dropped = append(dropped, hd.Name)
			continue
		}
		kept = append(kept, hd)
	}
	return kept, dropped
}

func listed(list []string, lowerName string) bool {
	for _, a := range list {
		if strings.EqualFold(a, lowerName) {
			return true
		}
	}
	return false
}
