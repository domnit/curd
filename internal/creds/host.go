package creds

import "strings"

// MatchHost reports whether host matches pattern. Patterns are either an
// exact hostname ("app.example.com") or an explicit wildcard ("*.example.com")
// that matches any strict subdomain but NOT the bare suffix. There is no
// implicit subdomain matching (spec section 12). Comparison is
// case-insensitive and ignores a port on host.
func MatchHost(pattern, host string) bool {
	host = strings.ToLower(stripPort(host))
	pattern = strings.ToLower(pattern)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
	}
	return host == pattern
}

// MatchAnyHost reports whether host matches any of patterns.
func MatchAnyHost(patterns []string, host string) bool {
	for _, p := range patterns {
		if MatchHost(p, host) {
			return true
		}
	}
	return false
}

// CookieDomainRelevant reports whether a cookie stored under cookieDomain
// (Chrome host_key form) could be sent to some host matching one of
// patterns. Sources use it to decide which rows to decrypt.
func CookieDomainRelevant(patterns []string, cookieDomain string) bool {
	d := strings.ToLower(cookieDomain)
	if strings.HasPrefix(d, ".") {
		bare := d[1:]
		for _, p := range patterns {
			p = strings.ToLower(p)
			if suffix, ok := strings.CutPrefix(p, "*."); ok {
				// *.example.com hosts receive .example.com and .sub.example.com cookies.
				if bare == suffix || strings.HasSuffix(bare, "."+suffix) || strings.HasSuffix(suffix, "."+bare) {
					return true
				}
				continue
			}
			if p == bare || strings.HasSuffix(p, "."+bare) {
				return true
			}
		}
		return false
	}
	return MatchAnyHost(patterns, d)
}

func stripPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			return h[1:i]
		}
		return h
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return h
}
