package creds

import "testing"

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"app.example.com", "app.example.com", true},
		{"app.example.com", "APP.example.com:443", true},
		{"app.example.com", "x.app.example.com", false},
		{"app.example.com", "example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"*.example.com", "a.example.com.evil.net", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.pattern, c.host); got != c.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestCookieDomainRelevant(t *testing.T) {
	cases := []struct {
		patterns []string
		domain   string
		want     bool
	}{
		{[]string{"app.example.com"}, "app.example.com", true},
		{[]string{"app.example.com"}, ".example.com", true},
		{[]string{"app.example.com"}, ".other.com", false},
		{[]string{"app.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, ".example.com", true},
		{[]string{"*.example.com"}, "x.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, ".com", true},
	}
	for _, c := range cases {
		if got := CookieDomainRelevant(c.patterns, c.domain); got != c.want {
			t.Errorf("CookieDomainRelevant(%v, %q) = %v, want %v", c.patterns, c.domain, got, c.want)
		}
	}
}
