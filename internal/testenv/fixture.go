package testenv

import (
	"fmt"
	"time"

	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/source"
)

// FixtureCookies are the synthetic cookies of the test fixture. Every secret
// value contains "SECRET" so tests can grep any output for leaks.
func FixtureCookies() []creds.Cookie {
	exp := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
	return []creds.Cookie{
		// The login cookie: host-only, Secure, HttpOnly.
		{Name: mockup.SessionCookieName, Value: mockup.SessionCookie, Domain: mockup.HostApp, Path: "/", Secure: true, HTTPOnly: true, Expires: exp},
		// Only sent under /admin: path matching.
		{Name: "adminonly", Value: "admin-path-SECRET-6", Domain: mockup.HostApp, Path: "/admin", Secure: true, Expires: exp},
		// A domain cookie: also matches subdomains such as app.example.com.
		{Name: "wide", Value: "wide-domain-SECRET-7", Domain: ".example.com", Path: "/", Secure: true, Expires: exp},
		// Belongs to another site; no policy covers it.
		{Name: "elsewhere", Value: "other-site-SECRET-8", Domain: mockup.HostOther, Path: "/", Secure: true, Expires: exp},
	}
}

// FixtureLocalStorage returns the localStorage entries of the fixture. In
// test mode origins carry the mock's TLS port. The token is stored for the
// app origin (where the mock page reads it) and the api origin (injection is
// scoped to the origin of the request being made).
func FixtureLocalStorage(tlsPort int) []creds.LocalStorageItem {
	return []creds.LocalStorageItem{
		{Origin: fmt.Sprintf("https://%s:%d", mockup.HostApp, tlsPort), Key: "authToken", Value: mockup.AuthToken},
		{Origin: fmt.Sprintf("https://%s:%d", mockup.HostAPI, tlsPort), Key: "authToken", Value: mockup.AuthToken},
	}
}

// StaticFixture returns the fixture as a static source file (spec 15.2).
func StaticFixture(tlsPort int) *source.StaticFile {
	f := &source.StaticFile{}
	for _, c := range FixtureCookies() {
		f.Cookies = append(f.Cookies, source.StaticCookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, Expires: c.Expires,
		})
	}
	for _, l := range FixtureLocalStorage(tlsPort) {
		f.LocalStorage = append(f.LocalStorage, source.StaticLocalStorage{Origin: l.Origin, Key: l.Key, Value: l.Value})
	}
	return f
}
