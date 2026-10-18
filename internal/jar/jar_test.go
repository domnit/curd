package jar

import (
	"net/url"
	"testing"
	"time"

	"github.com/domnit/curd/internal/creds"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func names(cs []creds.Cookie) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDomainVsHostOnly(t *testing.T) {
	j := New()
	j.ApplySetCookie(mustURL(t, "https://app.example.com/x"), []string{
		"host=1", "dom=2; Domain=example.com",
	}, t0)
	tests := []struct {
		url  string
		want []string
	}{
		{"https://app.example.com/", []string{"host", "dom"}},
		{"https://sub.app.example.com/", []string{"dom"}},
		{"https://example.com/", []string{"dom"}},
		{"https://other.example.com/", []string{"dom"}},
		{"https://notexample.com/", nil},
		{"https://example.org/", nil},
	}
	for _, tc := range tests {
		got := names(j.CookiesFor(mustURL(t, tc.url), t0))
		if len(got) == 2 && got[0] != tc.want[0] { // order is by creation; compare as set
			got[0], got[1] = got[1], got[0]
		}
		if !eq(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.url, got, tc.want)
		}
	}
}

func TestPathMatching(t *testing.T) {
	j := New()
	j.ApplySetCookie(mustURL(t, "https://a.com/api/v1/x"), []string{
		"def=1",               // default path /api/v1
		"root=2; Path=/",      // /
		"api=3; Path=/api",    // /api
		"slash=4; Path=/api/", // /api/
	}, t0)
	tests := []struct {
		path string
		want []string
	}{
		{"/", []string{"root"}},
		{"/api", []string{"api", "root"}},
		{"/api/", []string{"slash", "api", "root"}},
		{"/apix", []string{"root"}},
		{"/api/v1", []string{"def", "slash", "api", "root"}},
		{"/api/v1/deeper", []string{"def", "slash", "api", "root"}},
		{"/api/v10", []string{"slash", "api", "root"}},
	}
	for _, tc := range tests {
		got := names(j.CookiesFor(mustURL(t, "https://a.com"+tc.path), t0))
		if !eq(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.path, got, tc.want)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	for in, want := range map[string]string{"": "/", "/": "/", "/a": "/", "/a/b": "/a", "/a/b/": "/a/b", "x": "/"} {
		if got := defaultPath(in); got != want {
			t.Errorf("defaultPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOrderingSamePathByCreation(t *testing.T) {
	j := New()
	u := mustURL(t, "https://a.com/")
	j.ApplySetCookie(u, []string{"first=1"}, t0)
	j.ApplySetCookie(u, []string{"second=2"}, t0)
	j.ApplySetCookie(u, []string{"first=1b"}, t0.Add(time.Second)) // overwrite keeps creation order
	got := j.CookiesFor(u, t0)
	if !eq(names(got), []string{"first", "second"}) {
		t.Fatalf("order %v", names(got))
	}
	if h := CookieHeader(got); h != "first=1b; second=2" {
		t.Fatalf("header %q", h)
	}
}

func TestSecure(t *testing.T) {
	j := New()
	j.ApplySetCookie(mustURL(t, "https://a.com/"), []string{"s=1; Secure", "n=2"}, t0)
	if got := names(j.CookiesFor(mustURL(t, "http://a.com/"), t0)); !eq(got, []string{"n"}) {
		t.Errorf("http: %v", got)
	}
	if got := names(j.CookiesFor(mustURL(t, "https://a.com/"), t0)); len(got) != 2 {
		t.Errorf("https: %v", got)
	}
	// A Secure cookie cannot be set from plain http.
	j2 := New()
	j2.ApplySetCookie(mustURL(t, "http://a.com/"), []string{"s=1; Secure"}, t0)
	if j2.Len() != 0 {
		t.Error("secure cookie accepted over http")
	}
}

func TestExpiry(t *testing.T) {
	j := New()
	u := mustURL(t, "https://a.com/")
	j.ApplySetCookie(u, []string{
		"maxage=1; Max-Age=60",
		"exp=1; Expires=" + t0.Add(2*time.Hour).UTC().Format(time.RFC1123),
		"sess=1",
		"alreadygone=1; Expires=" + t0.Add(-time.Hour).UTC().Format(time.RFC1123),
	}, t0)
	if got := names(j.CookiesFor(u, t0)); len(got) != 3 {
		t.Fatalf("now: %v", got)
	}
	if got := names(j.CookiesFor(u, t0.Add(61*time.Second))); !eq(got, []string{"exp", "sess"}) {
		t.Errorf("after 61s: %v", got)
	}
	if got := names(j.CookiesFor(u, t0.Add(3*time.Hour))); !eq(got, []string{"sess"}) {
		t.Errorf("after 3h: %v", got)
	}
}

func TestOverwriteAndDelete(t *testing.T) {
	j := New()
	u := mustURL(t, "https://a.com/")
	j.ApplySetCookie(u, []string{"a=1"}, t0)
	j.ApplySetCookie(u, []string{"a=2"}, t0.Add(time.Second))
	if h := CookieHeader(j.CookiesFor(u, t0)); h != "a=2" {
		t.Fatalf("overwrite: %q", h)
	}
	j.ApplySetCookie(u, []string{"a=; Max-Age=0"}, t0.Add(2*time.Second))
	if j.Len() != 0 || len(j.CookiesFor(u, t0)) != 0 {
		t.Fatal("not deleted")
	}
	// Deletion with Max-Age=-1 and past Expires.
	j.ApplySetCookie(u, []string{"b=1", "c=1"}, t0)
	j.ApplySetCookie(u, []string{"b=; Max-Age=-1", "c=; Expires=Thu, 01 Jan 1970 00:00:01 GMT"}, t0.Add(time.Second))
	if j.Len() != 0 {
		t.Fatal("b/c not deleted")
	}
}

func TestDeleteMasksBase(t *testing.T) {
	j := New()
	u := mustURL(t, "https://a.com/")
	j.SetBase([]creds.Cookie{{Name: "s", Value: "v", Domain: "a.com", Path: "/", LastUpdate: t0}})
	j.ApplySetCookie(u, []string{"s=; Max-Age=0"}, t0.Add(time.Minute))
	if len(j.CookiesFor(u, t0)) != 0 {
		t.Fatal("base cookie not masked")
	}
	// Reload with the same stale base: still masked.
	j.SetBase([]creds.Cookie{{Name: "s", Value: "v", Domain: "a.com", Path: "/", LastUpdate: t0}})
	if len(j.CookiesFor(u, t0)) != 0 {
		t.Fatal("stale base resurrected")
	}
	// Newer base wins.
	j.SetBase([]creds.Cookie{{Name: "s", Value: "new", Domain: "a.com", Path: "/", LastUpdate: t0.Add(time.Hour)}})
	if h := CookieHeader(j.CookiesFor(u, t0)); h != "s=new" {
		t.Fatalf("got %q", h)
	}
}

func TestInvalidDomainAttr(t *testing.T) {
	tests := []struct {
		name, url, set string
	}{
		{"single label", "https://a.example.com/", "x=1; Domain=com"},
		{"unrelated host", "https://a.example.com/", "x=1; Domain=evil.com"},
		{"sibling", "https://a.example.com/", "x=1; Domain=b.example.com"},
		{"subdomain of self", "https://example.com/", "x=1; Domain=a.example.com"},
		{"suffix lookalike", "https://notexample.com/", "x=1; Domain=example.com"},
		{"ip literal", "https://127.0.0.1/", "x=1; Domain=0.0.1"},
	}
	for _, tc := range tests {
		j := New()
		j.ApplySetCookie(mustURL(t, tc.url), []string{tc.set}, t0)
		if j.Len() != 0 {
			t.Errorf("%s: cookie accepted", tc.name)
		}
	}
	// Valid: leading dot and uppercase are normalized.
	j := New()
	j.ApplySetCookie(mustURL(t, "https://a.example.com/"), []string{"x=1; Domain=.Example.COM"}, t0)
	if got := j.CookiesFor(mustURL(t, "https://b.example.com/"), t0); len(got) != 1 || got[0].Domain != ".example.com" {
		t.Errorf("got %+v", got)
	}
}

func TestOverlayVsSetBase(t *testing.T) {
	j := New()
	u := mustURL(t, "https://a.com/")
	j.SetBase([]creds.Cookie{
		{Name: "s", Value: "disk1", Domain: "a.com", Path: "/", LastUpdate: t0},
		{Name: "other", Value: "o", Domain: ".a.com", Path: "/", LastUpdate: t0},
	})
	j.ApplySetCookie(u, []string{"s=fresh"}, t0.Add(time.Minute))
	if h := CookieHeader(j.CookiesFor(u, t0)); h != "other=o; s=fresh" && h != "s=fresh; other=o" {
		t.Fatalf("overlay should win: %q", h)
	}
	// Older disk copy: overlay survives.
	j.SetBase([]creds.Cookie{{Name: "s", Value: "disk2", Domain: "a.com", Path: "/", LastUpdate: t0.Add(time.Second)}})
	if h := CookieHeader(j.CookiesFor(u, t0)); h != "s=fresh" {
		t.Fatalf("overlay should survive older base: %q", h)
	}
	// Newer disk copy: base wins.
	j.SetBase([]creds.Cookie{{Name: "s", Value: "disk3", Domain: "a.com", Path: "/", LastUpdate: t0.Add(time.Hour)}})
	if h := CookieHeader(j.CookiesFor(u, t0)); h != "s=disk3" {
		t.Fatalf("newer base should win: %q", h)
	}
	if j.Len() != 1 {
		t.Fatalf("len %d", j.Len())
	}
}

func TestBaseCookieMatchingAndZero(t *testing.T) {
	j := New()
	j.SetBase([]creds.Cookie{
		{Name: "d", Value: "1", Domain: ".example.com", Path: "/", Secure: true},
		{Name: "h", Value: "2", Domain: "www.example.com", Path: ""},
	})
	if got := names(j.CookiesFor(mustURL(t, "https://www.example.com/p"), t0)); len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if got := names(j.CookiesFor(mustURL(t, "http://www.example.com/p"), t0)); !eq(got, []string{"h"}) {
		t.Errorf("http: %v", got)
	}
	if got := j.CookiesFor(mustURL(t, "https://example.com/"), t0); len(got) != 1 {
		t.Errorf("apex: %v", names(got))
	}
	j.Zero()
	if j.Len() != 0 || len(j.CookiesFor(mustURL(t, "https://www.example.com/"), t0)) != 0 {
		t.Error("Zero left cookies")
	}
}

func TestPortIgnoredAndCase(t *testing.T) {
	j := New()
	j.ApplySetCookie(mustURL(t, "https://A.Example.com:8443/"), []string{"x=1"}, t0)
	if got := j.CookiesFor(mustURL(t, "https://a.example.com/"), t0); len(got) != 1 {
		t.Errorf("got %v", got)
	}
}

func TestAll(t *testing.T) {
	j := New()
	j.SetBase([]creds.Cookie{
		{Name: "session", Value: "old", Domain: "app.example.com", Path: "/", LastUpdate: t0.Add(-time.Hour)},
		{Name: "gone", Value: "g", Domain: "app.example.com", Path: "/", LastUpdate: t0.Add(-time.Hour)},
		{Name: "stale", Value: "s", Domain: "app.example.com", Path: "/", Expires: t0.Add(-time.Minute)},
		{Name: "wide", Value: "w", Domain: ".example.com", Path: "/a", Expires: t0.Add(time.Hour)},
	})
	u := mustURL(t, "https://app.example.com/")
	j.ApplySetCookie(u, []string{"session=new; Path=/", "gone=; Max-Age=-1; Path=/", "fresh=f; Path=/x"}, t0)

	got := j.All(t0)
	var have []string
	for _, c := range got {
		have = append(have, c.Name+"="+c.Value)
	}
	want := []string{"wide=w", "session=new", "fresh=f"} // by domain (".example.com" first), path, name
	if !eq(have, want) {
		t.Fatalf("All = %v, want %v", have, want)
	}
	if got := j.All(t0.Add(2 * time.Hour)); len(got) != 2 { // wide expired; session cookies stay
		t.Fatalf("after expiry: %d cookies, want 2", len(got))
	}
}
