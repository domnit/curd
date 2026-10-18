package fixture

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
)

// failingProvider fails the test if any key is requested.
type failingProvider struct{ t *testing.T }

func (failingProvider) Name() string { return "must-not-be-used" }
func (p failingProvider) Keys(context.Context) ([][]byte, error) {
	p.t.Error("key provider consulted although no row passed the filter")
	return nil, nil
}

// TestChromeMadeProfile is the Phase 1A proof (spec 15.1, 17): it builds a
// profile with the installed Chrome, then reads it back with curd's own
// SQLite/AES and LevelDB readers.
func TestChromeMadeProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Chrome fixture test in -short mode")
	}
	bin, err := chrome.FindBinary()
	if err != nil {
		t.Skipf("no Chrome available: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "udd")
	exp := time.Now().Add(48 * time.Hour).Truncate(time.Second).UTC()

	cookies := []creds.Cookie{
		{Name: "hostonly", Value: "h-value-1", Domain: "app.example.com", Path: "/", HTTPOnly: true, SameSite: "lax", Expires: exp},
		{Name: "domain", Value: "d=value-2_ünï", Domain: ".example.com", Path: "/", SameSite: "strict", Expires: exp},
		{Name: "secure", Value: "s-value-3", Domain: "app.example.com", Path: "/api", Secure: true, SameSite: "none", Expires: exp},
		{Name: "unrelated", Value: "SHOULD-NOT-BE-DECRYPTED", Domain: "other.test", Path: "/", Expires: exp},
	}
	ls := []creds.LocalStorageItem{
		{Origin: "https://app.example.com", Key: "ascii", Value: "plain-token-123"},
		{Origin: "https://app.example.com", Key: "unicode", Value: "héllo ☃ 日本語 😀"},
		{Origin: "https://app.example.com", Key: "unwanted", Value: "nope"},
		{Origin: "https://other.test", Key: "ascii", Value: "other-origin"},
		{Origin: "https://app.example.com", Key: "last-before-close", Value: "written-last"},
	}
	start := time.Now()
	if err := BuildChromeProfile(context.Background(), BuildOptions{Binary: bin, UserDataDir: dir, Cookies: cookies, LocalStorage: ls}); err != nil {
		t.Fatalf("BuildChromeProfile: %v", err)
	}
	t.Logf("fixture built in %v", time.Since(start))

	profiles, err := chrome.Profiles(dir)
	if err != nil || len(profiles) != 1 || profiles[0].Name != "Default" {
		t.Fatalf("profiles = %+v, %v", profiles, err)
	}
	p := profiles[0]
	if p.CookiesPath == "" || p.LocalStoragePath == "" {
		t.Fatalf("profile missing stores: %+v", p)
	}
	if v, err := chrome.Version(dir, bin); err != nil {
		t.Errorf("Version: %v", err)
	} else {
		t.Logf("chrome version %s; UA %s", v, chrome.UserAgent(v))
	}

	// Cookies, with filter accounting.
	var seen []string
	var kept []string
	filter := func(host, name string) bool {
		seen = append(seen, host+"|"+name)
		ok := creds.CookieDomainRelevant([]string{"app.example.com"}, host)
		if ok {
			kept = append(kept, name)
		}
		return ok
	}
	if n, err := chrome.CountCookies(context.Background(), p.CookiesPath, func(h, _ string) bool { return h == "other.test" }); err != nil || n != 1 {
		t.Errorf("CountCookies = %d, %v", n, err)
	}
	seen = nil
	got, err := chrome.ReadCookies(context.Background(), p.CookiesPath, chrome.MockProvider(), filter)
	if err != nil {
		t.Fatalf("ReadCookies: %v", err)
	}
	sort.Strings(seen)
	if want := []string{".example.com|domain", "app.example.com|hostonly", "app.example.com|secure", "other.test|unrelated"}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("filter saw %v, want %v", seen, want)
	}
	if len(got) != 3 {
		t.Fatalf("got %d cookies, want 3 (kept=%v)", len(got), kept)
	}
	byName := map[string]creds.Cookie{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if _, ok := byName["unrelated"]; ok {
		t.Fatal("unrelated cookie was returned")
	}
	for _, want := range cookies[:3] {
		g, ok := byName[want.Name]
		if !ok {
			t.Errorf("missing cookie %s", want.Name)
			continue
		}
		if g.Value != want.Value || g.Domain != want.Domain || g.Path != want.Path || g.Secure != want.Secure ||
			g.HTTPOnly != want.HTTPOnly || g.SameSite != want.SameSite || !g.Expires.Equal(want.Expires) {
			t.Errorf("cookie %s mismatch (value equal: %v): got domain=%s path=%s secure=%v httponly=%v samesite=%q exp=%v",
				want.Name, g.Value == want.Value, g.Domain, g.Path, g.Secure, g.HTTPOnly, g.SameSite, g.Expires)
		}
		if g.LastUpdate.IsZero() {
			t.Errorf("cookie %s: LastUpdate not set", want.Name)
		}
	}
	// The unrelated row is only safe if the key is never even requested when
	// nothing passes the filter.
	if _, err := chrome.ReadCookies(context.Background(), p.CookiesPath, failingProvider{t}, func(h, _ string) bool { return false }); err != nil {
		t.Errorf("ReadCookies(no match): %v", err)
	}

	// localStorage.
	items, err := chrome.ReadLocalStorage(context.Background(), p.LocalStoragePath, []creds.LocalStorageSpec{
		{Origin: "https://app.example.com", Keys: []string{"ascii", "unicode", "last-before-close", "absent"}},
	})
	if err != nil {
		t.Fatalf("ReadLocalStorage: %v", err)
	}
	gotLS := map[string]string{}
	for _, it := range items {
		if it.Origin != "https://app.example.com" {
			t.Errorf("unexpected origin %s", it.Origin)
		}
		gotLS[it.Key] = it.Value
	}
	wantLS := map[string]string{"ascii": "plain-token-123", "unicode": "héllo ☃ 日本語 😀", "last-before-close": "written-last"}
	if !reflect.DeepEqual(gotLS, wantLS) {
		t.Errorf("localStorage = %v, want %v", gotLS, wantLS)
	}

	// Record where the data lives: if only a .log exists, the reads above
	// prove .log replay works (spec 5.2).
	ldb, _ := filepath.Glob(filepath.Join(p.LocalStoragePath, "*.ldb"))
	logs, _ := filepath.Glob(filepath.Join(p.LocalStoragePath, "*.log"))
	t.Logf("leveldb after clean close: %d .ldb, %d .log files", len(ldb), len(logs))
	if len(ldb) == 0 && len(logs) == 0 {
		t.Error("no leveldb data files found")
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("fixture test too slow: %v", elapsed)
	}
}

func TestStaticRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	in := &creds.Credentials{
		Cookies: []creds.Cookie{
			{Name: "sid", Value: "v1", Domain: "app.example.com", Path: "/", Secure: true, HTTPOnly: true, SameSite: "lax", Expires: time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)},
			{Name: "s", Value: "v2", Domain: ".example.com", Path: "/x"},
		},
		LocalStorage: []creds.LocalStorageItem{{Origin: "https://app.example.com", Key: "k", Value: "v"}},
	}
	if err := WriteStatic(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n in  %+v\n out %+v", in, out)
	}
}

func TestLoadStaticErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := writeFile(p, body); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const secret = "SUPERSECRETVALUE"
	cases := map[string]string{
		"missing-name": "cookies:\n  - domain: a.test\n    value: " + secret + "\n",
		"bad-samesite": "cookies:\n  - {name: a, domain: a.test, value: " + secret + ", same_site: weird}\n",
		"unknown":      "cookies:\n  - {name: a, domain: a.test, value: " + secret + ", bogus: 1}\n",
		"bad-yaml":     "cookies: [ {name: " + secret + "\n",
	}
	for name, body := range cases {
		_, err := LoadStatic(write(name+".yaml", body))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks value: %v", name, err)
		}
	}
	got, err := LoadStatic(write("ok.yaml", "cookies:\n  - {name: a, value: b, domain: a.test}\nlocal_storage:\n  - {origin: 'https://a.test', key: k, value: v}\n"))
	if err != nil || len(got.Cookies) != 1 || got.Cookies[0].Path != "/" || len(got.LocalStorage) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func writeFile(p, body string) error { return os.WriteFile(p, []byte(body), 0o600) }
