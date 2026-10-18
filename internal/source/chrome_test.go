package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/fixture"
)

func TestChromeSourceIsolation(t *testing.T) {
	if _, err := NewChrome(ChromeOptions{UserDataDir: t.TempDir(), Keys: chrome.MockProvider()}); err == nil {
		t.Fatal("mock provider accepted outside test mode")
	}
	if _, err := NewChrome(ChromeOptions{UserDataDir: chrome.DefaultUserDataDir(), Keys: chrome.MockProvider(), Test: true}); err == nil {
		t.Fatal("real profile accepted in test mode")
	}
	if _, err := NewChrome(ChromeOptions{UserDataDir: filepath.Join(chrome.DefaultUserDataDir(), "Default"), Keys: chrome.MockProvider(), Test: true}); err == nil {
		t.Fatal("dir under the real profile accepted in test mode")
	}
	if _, err := NewChrome(ChromeOptions{UserDataDir: t.TempDir(), Keys: chrome.KeychainProvider(), Test: true}); err == nil {
		t.Fatal("keychain accepted in test mode")
	}
}

func TestChromeSourceFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("launches Chrome")
	}
	bin, err := chrome.FindBinary()
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	exp := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	err = fixture.BuildChromeProfile(context.Background(), fixture.BuildOptions{
		Binary: bin, UserDataDir: dir,
		Cookies: []creds.Cookie{
			{Name: "session", Value: "sess-SECRET", Domain: "app.example.com", Path: "/", Secure: true, Expires: exp},
			{Name: "other", Value: "other-SECRET", Domain: "other.example.net", Path: "/", Secure: true, Expires: exp},
		},
		LocalStorage: []creds.LocalStorageItem{{Origin: "https://app.example.com", Key: "authToken", Value: "tok-SECRET"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	src, err := NewChrome(ChromeOptions{UserDataDir: dir, Keys: chrome.MockProvider(), Test: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := src.Load(context.Background(), creds.Request{
		Hosts:        []string{"app.example.com"},
		LocalStorage: []creds.LocalStorageSpec{{Origin: "https://app.example.com", Keys: []string{"authToken"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Cookies) != 1 || c.Cookies[0].Value != "sess-SECRET" || c.Profile != "Default" {
		t.Fatalf("cookies: %+v", c.Cookies)
	}
	if len(c.LocalStorage) != 1 || c.LocalStorage[0].Value != "tok-SECRET" {
		t.Fatalf("localStorage: %+v", c.LocalStorage)
	}
	if _, err := src.Load(context.Background(), creds.Request{Hosts: []string{"app.example.com"}, Profile: "Nope"}); err == nil || !strings.Contains(err.Error(), "Default") {
		t.Fatalf("pinned missing profile: %v", err)
	}
}

func TestRealProfileRefusal(t *testing.T) {
	home := t.TempDir()
	for _, root := range realProfileRoots(home) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if !isRealProfileDirIn(root, home, "linux") || !isRealProfileDirIn(filepath.Join(root, "Default"), home, "linux") {
			t.Errorf("real browser root %s not refused", root)
		}
	}
	// Every known browser, by name.
	for _, rel := range []string{
		"Library/Application Support/Google/Chrome Beta", "Library/Application Support/Google/Chrome Canary",
		"Library/Application Support/Google/Chrome Dev", "Library/Application Support/Chromium",
		"Library/Application Support/BraveSoftware/Brave-Browser", "Library/Application Support/Microsoft Edge",
		"Library/Application Support/Vivaldi", ".config/chromium", ".config/BraveSoftware/Brave-Browser",
		".config/microsoft-edge", ".config/vivaldi", ".config/google-chrome-beta",
	} {
		if !isRealProfileDirIn(filepath.Join(home, rel, "Profile 1"), home, "linux") {
			t.Errorf("%s not refused", rel)
		}
	}
	// A symlink into a real profile is refused.
	outside := t.TempDir()
	link := filepath.Join(outside, "innocent")
	if err := os.Symlink(filepath.Join(home, ".config", "google-chrome"), link); err != nil {
		t.Fatal(err)
	}
	if !isRealProfileDirIn(link, home, "linux") || !isRealProfileDirIn(filepath.Join(link, "Default"), home, "linux") {
		t.Error("symlink into the real profile accepted")
	}
	// Case differences count on darwin only.
	up := filepath.Join(home, "LIBRARY", "APPLICATION SUPPORT", "GOOGLE", "CHROME")
	if !isRealProfileDirIn(up, home, "darwin") {
		t.Error("case-variant real profile accepted on darwin")
	}
	if isRealProfileDirIn(up, home, "linux") {
		t.Error("case folding applied on linux")
	}
	// A fixture directory elsewhere is fine, existing or not.
	if isRealProfileDirIn(t.TempDir(), home, "linux") || isRealProfileDirIn(filepath.Join(t.TempDir(), "new", "profile"), home, "darwin") {
		t.Error("fixture directory refused")
	}
}
