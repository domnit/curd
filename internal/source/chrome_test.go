package source

import (
	"context"
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
