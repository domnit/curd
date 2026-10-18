package chrome

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/config"
)

func TestFindBinaryEnv(t *testing.T) {
	f := filepath.Join(t.TempDir(), "chrome")
	os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755)
	t.Setenv(config.EnvChrome, f)
	got, err := FindBinary()
	if err != nil || got != f {
		t.Fatalf("got %q, %v", got, err)
	}
	t.Setenv(config.EnvChrome, filepath.Join(t.TempDir(), "missing"))
	if _, err := FindBinary(); err == nil || !strings.Contains(err.Error(), config.EnvChrome) {
		t.Fatalf("err = %v", err)
	}
}

func TestProfiles(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("Default/Local Storage/leveldb")
	os.WriteFile(filepath.Join(root, "Default", "Cookies"), nil, 0o600)
	mk("Profile 10/Network")
	os.WriteFile(filepath.Join(root, "Profile 10", "Network", "Cookies"), nil, 0o600)
	mk("Profile 2")
	mk("System Profile")
	ps, err := Profiles(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "Default,Profile 2,Profile 10" {
		t.Fatalf("names = %v", names)
	}
	if ps[0].CookiesPath != filepath.Join(root, "Default", "Cookies") || ps[0].LocalStoragePath == "" {
		t.Errorf("default = %+v", ps[0])
	}
	if ps[2].CookiesPath != filepath.Join(root, "Profile 10", "Network", "Cookies") {
		t.Errorf("p10 = %+v", ps[2])
	}
	if ps[1].CookiesPath != "" || ps[1].LocalStoragePath != "" {
		t.Errorf("p2 = %+v", ps[1])
	}
	if _, err := Profiles(filepath.Join(root, "nope")); err == nil {
		t.Error("want error")
	}
}

func TestVersionAndUA(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "Last Version"), []byte("141.0.7390.37\n"), 0o600)
	v, err := Version(root, "")
	if err != nil || v != "141.0.7390.37" {
		t.Fatalf("%q %v", v, err)
	}
	script := filepath.Join(t.TempDir(), "fake")
	os.WriteFile(script, []byte("#!/bin/sh\necho 'Google Chrome 130.0.1.2 '\n"), 0o755)
	if runtime.GOOS != "windows" {
		v, err = Version(t.TempDir(), script)
		if err != nil || v != "130.0.1.2" {
			t.Fatalf("%q %v", v, err)
		}
	}
	ua := UserAgent("141.0.7390.37")
	if !strings.Contains(ua, "Chrome/141.0.0.0 Safari/537.36") || !strings.HasPrefix(ua, "Mozilla/5.0 (") {
		t.Errorf("ua = %q", ua)
	}
}

func TestDeriveKeyKnownVector(t *testing.T) {
	// Chrome Linux basic store: PBKDF2-SHA1("peanuts","saltysalt",1,16).
	k, err := deriveKey("peanuts", 1)
	if err != nil || len(k) != 16 {
		t.Fatal(err)
	}
	if got := toHex(k); got != "fd621fe5a2b402539dfa147ca9272778" {
		t.Errorf("key = %s", got)
	}
}

func toHex(b []byte) string {
	const h = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(h[c>>4])
		sb.WriteByte(h[c&15])
	}
	return sb.String()
}
