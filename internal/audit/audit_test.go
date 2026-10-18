package audit

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	l, err := Open(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Write(Record{Event: "fetch", Host: "a.example", Path: "/x", Status: 200, Tags: []string{"explore"}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	recs, err := l.Tail(5)
	if err != nil || len(recs) != 5 {
		t.Fatalf("tail: %d %v", len(recs), err)
	}
	if recs[0]["ts"] == "" || recs[0]["event"] != "fetch" {
		t.Fatalf("rec: %v", recs[0])
	}
	if _, ok := recs[0]["test"]; ok {
		t.Fatal("test flag should be omitted")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
}

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p, Options{MaxBytes: 300, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 30; i++ {
		if err := l.Write(Record{Event: "fetch", Path: "/some/path"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", ".1", ".2"} {
		fi, err := os.Stat(p + name)
		if err != nil {
			t.Fatalf("missing %q: %v", name, err)
		}
		if fi.Size() > 300 {
			t.Fatalf("%q too large: %d", name, fi.Size())
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%q mode %v", name, fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("kept too many files")
	}
}

func TestTestTag(t *testing.T) {
	l, _ := Open(filepath.Join(t.TempDir(), "a.jsonl"), Options{Test: true})
	defer l.Close()
	l.Write(Record{Event: "grant"})
	recs, _ := l.Tail(1)
	if recs[0]["test"] != true {
		t.Fatalf("%v", recs[0])
	}
}

func TestHashToken(t *testing.T) {
	tok := "crd_abcdefghijklmnopqrstuvwxyz234567"
	h := HashToken(tok)
	if h == tok || strings.Contains(h, tok) || !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+16 {
		t.Fatalf("bad hash %q", h)
	}
	if HashToken(tok) != h || HashToken(tok+"x") == h {
		t.Fatal("hash not deterministic/distinct")
	}
}

func TestRedactPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://h.example/a/b":           "/a/b",
		"https://h.example/a/b?token=zzz": "/a/b?<redacted>",
		"https://h.example":               "/",
		"https://h.example/a?":            "/a?<redacted>",
	} {
		u, _ := url.Parse(in)
		if got := RedactPath(u); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
