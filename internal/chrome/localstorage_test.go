package chrome

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/domnit/curd/internal/creds"
	"github.com/syndtr/goleveldb/leveldb"
)

func lsUTF16(s string) []byte {
	out := []byte{0}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestReadLocalStorage(t *testing.T) {
	dir := t.TempDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	put := func(k string, v []byte) {
		if err := db.Put([]byte(k), v, nil); err != nil {
			t.Fatal(err)
		}
	}
	put("VERSION", []byte("1"))
	put("META:https://app.example.com", []byte{8, 1})
	put("METAACCESS:https://app.example.com", []byte{8, 1})
	put("_https://app.example.com\x00\x01token", append([]byte{1}, "abc"...))
	put("_https://app.example.com\x00\x01uni", lsUTF16("héllo ☃ 😀"))
	put("_https://app.example.com\x00\x01latin", []byte{1, 'c', 'a', 'f', 0xe9})
	put("_https://app.example.com\x00\x00k\x00\xe9\x00", append([]byte{1}, "wide-key"...))
	put("_https://app.example.com\x00\x01ignored", append([]byte{1}, "no"...))
	put("_https://other.example.com\x00\x01token", append([]byte{1}, "other-origin"...))
	put("_https://app.example.com.evil\x00\x01token", append([]byte{1}, "prefix-origin"...))
	// Deliberately no db.Close compaction: data lives in the .log.
	logs, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	if len(logs) == 0 {
		t.Fatal("test premise: expected a .log")
	}
	os.WriteFile(filepath.Join(dir, "LOCK-sentinel"), nil, 0o600) // unrelated file is fine

	// Read while the writer still has the DB open (as with a running Chrome):
	// LOCK must not be an obstacle because we copy without it.
	got, err := ReadLocalStorage(context.Background(), dir, []creds.LocalStorageSpec{
		{Origin: "https://app.example.com", Keys: []string{"token", "uni", "latin", "ké", "missing"}},
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"token": "abc", "uni": "héllo ☃ 😀", "latin": "café", "ké": "wide-key"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for _, it := range got {
		if it.Origin != "https://app.example.com" || want[it.Key] != it.Value {
			t.Errorf("item %q = %q", it.Key, it.Value)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "LOCK")); err != nil {
		t.Error("source LOCK must be untouched")
	}
}
