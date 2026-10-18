package chrome

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPassword = "unit-test-password"

func encryptCookie(t *testing.T, key []byte, host, value string, hashPrefix bool) []byte {
	t.Helper()
	pt := []byte(value)
	if hashPrefix {
		sum := sha256.Sum256([]byte(host))
		pt = append(sum[:], pt...)
	}
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	pt = append(pt, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, cbcIV).CryptBlocks(ct, pt)
	return append([]byte("v10"), ct...)
}

type testCookie struct {
	host, name, value string
	enc               []byte
	expires           int64
	secure, httpOnly  int
	samesite          int
}

func makeDB(t *testing.T, version string, full bool, cookies []testCookie) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Cookies")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)")
	exec("INSERT INTO meta VALUES('version', ?)", version)
	if full {
		exec(`CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT,
			expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, last_update_utc INTEGER)`)
		for _, c := range cookies {
			exec("INSERT INTO cookies VALUES(?,?,?,?,?,?,?,?,?,?)", c.host, c.name, c.value, c.enc, "/p", c.expires, c.secure, c.httpOnly, c.samesite, 13300000000000000)
		}
	} else {
		exec("CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)")
		for _, c := range cookies {
			exec("INSERT INTO cookies VALUES(?,?,?,?)", c.host, c.name, c.value, c.enc)
		}
	}
	return path
}

func testKey(t *testing.T) []byte {
	k, err := deriveKey(testPassword, 1003)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func chromeMicros(tm time.Time) int64 { return tm.UnixMicro() + chromeEpochOffsetMicros }

func TestReadCookiesVersions(t *testing.T) {
	key := testKey(t)
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		version string
		hash    bool
	}{{"23", false}, {"24", true}} {
		t.Run("v"+tc.version, func(t *testing.T) {
			path := makeDB(t, tc.version, true, []testCookie{
				{host: "app.example.com", name: "sid", enc: encryptCookie(t, key, "app.example.com", "s3cret=value", tc.hash), expires: chromeMicros(exp), secure: 1, httpOnly: 1, samesite: 1},
				{host: ".example.com", name: "dom", enc: encryptCookie(t, key, ".example.com", "d", tc.hash), samesite: 2},
				{host: "app.example.com", name: "plain", value: "pv", samesite: -1},
				{host: "other.test", name: "no", enc: []byte("v10garbage-not-block-aligned")}, // must never be decrypted
			})
			var seen []string
			got, err := ReadCookies(context.Background(), path, StaticProvider(testPassword, 1003), func(h, n string) bool {
				seen = append(seen, h+"|"+n)
				return h != "other.test"
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(seen) != 4 {
				t.Fatalf("filter saw %v", seen)
			}
			if len(got) != 3 {
				t.Fatalf("got %d cookies", len(got))
			}
			byName := map[string]int{}
			for i, c := range got {
				byName[c.Name] = i
			}
			sid := got[byName["sid"]]
			if sid.Value != "s3cret=value" || sid.Domain != "app.example.com" || sid.Path != "/p" || !sid.Secure || !sid.HTTPOnly ||
				sid.SameSite != "lax" || !sid.Expires.Equal(exp) {
				t.Errorf("sid = %+v", sid)
			}
			dom := got[byName["dom"]]
			if dom.Value != "d" || dom.SameSite != "strict" || !dom.Expires.IsZero() || dom.HostOnly() {
				t.Errorf("dom = %+v", dom)
			}
			if p := got[byName["plain"]]; p.Value != "pv" || p.SameSite != "" {
				t.Errorf("plain = %+v", p)
			}
		})
	}
}

func TestReadCookiesWrongKeyDoesNotLeak(t *testing.T) {
	key := testKey(t)
	const secret = "TOPSECRETVALUE-123456"
	for _, hash := range []bool{false, true} {
		v := "23"
		if hash {
			v = "24"
		}
		path := makeDB(t, v, true, []testCookie{{host: "a.test", name: "sid", enc: encryptCookie(t, key, "a.test", secret, hash)}})
		_, err := ReadCookies(context.Background(), path, StaticProvider("some-other-password", 1003), nil)
		if err == nil {
			// v23 has a ~1/256 chance of valid padding with a wrong key; the
			// hash check makes v24 reliable.
			if hash {
				t.Fatal("expected error with wrong key")
			}
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks value: %v", err)
		}
	}
}

func TestReadCookiesBadPaddingAndFormat(t *testing.T) {
	key := testKey(t)
	good := encryptCookie(t, key, "a.test", "valuevaluevalue", false)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff // corrupts final block: padding check fails
	cases := map[string][]byte{
		"badpad":   bad,
		"noprefix": []byte("xyz0123456789abcdef"),
		"v11":      append([]byte("v11"), good[3:]...),
	}
	for name, enc := range cases {
		path := makeDB(t, "23", true, []testCookie{{host: "a.test", name: "c", enc: enc}})
		_, err := ReadCookies(context.Background(), path, StaticProvider(testPassword, 1003), nil)
		if name == "v11" {
			if err != nil {
				t.Errorf("v11 with matching key should decrypt: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), "valuevalue") {
			t.Errorf("%s: leak: %v", name, err)
		}
	}
	// v11 with an unusable key yields the dedicated error.
	path := makeDB(t, "23", true, []testCookie{{host: "a.test", name: "c", enc: append([]byte("v11"), good[3:]...)}})
	_, err := ReadCookies(context.Background(), path, StaticProvider("nope", 1003), nil)
	if err == nil || !strings.Contains(err.Error(), "v11") {
		t.Errorf("want v11 error, got %v", err)
	}
}

func TestReadCookiesMinimalSchemaAndCandidates(t *testing.T) {
	key := testKey(t)
	path := makeDB(t, "23", false, []testCookie{{host: "a.test", name: "c", enc: encryptCookie(t, key, "a.test", "v", false)}})
	// Candidate list: first wrong, second right.
	kp := multiProvider{StaticProvider("wrong", 1003), StaticProvider(testPassword, 1003)}
	got, err := ReadCookies(context.Background(), path, kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != "v" || got[0].Path != "/" || !got[0].Expires.IsZero() {
		t.Fatalf("got %+v", got)
	}
	// RawKeyProvider
	got, err = ReadCookies(context.Background(), path, RawKeyProvider(key), nil)
	if err != nil || got[0].Value != "v" {
		t.Fatalf("raw: %v", err)
	}
}

type multiProvider []KeyProvider

func (m multiProvider) Name() string { return "multi" }
func (m multiProvider) Keys(ctx context.Context) ([][]byte, error) {
	var out [][]byte
	for _, p := range m {
		k, err := p.Keys(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, k...)
	}
	return out, nil
}

func TestCountCookies(t *testing.T) {
	path := makeDB(t, "24", true, []testCookie{
		{host: "a.test", name: "x", enc: []byte("v10junk")},
		{host: ".a.test", name: "y", enc: []byte("v10junk")},
		{host: "b.test", name: "z", enc: []byte("v10junk")},
	})
	n, err := CountCookies(context.Background(), path, func(h, _ string) bool { return strings.HasSuffix(h, "a.test") })
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestChromeTime(t *testing.T) {
	if !chromeTime(0).IsZero() {
		t.Error("0 should be session")
	}
	want := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := chromeTime(chromeMicros(want)); !got.Equal(want) {
		t.Errorf("got %v", got)
	}
}

func TestReadCookiesWAL(t *testing.T) {
	key := testKey(t)
	path := filepath.Join(t.TempDir(), "Cookies")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)",
		"INSERT INTO meta VALUES('version','24')",
		"CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// Row lives only in the -wal file while the writer is still open.
	if _, err := db.Exec("INSERT INTO cookies VALUES('w.test','c','',?)", encryptCookie(t, key, "w.test", "walvalue", true)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCookies(context.Background(), path, RawKeyProvider(key), nil)
	if err != nil || len(got) != 1 || got[0].Value != "walvalue" {
		t.Fatalf("got %v err %v", len(got), err)
	}
}
