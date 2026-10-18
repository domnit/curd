package chrome

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/domnit/curd/internal/creds"
	_ "modernc.org/sqlite" // registers driver "sqlite"
)

// hashPrefixVersion is the first cookie DB meta version whose plaintext
// begins with SHA256(host_key).
const hashPrefixVersion = 24

// chromeEpochOffsetMicros converts Chrome time (microseconds since
// 1601-01-01 UTC) to Unix microseconds.
const chromeEpochOffsetMicros = 11644473600 * 1_000_000

// ReadCookies reads cookies from a Chrome Cookies SQLite file. The file (and
// its -journal/-wal) is copied to a private temp dir and opened read-only.
// filter is called with (host_key, name) for every row; only rows for which it
// returns true are decrypted and returned (nil filter selects all). Errors
// never contain cookie values.
//
// Format, verified against Chrome 141 (meta version 24): encrypted_value is
// "v10" + AES-128-CBC(IV = 16 spaces, PKCS#7) whose plaintext is
// SHA256(host_key) followed by the value. For meta version < 24 there is no
// hash prefix.
func ReadCookies(ctx context.Context, cookiesPath string, kp KeyProvider, filter func(hostKey, name string) bool) ([]creds.Cookie, error) {
	var out []creds.Cookie
	var dec *decryptor
	err := withCookieDB(ctx, cookiesPath, func(db *sql.DB, version int) error {
		rows, err := queryCookies(ctx, db)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r cookieRow
			if err := r.scan(rows); err != nil {
				return fmt.Errorf("chrome: scan cookie row: %w", err)
			}
			if filter != nil && !filter(r.host, r.name) {
				continue
			}
			value := r.value
			if len(r.enc) > 0 {
				if dec == nil {
					if kp == nil {
						return errors.New("chrome: no key provider")
					}
					keys, err := kp.Keys(ctx)
					if err != nil {
						return fmt.Errorf("chrome: key provider %s: %w", kp.Name(), err)
					}
					dec = &decryptor{keys: keys}
				}
				v, err := dec.decrypt(r.enc, r.host, version)
				if err != nil {
					return fmt.Errorf("chrome: cookie %q on %s: %w", r.name, r.host, err)
				}
				value = v
			}
			out = append(out, creds.Cookie{
				Name:       r.name,
				Value:      value,
				Domain:     r.host,
				Path:       r.path,
				Secure:     r.secure,
				HTTPOnly:   r.httpOnly,
				SameSite:   sameSiteName(r.sameSite),
				Expires:    chromeTime(r.expires),
				LastUpdate: chromeTime(r.lastUpdate),
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountCookies counts rows selected by filter without decrypting anything.
// It is used to pick the profile that holds a site's cookies.
func CountCookies(ctx context.Context, cookiesPath string, filter func(hostKey, name string) bool) (int, error) {
	n := 0
	err := withCookieDB(ctx, cookiesPath, func(db *sql.DB, _ int) error {
		rows, err := db.QueryContext(ctx, "SELECT host_key, name FROM cookies")
		if err != nil {
			return fmt.Errorf("chrome: query cookies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var host, name string
			if err := rows.Scan(&host, &name); err != nil {
				return err
			}
			if filter == nil || filter(host, name) {
				n++
			}
		}
		return rows.Err()
	})
	return n, err
}

// withCookieDB copies the DB to a private temp dir, opens it read-only, and
// runs fn with the meta version (0 if unknown).
func withCookieDB(ctx context.Context, cookiesPath string, fn func(db *sql.DB, version int) error) error {
	tmp, err := os.MkdirTemp("", "curd-cookies-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	dst := filepath.Join(tmp, "Cookies")
	if err := copyFile(cookiesPath, dst); err != nil {
		return fmt.Errorf("chrome: copy cookie db: %w", err)
	}
	for _, suffix := range []string{"-journal", "-wal"} {
		if _, err := os.Stat(cookiesPath + suffix); err == nil {
			if err := copyFile(cookiesPath+suffix, dst+suffix); err != nil {
				return fmt.Errorf("chrome: copy cookie db: %w", err)
			}
		}
	}
	dsn := (&url.URL{Scheme: "file", Path: dst, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("chrome: open cookie db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	version := 0
	var vs string
	if err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'version'").Scan(&vs); err == nil {
		version, _ = strconv.Atoi(vs)
	}
	return fn(db, version)
}

type cookieRow struct {
	host, name, value, path string
	enc                     []byte
	expires, lastUpdate     int64
	secure, httpOnly        bool
	sameSite                int64
}

func (r *cookieRow) scan(rows *sql.Rows) error {
	var value, path sql.NullString
	var expires, secure, httpOnly, sameSite, lastUpdate sql.NullInt64
	if err := rows.Scan(&r.host, &r.name, &value, &r.enc, &path, &expires, &secure, &httpOnly, &sameSite, &lastUpdate); err != nil {
		return err
	}
	r.value, r.path = value.String, path.String
	if r.path == "" {
		r.path = "/"
	}
	r.expires, r.lastUpdate = expires.Int64, lastUpdate.Int64
	r.secure, r.httpOnly = secure.Int64 != 0, httpOnly.Int64 != 0
	r.sameSite = -1
	if sameSite.Valid {
		r.sameSite = sameSite.Int64
	}
	return nil
}

// queryCookies selects the columns we need, substituting constants for any
// column this Chrome version's schema lacks.
func queryCookies(ctx context.Context, db *sql.DB) (*sql.Rows, error) {
	have := map[string]bool{}
	cols, err := db.QueryContext(ctx, "PRAGMA table_info(cookies)")
	if err != nil {
		return nil, fmt.Errorf("chrome: inspect cookie schema: %w", err)
	}
	for cols.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := cols.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			cols.Close()
			return nil, err
		}
		have[name] = true
	}
	cols.Close()
	for _, req := range []string{"host_key", "name"} {
		if !have[req] {
			return nil, fmt.Errorf("chrome: cookie db has no %s column", req)
		}
	}
	sel := func(col, fallback string) string {
		if have[col] {
			return col
		}
		return fallback + " AS " + col
	}
	q := "SELECT host_key, name, " +
		sel("value", "''") + ", " +
		sel("encrypted_value", "x''") + ", " +
		sel("path", "'/'") + ", " +
		sel("expires_utc", "0") + ", " +
		sel("is_secure", "0") + ", " +
		sel("is_httponly", "0") + ", " +
		sel("samesite", "-1") + ", " +
		sel("last_update_utc", "0") +
		" FROM cookies"
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("chrome: query cookies: %w", err)
	}
	return rows, nil
}

func sameSiteName(v int64) string {
	switch v {
	case 0:
		return "none"
	case 1:
		return "lax"
	case 2:
		return "strict"
	}
	return ""
}

// chromeTime converts Chrome microseconds-since-1601 to time.Time; 0 (and
// anything unrepresentable) is the zero time, meaning "session".
func chromeTime(us int64) time.Time {
	if us <= chromeEpochOffsetMicros {
		return time.Time{}
	}
	return time.UnixMicro(us - chromeEpochOffsetMicros).UTC()
}

// decryptor decrypts cookie values, choosing among candidate keys.
type decryptor struct {
	keys [][]byte
	good int // index of the key that last worked
}

var cbcIV = bytes.Repeat([]byte{' '}, 16)

func (d *decryptor) decrypt(enc []byte, host string, dbVersion int) (string, error) {
	if len(enc) < 3 || enc[0] != 'v' || (enc[1] != '1') || (enc[2] != '0' && enc[2] != '1') {
		return "", errors.New("unsupported encryption format (no v10/v11 prefix)")
	}
	prefix := string(enc[:3])
	ct := enc[3:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", errors.New("malformed ciphertext length")
	}
	if len(d.keys) == 0 {
		return "", errors.New("no candidate keys")
	}
	n := len(d.keys)
	for i := 0; i < n; i++ {
		k := d.keys[(d.good+i)%n]
		pt, ok := decryptCBC(k, ct)
		if !ok {
			continue
		}
		if dbVersion >= hashPrefixVersion {
			sum := sha256.Sum256([]byte(host))
			if len(pt) < len(sum) || !bytes.Equal(pt[:len(sum)], sum[:]) {
				continue // wrong key (or wrong host binding)
			}
			pt = pt[len(sum):]
		}
		d.good = (d.good + i) % n
		return string(pt), nil
	}
	if prefix == "v11" {
		return "", errors.New("v11 (libsecret/keyring) cookies cannot be decrypted with the available key; only the basic password store is supported")
	}
	return "", errors.New("decryption failed: wrong key, bad padding, or host hash mismatch")
}

// decryptCBC decrypts with AES-128-CBC and a space IV and strips PKCS#7
// padding, reporting false if the padding is invalid.
func decryptCBC(key, ct []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, cbcIV).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(pt) {
		return nil, false
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return nil, false
		}
	}
	return pt[:len(pt)-pad], true
}
