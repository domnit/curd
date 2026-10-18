package chrome

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/domnit/curd/internal/creds"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// ReadLocalStorage extracts the requested localStorage keys from a Chrome
// "Local Storage/leveldb" directory. The directory is copied (without LOCK)
// to a private temp dir first, and the copy is opened so the write-ahead .log
// is replayed. Only entries named in specs are decoded and returned.
//
// Chrome's on-disk format, verified against Chrome 141: key =
// "_" + origin + "\x00" + encoding byte (0 = UTF-16LE, 1 = Latin-1) + key
// bytes; value = encoding byte (0 = UTF-16LE, 1 = Latin-1) + value bytes.
// "META:", "METAACCESS:" and "VERSION" records are ignored.
func ReadLocalStorage(ctx context.Context, leveldbDir string, specs []creds.LocalStorageSpec) ([]creds.LocalStorageItem, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	tmp, err := os.MkdirTemp("", "curd-ls-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyDir(leveldbDir, tmp); err != nil {
		return nil, fmt.Errorf("chrome: copy localStorage db: %w", err)
	}
	db, err := leveldb.OpenFile(tmp, &opt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("chrome: open localStorage db: %w", err)
	}
	defer db.Close()

	var out []creds.LocalStorageItem
	for _, spec := range specs {
		want := make(map[string]bool, len(spec.Keys))
		for _, k := range spec.Keys {
			want[k] = true
		}
		it := db.NewIterator(util.BytesPrefix([]byte("_"+spec.Origin+"\x00")), nil)
		prefixLen := len("_" + spec.Origin + "\x00")
		for it.Next() {
			if err := ctx.Err(); err != nil {
				it.Release()
				return nil, err
			}
			key, err := decodeLSString(it.Key()[prefixLen:], true)
			if err != nil || !want[key] {
				continue
			}
			val, err := decodeLSString(it.Value(), false)
			if err != nil {
				it.Release()
				return nil, fmt.Errorf("chrome: localStorage %s key %q: %w", spec.Origin, key, err)
			}
			out = append(out, creds.LocalStorageItem{Origin: spec.Origin, Key: key, Value: val})
		}
		err := it.Error()
		it.Release()
		if err != nil {
			return nil, fmt.Errorf("chrome: read localStorage db: %w", err)
		}
	}
	return out, nil
}

// decodeLSString decodes Chrome's string encoding: a leading byte selecting
// UTF-16LE (0) or Latin-1 (1), then the characters. For keys the leading byte
// is the one following the origin's NUL separator.
func decodeLSString(b []byte, isKey bool) (string, error) {
	if len(b) == 0 {
		if isKey {
			return "", errors.New("empty key")
		}
		return "", nil
	}
	enc, data := b[0], b[1:]
	switch enc {
	case 1:
		rs := make([]rune, len(data))
		for i, c := range data {
			rs[i] = rune(c)
		}
		return string(rs), nil
	case 0:
		if len(data)%2 != 0 {
			return "", errors.New("odd-length UTF-16 data")
		}
		u := make([]uint16, len(data)/2)
		for i := range u {
			u[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
		}
		return string(utf16.Decode(u)), nil
	}
	return "", fmt.Errorf("unknown string encoding marker %d", enc)
}

// copyDir copies the regular files of src into dst, skipping LOCK.
func copyDir(src, dst string) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() || e.Name() == "LOCK" || strings.HasSuffix(e.Name(), ".lock") {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
