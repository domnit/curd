package chrome

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha1"
	"errors"
	"fmt"
	"runtime"
)

// KeyProvider supplies candidate AES-128 keys for decrypting Chrome cookies.
// More than one candidate is returned when the exact password is uncertain
// (mock keychain); the decryptor keeps whichever yields valid plaintext.
// Returned keys are secrets.
type KeyProvider interface {
	Name() string
	Keys(ctx context.Context) ([][]byte, error)
}

// pbkdf2Iterations is Chrome's PBKDF2 iteration count for this OS.
func pbkdf2Iterations() int {
	if runtime.GOOS == "darwin" {
		return 1003
	}
	return 1
}

// deriveKey is Chrome's key derivation: PBKDF2-HMAC-SHA1, salt "saltysalt",
// 16-byte output.
func deriveKey(password string, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha1.New, password, []byte("saltysalt"), iterations, 16)
}

type staticProvider struct {
	name      string
	passwords []string
	iters     int
}

func (p staticProvider) Name() string { return p.name }

func (p staticProvider) Keys(context.Context) ([][]byte, error) {
	keys := make([][]byte, 0, len(p.passwords))
	for _, pw := range p.passwords {
		k, err := deriveKey(pw, p.iters)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// StaticProvider derives the key from a fixed password with the given PBKDF2
// iteration count. For hand-built fixtures and test configuration.
func StaticProvider(password string, iterations int) KeyProvider {
	return staticProvider{name: "static", passwords: []string{password}, iters: iterations}
}

type rawProvider struct{ key []byte }

func (p rawProvider) Name() string { return "raw" }

func (p rawProvider) Keys(context.Context) ([][]byte, error) {
	if len(p.key) != 16 {
		return nil, fmt.Errorf("chrome: raw key must be 16 bytes, got %d", len(p.key))
	}
	return [][]byte{append([]byte(nil), p.key...)}, nil
}

// RawKeyProvider uses key (16 bytes) directly as the AES key.
func RawKeyProvider(key []byte) KeyProvider { return rawProvider{key: append([]byte(nil), key...)} }

// MockProvider returns the keys of Chrome's mock keychain (macOS,
// --use-mock-keychain) or basic password store (Linux,
// --password-store=basic). Test mode and fixtures only: these keys are
// publicly known.
func MockProvider() KeyProvider {
	if runtime.GOOS == "darwin" {
		// Chromium's MockAppleKeychain answers FindGenericPassword with
		// "mock_password". The others are fallbacks should that change.
		return staticProvider{name: "mock", passwords: []string{"mock_password", "peanuts", "mock"}, iters: 1003}
	}
	return staticProvider{name: "mock", passwords: []string{"peanuts"}, iters: 1}
}

var errNoKeychain = errors.New("chrome: Chrome Safe Storage key not available")
