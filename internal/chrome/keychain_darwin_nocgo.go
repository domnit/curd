//go:build darwin && !cgo

package chrome

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type keychainProvider struct{}

// KeychainProvider returns a provider that shells out to
// /usr/bin/security. Without cgo this is the only option, and it means the
// system `security` tool, not curd, is the keychain client: the keychain ACL
// prompt and any "Always Allow" apply to /usr/bin/security, which every
// process of the user can run. Prefer a cgo build (spec section 5.6).
func KeychainProvider() KeyProvider { return keychainProvider{} }

func (keychainProvider) Name() string { return "keychain(security)" }

func (keychainProvider) Keys(ctx context.Context) ([][]byte, error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password",
		"-w", "-s", "Chrome Safe Storage", "-a", "Chrome").Output()
	if err != nil {
		return nil, fmt.Errorf("%w: security exited with an error", errNoKeychain)
	}
	pw := strings.TrimRight(string(out), "\r\n")
	key, err := deriveKey(pw, pbkdf2Iterations())
	if err != nil {
		return nil, err
	}
	return [][]byte{key}, nil
}
