// Package chrome finds and launches Chrome, discovers its profiles, and reads
// the credentials Chrome stores on disk (cookies in SQLite, localStorage in
// LevelDB). Everything platform-specific is behind build tags.
package chrome

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/domnit/curd/internal/config"
)

// ErrNoBinary is returned by FindBinary when no browser could be found.
var ErrNoBinary = errors.New("chrome: no Chrome/Chromium binary found; set chrome_binary in ~/.config/curd/config.yaml")

// FindBinary is the test/development lookup: $CURD_CHROME wins, then the
// well-known locations. It must not be used by the production daemon (it
// would let the environment pick the program that receives hoisted cookies);
// production code uses FindBinaryFor(false, configured).
func FindBinary() (string, error) { return FindBinaryFor(true, "") }

// FindBinaryFor locates a Chrome or Chromium executable. With allowEnv
// (test mode only) $CURD_CHROME is honored first. In production allowEnv is
// false: the environment is ignored and only configured (the chrome_binary
// setting of ~/.config/curd/config.yaml, or "") or a fixed well-known
// install path is used. A configured path takes precedence over discovery.
func FindBinaryFor(allowEnv bool, configured string) (string, error) {
	if allowEnv {
		if p := os.Getenv(config.EnvChrome); p != "" {
			if !isFile(p) {
				return "", fmt.Errorf("chrome: %s=%q is not an executable file", config.EnvChrome, p)
			}
			return p, nil
		}
	}
	if configured != "" {
		if !filepath.IsAbs(configured) || !isFile(configured) {
			return "", fmt.Errorf("chrome: configured chrome_binary %q is not an absolute path to an executable file", configured)
		}
		return configured, nil
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		for _, p := range []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			filepath.Join(home, "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			filepath.Join(home, "Applications/Chromium.app/Contents/MacOS/Chromium"),
		} {
			if isFile(p) {
				return p, nil
			}
		}
	default:
		if allowEnv {
			// PATH lookup is a test/dev convenience; production only trusts
			// fixed install locations.
			for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
				if p, err := exec.LookPath(n); err == nil {
					return p, nil
				}
			}
		} else {
			for _, p := range []string{
				"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
				"/opt/google/chrome/chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
				"/snap/bin/chromium",
			} {
				if isFile(p) {
					return p, nil
				}
			}
			return "", ErrNoBinary
		}
		matches, _ := filepath.Glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")
		sort.Strings(matches)
		for i := len(matches) - 1; i >= 0; i-- { // newest first
			if isFile(matches[i]) {
				return matches[i], nil
			}
		}
	}
	return "", ErrNoBinary
}

// DefaultUserDataDir returns Chrome's default user data directory for the
// current OS ("" if the home directory is unknown).
func DefaultUserDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	}
	return filepath.Join(home, ".config", "google-chrome")
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
