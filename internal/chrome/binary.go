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
var ErrNoBinary = errors.New("chrome: no Chrome/Chromium binary found; set " + config.EnvChrome + " to its path")

// FindBinary locates a Chrome or Chromium executable. $CURD_CHROME wins;
// otherwise well-known locations for the current OS are tried.
func FindBinary() (string, error) {
	if p := os.Getenv(config.EnvChrome); p != "" {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return "", fmt.Errorf("chrome: %s=%q is not an executable file", config.EnvChrome, p)
		}
		return p, nil
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
		for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
			if p, err := exec.LookPath(n); err == nil {
				return p, nil
			}
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
