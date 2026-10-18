package chrome

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var versionRE = regexp.MustCompile(`\d+(\.\d+){1,3}`)

// Version returns Chrome's full version ("141.0.7390.37"). It reads
// "<userDataDir>/Last Version" if present, else runs "binary --version".
func Version(userDataDir, binary string) (string, error) {
	if userDataDir != "" {
		if b, err := os.ReadFile(filepath.Join(userDataDir, "Last Version")); err == nil {
			if v := versionRE.FindString(string(b)); v != "" {
				return v, nil
			}
		}
	}
	if binary == "" {
		return "", errors.New("chrome: cannot determine version: no Last Version file and no binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("chrome: %s --version: %w", binary, err)
	}
	v := versionRE.FindString(string(out))
	if v == "" {
		return "", fmt.Errorf("chrome: unrecognized version output %q", strings.TrimSpace(string(out)))
	}
	return v, nil
}

// UserAgent returns a desktop Chrome user agent for the current OS using
// Chrome's reduced form (Chrome/<major>.0.0.0). version is as returned by
// Version.
func UserAgent(version string) string {
	major, _, _ := strings.Cut(version, ".")
	if major == "" {
		major = "0"
	}
	var platform string
	switch runtime.GOOS {
	case "darwin":
		platform = "Macintosh; Intel Mac OS X 10_15_7"
	case "windows":
		platform = "Windows NT 10.0; Win64; x64"
	default:
		platform = "X11; Linux x86_64"
	}
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36", platform, major)
}
