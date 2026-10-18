package chrome

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Profile is one Chrome profile directory.
type Profile struct {
	Name             string // directory name: "Default", "Profile 1"
	Dir              string // absolute directory
	CookiesPath      string // Cookies SQLite file; "" if absent
	LocalStoragePath string // Local Storage/leveldb directory; "" if absent
}

// Profiles lists the profiles under userDataDir: Default, then Profile N in
// numeric order. Cookies live at <profile>/Network/Cookies in current Chrome
// and <profile>/Cookies in older versions; both are handled.
func Profiles(userDataDir string) ([]Profile, error) {
	st, err := os.Stat(userDataDir)
	if err != nil {
		return nil, fmt.Errorf("chrome: user data dir: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("chrome: user data dir %s is not a directory", userDataDir)
	}
	var dirs []string
	if d := filepath.Join(userDataDir, "Default"); isDir(d) {
		dirs = append(dirs, d)
	}
	others, _ := filepath.Glob(filepath.Join(userDataDir, "Profile *"))
	sort.Slice(others, func(i, j int) bool {
		a, b := profileNum(others[i]), profileNum(others[j])
		if a != b {
			return a < b
		}
		return others[i] < others[j]
	})
	for _, d := range others {
		if isDir(d) {
			dirs = append(dirs, d)
		}
	}
	out := make([]Profile, 0, len(dirs))
	for _, d := range dirs {
		p := Profile{Name: filepath.Base(d), Dir: d}
		for _, c := range []string{filepath.Join(d, "Network", "Cookies"), filepath.Join(d, "Cookies")} {
			if isFile(c) {
				p.CookiesPath = c
				break
			}
		}
		if ls := filepath.Join(d, "Local Storage", "leveldb"); isDir(ls) {
			p.LocalStoragePath = ls
		}
		out = append(out, p)
	}
	return out, nil
}

func profileNum(dir string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(dir), "Profile "))
	if err != nil {
		return 1 << 30
	}
	return n
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
