// Package config resolves curd's filesystem locations and run mode.
//
// Production and test mode are separate instances with separate socket,
// state, policy and audit locations (spec section 15.5). Mode is fixed at
// daemon launch and cannot change at runtime.
package config

import (
	"os"
	"path/filepath"
)

// Mode is the daemon run mode.
type Mode string

const (
	ModeProd Mode = "prod"
	ModeTest Mode = "test"
)

// Paths are the locations one daemon instance uses.
type Paths struct {
	Socket    string // unix socket, mode 0600
	StateDir  string // audit log, pid files
	PolicyDir string // <name>.yaml policies, <name>.draft.yaml drafts
	ConfigDir string // config.yaml, profile choices
	AuditLog  string
}

// EnvSocket overrides the socket path a client connects to. test-env run sets
// it for the child command.
const EnvSocket = "CURD_SOCKET"

// Other environment variables.
const (
	EnvToken       = "CURD_TOKEN"
	EnvSessionKey  = "CURD_SESSION_KEY"
	EnvChrome      = "CURD_CHROME" // path to a Chrome/Chromium binary
	EnvNoAutostart = "CURD_NO_AUTOSTART"
)

// ProdPaths returns the production locations under the user's home:
// ~/.local/run/curd.sock, ~/.local/state/curd, ~/.config/curd.
func ProdPaths() Paths {
	home, _ := os.UserHomeDir()
	cfg := filepath.Join(home, ".config", "curd")
	state := filepath.Join(home, ".local", "state", "curd")
	return Paths{
		Socket:    filepath.Join(home, ".local", "run", "curd.sock"),
		StateDir:  state,
		PolicyDir: filepath.Join(cfg, "policies"),
		ConfigDir: cfg,
		AuditLog:  filepath.Join(state, "audit.jsonl"),
	}
}

// TestPaths returns the locations for a test-mode instance rooted at dir.
func TestPaths(dir string) Paths {
	return Paths{
		Socket:    filepath.Join(dir, "curd-test.sock"),
		StateDir:  filepath.Join(dir, "state"),
		PolicyDir: filepath.Join(dir, "policies"),
		ConfigDir: dir,
		AuditLog:  filepath.Join(dir, "state", "audit.jsonl"),
	}
}

// ClientSocket returns the socket a CLI client should use: $CURD_SOCKET if
// set, else the production socket.
func ClientSocket() string {
	if s := os.Getenv(EnvSocket); s != "" {
		return s
	}
	return ProdPaths().Socket
}

// EnsureDirs creates the directories in p with private permissions.
func (p Paths) EnsureDirs() error {
	for _, d := range []string{filepath.Dir(p.Socket), p.StateDir, p.PolicyDir, p.ConfigDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}
