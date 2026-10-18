package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/source"
)

// Config configures a Daemon. Mode is fixed for the daemon's lifetime
// (spec 15.5); Validate enforces the isolation rules at startup, not only at
// flag parsing.
type Config struct {
	Mode  config.Mode
	Paths config.Paths
	// Test is required in test mode and refused in production.
	Test *TestConfig
	// KeychainMode is prompt, always-allow or strict. Empty means: read it
	// from <ConfigDir>/config.yaml (production) or "mock" (test mode).
	KeychainMode string
	Version      string
	// Logger receives operational messages (never credential values). nil
	// discards them.
	Logger Logger
}

// Logger is the subset of *log.Logger the daemon uses.
type Logger interface {
	Printf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}

// TestConfig is the YAML file passed as `curd daemon --test --test-config f`.
// It is written by `curd test-env up`.
type TestConfig struct {
	// Dir is the test root. Paths must equal config.TestPaths(Dir).
	Dir string `yaml:"dir"`
	// Consent is allow-all, deny-all or script:<file>.
	Consent string     `yaml:"consent"`
	Source  TestSource `yaml:"source"`
	// CACert is the mock upstream's certificate (PEM), trusted by the
	// broker in test mode only.
	CACert       string `yaml:"ca_cert,omitempty"`
	ChromeBinary string `yaml:"chrome_binary,omitempty"`
}

// TestSource selects the credential source in test mode.
type TestSource struct {
	// Kind is "static" (a fixture YAML file) or "chrome" (a Chrome-made
	// profile read with the mock key provider).
	Kind        string `yaml:"kind"`
	File        string `yaml:"file,omitempty"`
	UserDataDir string `yaml:"user_data_dir,omitempty"`
	KeyProvider string `yaml:"key_provider,omitempty"`
}

// Source kinds.
const (
	SourceStatic = "static"
	SourceChrome = "chrome"
)

// LoadTestConfig reads a test config file. Unknown fields are rejected.
func LoadTestConfig(path string) (*TestConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read test config: %w", err)
	}
	var tc TestConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&tc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse test config %s: %w", path, err)
	}
	return &tc, nil
}

// Write writes tc to path (mode 0600).
func (tc *TestConfig) Write(path string) error {
	b, err := yaml.Marshal(tc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Validate enforces the isolation rules of spec 15.5 for c.
func (c Config) Validate() error {
	switch c.Mode {
	case config.ModeProd:
		return c.validateProd()
	case config.ModeTest:
		return c.validateTest()
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
}

func (c Config) validateProd() error {
	if c.Test != nil {
		return errors.New("a test config is only allowed in test mode (curd daemon --test); " +
			"the production daemon refuses scripted consent, static sources, mock key providers and host maps")
	}
	switch c.KeychainMode {
	case "", source.KeychainPrompt, source.KeychainAlwaysAllow, source.KeychainStrict:
	default:
		return fmt.Errorf("keychain mode %q is not valid in production (want prompt, always-allow or strict)", c.KeychainMode)
	}
	if c.Paths.Socket == "" || c.Paths.PolicyDir == "" || c.Paths.AuditLog == "" || c.Paths.StateDir == "" {
		return errors.New("incomplete paths")
	}
	return nil
}

func (c Config) validateTest() error {
	tc := c.Test
	if tc == nil {
		return errors.New("test mode needs a test config: curd daemon --test --test-config <file> (or use `curd test-env up`)")
	}
	if tc.Dir == "" {
		return errors.New("test config: dir is required")
	}
	if !filepath.IsAbs(tc.Dir) {
		return fmt.Errorf("test config: dir %q must be absolute", tc.Dir)
	}
	want := config.TestPaths(tc.Dir)
	if c.Paths != want {
		return errors.New("test mode may only use the test paths under the test dir; refusing to touch production locations")
	}
	prod := config.ProdPaths()
	for _, p := range []string{c.Paths.Socket, c.Paths.StateDir, c.Paths.PolicyDir, c.Paths.AuditLog} {
		for _, q := range []string{prod.Socket, prod.StateDir, prod.PolicyDir, prod.AuditLog} {
			if q != "" && (p == q || strings.HasPrefix(p, q+string(filepath.Separator))) {
				return fmt.Errorf("test mode path %s overlaps production path %s", p, q)
			}
		}
	}
	switch {
	case tc.Consent == "allow-all", tc.Consent == "deny-all":
	case strings.HasPrefix(tc.Consent, "script:") && len(tc.Consent) > len("script:"):
	default:
		return fmt.Errorf("test config: consent %q must be allow-all, deny-all or script:<file>", tc.Consent)
	}
	switch tc.Source.Kind {
	case SourceStatic:
		if tc.Source.File == "" {
			return errors.New("test config: source.file is required for the static source")
		}
	case SourceChrome:
		if tc.Source.UserDataDir == "" {
			return errors.New("test config: source.user_data_dir is required for the chrome source")
		}
		if tc.Source.KeyProvider != "mock" {
			return fmt.Errorf("test config: source.key_provider %q must be \"mock\" (test mode never queries the real keychain)", tc.Source.KeyProvider)
		}
	default:
		return fmt.Errorf("test config: source.kind %q must be static or chrome", tc.Source.Kind)
	}
	if c.KeychainMode != "" && c.KeychainMode != "mock" {
		return fmt.Errorf("keychain mode %q is not valid in test mode", c.KeychainMode)
	}
	return nil
}

// UserConfig is ~/.config/curd/config.yaml.
type UserConfig struct {
	// Keychain is prompt (default), always-allow or strict (spec 5.6).
	Keychain string `yaml:"keychain,omitempty"`
}

// LoadUserConfig reads <configDir>/config.yaml. A missing file yields the
// defaults. Unknown keys are tolerated so other components can add settings.
func LoadUserConfig(configDir string) (UserConfig, error) {
	uc := UserConfig{Keychain: source.KeychainPrompt}
	path := filepath.Join(configDir, "config.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return uc, nil
		}
		return uc, fmt.Errorf("read %s: %w", path, err)
	}
	var in UserConfig
	if err := yaml.Unmarshal(b, &in); err != nil {
		return uc, fmt.Errorf("parse %s: %w", path, err)
	}
	switch in.Keychain {
	case "":
	case source.KeychainPrompt, source.KeychainAlwaysAllow, source.KeychainStrict:
		uc.Keychain = in.Keychain
	default:
		return uc, fmt.Errorf("%s: keychain %q must be prompt, always-allow or strict", path, in.Keychain)
	}
	return uc, nil
}
