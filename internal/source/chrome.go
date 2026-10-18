package source

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
)

// Keychain modes (spec section 5.6).
const (
	// KeychainPrompt fetches the key once (one keychain dialog per daemon
	// start) and keeps it in memory.
	KeychainPrompt = "prompt"
	// KeychainAlwaysAllow is for a binary added to the item's ACL: the key
	// is fetched silently on first use and kept in memory.
	KeychainAlwaysAllow = "always-allow"
	// KeychainStrict never caches the key: it is fetched for each reload
	// and discarded after decrypting.
	KeychainStrict = "strict"
)

// ChromeOptions configures the Chrome profile source.
type ChromeOptions struct {
	UserDataDir string             // default chrome.DefaultUserDataDir()
	Keys        chrome.KeyProvider // default chrome.KeychainProvider()
	KeyMode     string             // prompt (default), always-allow, strict
	// Test allows the mock and static key providers and refuses the real
	// Chrome user data dir (spec section 15.5).
	Test bool
}

type chromeSource struct {
	opts ChromeOptions

	mu  sync.Mutex
	key [][]byte // cached candidate keys unless strict
}

// NewChrome returns a Source that reads cookies and localStorage from a
// Chrome user data dir. It enforces the test/production isolation rules.
func NewChrome(opts ChromeOptions) (creds.Source, error) {
	if opts.UserDataDir == "" {
		opts.UserDataDir = chrome.DefaultUserDataDir()
	}
	if opts.Keys == nil {
		opts.Keys = chrome.KeychainProvider()
	}
	if opts.KeyMode == "" {
		opts.KeyMode = KeychainPrompt
	}
	switch opts.KeyMode {
	case KeychainPrompt, KeychainAlwaysAllow, KeychainStrict:
	default:
		return nil, fmt.Errorf("unknown keychain mode %q (want prompt, always-allow or strict)", opts.KeyMode)
	}
	kind := opts.Keys.Name()
	if opts.Test {
		if strings.HasPrefix(kind, "keychain") || kind == "basic-store" {
			return nil, fmt.Errorf("test mode never queries the real keychain")
		}
		if isRealProfileDir(opts.UserDataDir) {
			return nil, fmt.Errorf("test mode refuses to open the real Chrome profile at %s", opts.UserDataDir)
		}
	} else if kind == "mock" || kind == "static" || kind == "raw" {
		return nil, fmt.Errorf("the %s key provider is only allowed in test mode", kind)
	}
	return &chromeSource{opts: opts}, nil
}

func isRealProfileDir(dir string) bool {
	real, err1 := filepath.Abs(chrome.DefaultUserDataDir())
	d, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return true
	}
	return d == real || strings.HasPrefix(d, real+string(filepath.Separator))
}

func (s *chromeSource) Name() string { return "chrome" }

// Prefetch fetches the key now, for the prompt mode's one dialog at
// startup. It is a no-op in strict mode.
func (s *chromeSource) Prefetch(ctx context.Context) error {
	if s.opts.KeyMode == KeychainStrict {
		return nil
	}
	_, err := s.keys(ctx)
	return err
}

func (s *chromeSource) Load(ctx context.Context, req creds.Request) (*creds.Credentials, error) {
	prof, err := s.pickProfile(ctx, req)
	if err != nil {
		return nil, err
	}
	out := &creds.Credentials{Profile: prof.Name}
	if prof.CookiesPath != "" {
		filter := func(hostKey, name string) bool {
			return creds.CookieDomainRelevant(req.Hosts, hostKey) && nameAllowed(req.CookieNames, name)
		}
		// Only fetch the key if some row will be decrypted.
		n, err := chrome.CountCookies(ctx, prof.CookiesPath, filter)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			keys, err := s.keys(ctx)
			if err != nil {
				return nil, err
			}
			cs, err := chrome.ReadCookies(ctx, prof.CookiesPath, fixedKeys(keys), filter)
			if s.opts.KeyMode == KeychainStrict {
				zeroKeys(keys)
			}
			if err != nil {
				return nil, err
			}
			out.Cookies = cs
		}
	}
	if len(req.LocalStorage) > 0 && prof.LocalStoragePath != "" {
		items, err := chrome.ReadLocalStorage(ctx, prof.LocalStoragePath, req.LocalStorage)
		if err != nil {
			return nil, err
		}
		out.LocalStorage = items
	}
	return out, nil
}

func (s *chromeSource) keys(ctx context.Context) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	k, err := s.opts.Keys.Keys(ctx)
	if err != nil {
		return nil, apierr.New(apierr.SourceError, "could not get Chrome's cookie key from the keychain: "+err.Error(),
			"approve the keychain dialog (run `curd setup` once to allow curd permanently), or check that Chrome is installed")
	}
	if s.opts.KeyMode != KeychainStrict {
		s.key = k
	}
	return k, nil
}

func (s *chromeSource) pickProfile(ctx context.Context, req creds.Request) (chrome.Profile, error) {
	profs, err := chrome.Profiles(s.opts.UserDataDir)
	if err != nil {
		return chrome.Profile{}, apierr.New(apierr.SourceError, err.Error(),
			"is Chrome installed? curd reads the profile in "+s.opts.UserDataDir)
	}
	if len(profs) == 0 {
		return chrome.Profile{}, apierr.New(apierr.SourceError, "no Chrome profiles found in "+s.opts.UserDataDir,
			"open Chrome once and log into the site")
	}
	if req.Profile != "" {
		var names []string
		for _, p := range profs {
			if p.Name == req.Profile {
				return p, nil
			}
			names = append(names, p.Name)
		}
		return chrome.Profile{}, apierr.Newf(apierr.SourceError,
			"fix `profile:` in the policy; available profiles: "+strings.Join(names, ", "),
			"Chrome profile %q not found", req.Profile)
	}
	var with []chrome.Profile
	for _, p := range profs {
		if p.CookiesPath == "" {
			continue
		}
		n, err := chrome.CountCookies(ctx, p.CookiesPath, func(hostKey, name string) bool {
			return creds.CookieDomainRelevant(req.Hosts, hostKey) && nameAllowed(req.CookieNames, name)
		})
		if err == nil && n > 0 {
			with = append(with, p)
		}
	}
	switch len(with) {
	case 1:
		return with[0], nil
	case 0:
		return profs[0], nil // Default first; the site may keep its token in localStorage
	}
	var names []string
	for _, p := range with {
		names = append(names, p.Name)
	}
	return chrome.Profile{}, apierr.Newf(apierr.SourceError,
		"pin one with `profile: <name>` in the policy file",
		"several Chrome profiles have cookies for %s: %s", strings.Join(req.Hosts, ", "), strings.Join(names, ", "))
}

func zeroKeys(keys [][]byte) {
	for _, k := range keys {
		for i := range k {
			k[i] = 0
		}
	}
}

// fixedKeys hands already-fetched candidate keys to chrome.ReadCookies.
type fixedKeys [][]byte

func (fixedKeys) Name() string                             { return "cached" }
func (k fixedKeys) Keys(context.Context) ([][]byte, error) { return k, nil }
