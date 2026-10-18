package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/domnit/curd/internal/creds"
)

// StaticFile is the on-disk shape of the test-mode fixture (spec 15.2).
type StaticFile struct {
	Cookies      []StaticCookie       `yaml:"cookies"`
	LocalStorage []StaticLocalStorage `yaml:"local_storage"`
}

// StaticCookie is one fixture cookie.
type StaticCookie struct {
	Name     string    `yaml:"name"`
	Value    string    `yaml:"value"`
	Domain   string    `yaml:"domain"`
	Path     string    `yaml:"path,omitempty"`
	Secure   bool      `yaml:"secure,omitempty"`
	HTTPOnly bool      `yaml:"http_only,omitempty"`
	SameSite string    `yaml:"same_site,omitempty"`
	Expires  time.Time `yaml:"expires,omitempty"`
}

// StaticLocalStorage is one fixture localStorage entry.
type StaticLocalStorage struct {
	Origin string `yaml:"origin"`
	Key    string `yaml:"key"`
	Value  string `yaml:"value"`
}

var yamlLine = regexp.MustCompile(`line \d+`)

// LoadStaticFile reads and validates a fixture file. Errors never include
// file contents (yaml errors can quote values).
func LoadStaticFile(p string) (*StaticFile, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("static source: %w", err)
	}
	var f StaticFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err.Error() != "EOF" {
		where := yamlLine.FindString(err.Error())
		if where == "" {
			where = "unknown position"
		}
		return nil, fmt.Errorf("static source: %s: invalid YAML (%s)", p, where)
	}
	for i, c := range f.Cookies {
		if c.Name == "" || c.Domain == "" {
			return nil, fmt.Errorf("static source: %s: cookies[%d]: name and domain are required", p, i)
		}
		switch strings.ToLower(c.SameSite) {
		case "", "lax", "strict", "none":
		default:
			return nil, fmt.Errorf("static source: %s: cookies[%d]: same_site must be lax, strict or none", p, i)
		}
	}
	for i, l := range f.LocalStorage {
		if l.Origin == "" || l.Key == "" {
			return nil, fmt.Errorf("static source: %s: local_storage[%d]: origin and key are required", p, i)
		}
	}
	return &f, nil
}

// WriteStaticFile writes f atomically with mode 0600.
func WriteStaticFile(p string, f *StaticFile) error {
	if f == nil {
		return errors.New("static source: nil file")
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("static source: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".static-*")
	if err != nil {
		return fmt.Errorf("static source: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("static source: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("static source: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("static source: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("static source: %w", err)
	}
	return nil
}

type staticSource struct{ path string }

// NewStatic returns a test-mode source reading the fixture file at path on
// every Load.
func NewStatic(path string) creds.Source { return &staticSource{path: path} }

func (s *staticSource) Name() string { return "static" }

func (s *staticSource) Load(ctx context.Context, req creds.Request) (*creds.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := LoadStaticFile(s.path)
	if err != nil {
		return nil, err
	}
	var mtime time.Time
	if st, err := os.Stat(s.path); err == nil {
		mtime = st.ModTime()
	}
	out := &creds.Credentials{Profile: "static"}
	for _, c := range f.Cookies {
		if !creds.CookieDomainRelevant(req.Hosts, c.Domain) || !nameAllowed(req.CookieNames, c.Name) {
			continue
		}
		p := c.Path
		if p == "" {
			p = "/"
		}
		out.Cookies = append(out.Cookies, creds.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: p,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, SameSite: strings.ToLower(c.SameSite),
			Expires: c.Expires, LastUpdate: mtime,
		})
	}
	for _, l := range f.LocalStorage {
		if wantsLocalStorage(req.LocalStorage, l.Origin, l.Key) {
			out.LocalStorage = append(out.LocalStorage, creds.LocalStorageItem{Origin: l.Origin, Key: l.Key, Value: l.Value})
		}
	}
	return out, nil
}

func nameAllowed(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, g := range patterns {
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

func wantsLocalStorage(specs []creds.LocalStorageSpec, origin, key string) bool {
	for _, sp := range specs {
		if !strings.EqualFold(sp.Origin, origin) {
			continue
		}
		for _, k := range sp.Keys {
			if k == key {
				return true
			}
		}
	}
	return false
}
