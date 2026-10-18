package fixture

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/domnit/curd/internal/creds"
	"gopkg.in/yaml.v3"
)

// staticFile is the on-disk YAML shape of a static fixture (spec 15.2).
type staticFile struct {
	Cookies      []staticCookie `yaml:"cookies"`
	LocalStorage []staticLS     `yaml:"local_storage"`
}

type staticCookie struct {
	Name     string     `yaml:"name"`
	Value    string     `yaml:"value"`
	Domain   string     `yaml:"domain"`
	Path     string     `yaml:"path,omitempty"`
	Secure   bool       `yaml:"secure,omitempty"`
	HTTPOnly bool       `yaml:"http_only,omitempty"`
	SameSite string     `yaml:"same_site,omitempty"`
	Expires  *time.Time `yaml:"expires,omitempty"`
}

type staticLS struct {
	Origin string `yaml:"origin"`
	Key    string `yaml:"key"`
	Value  string `yaml:"value"`
}

// LoadStatic reads a static fixture file. Unknown fields are rejected. Errors
// never include cookie or localStorage values.
func LoadStatic(path string) (*creds.Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fixture: %w", err)
	}
	var f staticFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err.Error() != "EOF" {
		// yaml.v3 errors quote the offending line, which may hold a value;
		// keep only the line-number part.
		return nil, fmt.Errorf("fixture: %s: invalid YAML (%s)", path, scrub(err))
	}
	out := &creds.Credentials{}
	for i, c := range f.Cookies {
		if c.Name == "" || c.Domain == "" {
			return nil, fmt.Errorf("fixture: %s: cookies[%d]: name and domain are required", path, i)
		}
		ss := strings.ToLower(c.SameSite)
		switch ss {
		case "", "lax", "strict", "none":
		default:
			return nil, fmt.Errorf("fixture: %s: cookies[%d] (%s): same_site must be lax, strict or none", path, i, c.Name)
		}
		ck := creds.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Secure: c.Secure, HTTPOnly: c.HTTPOnly, SameSite: ss,
		}
		if ck.Path == "" {
			ck.Path = "/"
		}
		if c.Expires != nil {
			ck.Expires = *c.Expires
		}
		out.Cookies = append(out.Cookies, ck)
	}
	for i, l := range f.LocalStorage {
		if l.Origin == "" || l.Key == "" {
			return nil, fmt.Errorf("fixture: %s: local_storage[%d]: origin and key are required", path, i)
		}
		out.LocalStorage = append(out.LocalStorage, creds.LocalStorageItem{Origin: l.Origin, Key: l.Key, Value: l.Value})
	}
	return out, nil
}

// scrub reduces a yaml error to its "line N: ..." prefix-free summary without
// echoing document content.
func scrub(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "line "); i >= 0 {
		rest := msg[i:]
		if j := strings.Index(rest, ":"); j > 0 {
			return rest[:j]
		}
	}
	return "parse error"
}

// WriteStatic writes c as a static fixture file (mode 0600).
func WriteStatic(path string, c *creds.Credentials) error {
	var f staticFile
	for _, ck := range c.Cookies {
		sc := staticCookie{
			Name: ck.Name, Value: ck.Value, Domain: ck.Domain, Path: ck.Path,
			Secure: ck.Secure, HTTPOnly: ck.HTTPOnly, SameSite: ck.SameSite,
		}
		if !ck.Expires.IsZero() {
			t := ck.Expires.UTC()
			sc.Expires = &t
		}
		f.Cookies = append(f.Cookies, sc)
	}
	for _, l := range c.LocalStorage {
		f.LocalStorage = append(f.LocalStorage, staticLS{Origin: l.Origin, Key: l.Key, Value: l.Value})
	}
	data, err := yaml.Marshal(&f)
	if err != nil {
		return fmt.Errorf("fixture: marshal: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}
