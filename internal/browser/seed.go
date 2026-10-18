package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
	"github.com/domnit/curd/internal/redact"
)

type cdpCookie struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	URL      string   `json:"url,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secure   bool     `json:"secure"`
	HTTPOnly bool     `json:"httpOnly"`
	SameSite string   `json:"sameSite,omitempty"`
	Expires  *float64 `json:"expires,omitempty"`
}

func toCDPCookie(c creds.Cookie, allowHTTP bool) cdpCookie {
	host := strings.TrimPrefix(c.Domain, ".")
	scheme := "https"
	if !c.Secure && allowHTTP {
		scheme = "http"
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	out := cdpCookie{
		Name: c.Name, Value: c.Value, Path: path,
		Secure: c.Secure, HTTPOnly: c.HTTPOnly,
		URL: scheme + "://" + host + path,
	}
	if !c.HostOnly() {
		out.Domain = c.Domain
	}
	switch strings.ToLower(c.SameSite) {
	case "lax":
		out.SameSite = "Lax"
	case "strict":
		out.SameSite = "Strict"
	case "none":
		out.SameSite = "None"
	}
	if !c.Expires.IsZero() {
		e := float64(c.Expires.Unix())
		out.Expires = &e
	}
	return out
}

// seedHoist loads credentials for each policy and seeds them into the
// off-the-record context: cookies with Storage.setCookies, localStorage with
// a document-start script that only writes on the matching origin.
func (s *Session) seedHoist(ctx context.Context) error {
	var cookies []cdpCookie
	var items [][3]string
	for _, p := range s.spec.Policies {
		c, err := s.opts.Load(ctx, p)
		if err != nil {
			e := apierr.As(err)
			if e.Code == apierr.Internal {
				return apierr.Newf(apierr.SourceError, "check the policy's profile and that Chrome is installed", "load credentials for policy %q: %s", p.Name, e.Message)
			}
			return e
		}
		if c == nil {
			continue
		}
		s.addSecrets(redact.FromCredentials(c)...)
		for _, ck := range c.Cookies {
			if !creds.CookieDomainRelevant(p.Match.Hosts, ck.Domain) || !p.CookieNameAllowed(ck.Name) {
				continue
			}
			cookies = append(cookies, toCDPCookie(ck, s.opts.Test))
		}
		for _, it := range c.LocalStorage {
			ou, err := url.Parse(it.Origin)
			if err != nil || (ou.Scheme != "https" && ou.Scheme != "http") || !p.MatchesHost(ou.Hostname()) {
				continue
			}
			items = append(items, [3]string{it.Origin, it.Key, it.Value})
		}
		c.Zero()
	}
	if len(cookies) > 0 {
		params := map[string]any{"browserContextId": s.ctxID, "cookies": cookies}
		if err := s.call(ctx, "", "Storage.setCookies", params, nil); err != nil {
			// One invalid cookie fails the whole batch; retry individually.
			ok := 0
			for _, ck := range cookies {
				one := map[string]any{"browserContextId": s.ctxID, "cookies": []cdpCookie{ck}}
				if s.call(ctx, "", "Storage.setCookies", one, nil) == nil {
					ok++
				}
			}
			if ok == 0 {
				return browserErr("seed cookies: %v", err)
			}
		}
	}
	if len(items) > 0 {
		b, _ := json.Marshal(items)
		s.lsScript = fmt.Sprintf(lsSeedScript, b)
	}
	return nil
}

// lsSeedScript runs in the main world before page scripts. Values are
// embedded as JSON; they only ever land in localStorage of the matching
// origin, and only if the key is absent.
const lsSeedScript = `(() => { try {
  const items = %s;
  const o = location.origin, h = location.protocol + '//' + location.hostname;
  for (const [origin, key, value] of items) {
    if ((origin === o || origin === h) && localStorage.getItem(key) === null) localStorage.setItem(key, value);
  }
} catch (e) {} })();`

func (s *Session) addSecrets(secrets ...redact.Secret) {
	s.red.Add(secrets...)
	if !s.opts.Test {
		return
	}
	s.mu.Lock()
	for _, sec := range secrets {
		if len(sec.Value) >= redact.MinSecretLen {
			s.secrets[sec.Value] = sec.Placeholder
		}
	}
	s.mu.Unlock()
}

// refreshRedactor registers the context's current cookie values (login mode,
// where the daemon does not hold the credentials). The values are used only
// to redact output and never leave this package.
func (s *Session) refreshRedactor(ctx context.Context) {
	if s.spec.Seed != SeedLogin || s.isClosed() {
		return
	}
	var res struct {
		Cookies []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"cookies"`
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.call(cctx, "", "Storage.getCookies", map[string]any{"browserContextId": s.ctxID}, &res); err != nil {
		return
	}
	secs := make([]redact.Secret, 0, len(res.Cookies))
	for _, c := range res.Cookies {
		secs = append(secs, redact.Secret{Value: c.Value, Placeholder: redact.CookiePlaceholder(c.Name)})
	}
	s.addSecrets(secs...)
}

func (s *Session) refreshLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.refreshRedactor(s.ctx)
		case <-s.ctx.Done():
			return
		}
	}
}

// scanProfile is the test-mode assertion of spec 9.4: the profile must never
// have contained an injected value. It runs after the browser exited and
// before the profile is deleted. Findings name the file and the placeholder,
// never the value.
func (s *Session) scanProfile(ctx context.Context) []string {
	s.mu.Lock()
	secrets := make(map[string]string, len(s.secrets))
	for v, ph := range s.secrets {
		secrets[v] = ph
	}
	s.mu.Unlock()
	if len(secrets) == 0 || s.dir == "" {
		return nil
	}
	var findings []string
	_ = filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(s.dir, path)
		st, err := os.Stat(path)
		if err != nil || st.Size() > 256<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for v, ph := range secrets {
			if bytes.Contains(data, []byte(v)) {
				findings = append(findings, fmt.Sprintf("%s: profile file %s contains injected secret %s", s.ID, rel, ph))
			}
		}
		return nil
	})
	for _, rel := range []string{"Default/Cookies", "Default/Network/Cookies"} {
		path := filepath.Join(s.dir, rel)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cs, err := chrome.ReadCookies(ctx, path, chrome.MockProvider(), nil)
		if err != nil {
			continue
		}
		for _, c := range cs {
			if ph, ok := secrets[c.Value]; ok {
				findings = append(findings, fmt.Sprintf("%s: cookie database %s holds cookie %q with injected secret %s", s.ID, rel, c.Name, ph))
			}
		}
	}
	return findings
}
