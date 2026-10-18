// Package fixture builds test fixtures: real Chrome-made profiles (spec 15.1)
// and static credential files (spec 15.2).
package fixture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domnit/curd/internal/cdp"
	"github.com/domnit/curd/internal/chrome"
	"github.com/domnit/curd/internal/creds"
)

// BuildOptions configures BuildChromeProfile.
type BuildOptions struct {
	Binary       string // Chrome binary; chrome.FindBinary() if empty
	UserDataDir  string // profile root to create/populate (Chrome makes Default/)
	Cookies      []creds.Cookie
	LocalStorage []creds.LocalStorageItem
}

// BuildChromeProfile launches Chrome headless with the mock keychain on
// UserDataDir, seeds the given cookies and localStorage through CDP with no
// network access, and quits Chrome cleanly so everything is flushed to disk.
//
// Cookies with a zero Expires get a one-year expiry (session cookies are not
// persisted by Chrome). A cookie whose Domain has no leading dot is host-only.
func BuildChromeProfile(ctx context.Context, o BuildOptions) (err error) {
	if o.UserDataDir == "" {
		return errors.New("fixture: UserDataDir is required")
	}
	b, err := chrome.Launch(ctx, chrome.LaunchOptions{
		Binary:       o.Binary,
		UserDataDir:  o.UserDataDir,
		Headless:     true,
		MockKeychain: true,
	})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := b.Close(context.Background()); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if len(o.Cookies) > 0 {
		cs := make([]cdpCookie, 0, len(o.Cookies))
		for _, c := range o.Cookies {
			cs = append(cs, toCDPCookie(c))
		}
		if err := b.Conn.Call(ctx, "", "Storage.setCookies", map[string]any{"cookies": cs}, nil); err != nil {
			return fmt.Errorf("fixture: set cookies: %w", err)
		}
	}
	if len(o.LocalStorage) > 0 {
		if err := seedLocalStorage(ctx, b.Conn, o.LocalStorage); err != nil {
			return err
		}
	}
	return nil
}

type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	URL      string  `json:"url,omitempty"`
	Domain   string  `json:"domain,omitempty"`
	Path     string  `json:"path,omitempty"`
	Secure   bool    `json:"secure,omitempty"`
	HTTPOnly bool    `json:"httpOnly,omitempty"`
	SameSite string  `json:"sameSite,omitempty"`
	Expires  float64 `json:"expires"`
}

func toCDPCookie(c creds.Cookie) cdpCookie {
	host := strings.TrimPrefix(c.Domain, ".")
	scheme := "http"
	if c.Secure {
		scheme = "https"
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
	switch c.SameSite {
	case "lax":
		out.SameSite = "Lax"
	case "strict":
		out.SameSite = "Strict"
	case "none":
		out.SameSite = "None"
	}
	exp := c.Expires
	if exp.IsZero() {
		exp = time.Now().AddDate(1, 0, 0)
	}
	out.Expires = float64(exp.Unix())
	return out
}

const blankPage = "<!doctype html><title>fixture</title>"

func seedLocalStorage(ctx context.Context, conn *cdp.Conn, items []creds.LocalStorageItem) error {
	byOrigin := map[string][]creds.LocalStorageItem{}
	for _, it := range items {
		byOrigin[it.Origin] = append(byOrigin[it.Origin], it)
	}
	origins := make([]string, 0, len(byOrigin))
	for o := range byOrigin {
		origins = append(origins, o)
	}
	sort.Strings(origins)

	var tgt struct {
		TargetID string `json:"targetId"`
	}
	if err := conn.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &tgt); err != nil {
		return fmt.Errorf("fixture: create target: %w", err)
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": tgt.TargetID, "flatten": true}, &att); err != nil {
		return fmt.Errorf("fixture: attach: %w", err)
	}
	sid := att.SessionID

	var mu sync.Mutex
	loads := make(chan struct{}, 8)
	var handlerErr error
	unsub := conn.Subscribe(func(ev cdp.Event) {
		if ev.SessionID != sid {
			return
		}
		switch ev.Method {
		case "Page.loadEventFired":
			select {
			case loads <- struct{}{}:
			default:
			}
		case "Fetch.requestPaused":
			var p struct {
				RequestID string `json:"requestId"`
			}
			if json.Unmarshal(ev.Params, &p) != nil {
				return
			}
			err := conn.Call(ctx, sid, "Fetch.fulfillRequest", map[string]any{
				"requestId":       p.RequestID,
				"responseCode":    200,
				"responseHeaders": []map[string]string{{"name": "Content-Type", "value": "text/html"}},
				"body":            base64.StdEncoding.EncodeToString([]byte(blankPage)),
			}, nil)
			if err != nil {
				mu.Lock()
				handlerErr = err
				mu.Unlock()
			}
		}
	})
	defer unsub()

	for _, m := range []string{"Page.enable", "Runtime.enable"} {
		if err := conn.Call(ctx, sid, m, nil, nil); err != nil {
			return fmt.Errorf("fixture: %s: %w", m, err)
		}
	}
	if err := conn.Call(ctx, sid, "Fetch.enable", map[string]any{"patterns": []map[string]string{{"urlPattern": "*"}}}, nil); err != nil {
		return fmt.Errorf("fixture: Fetch.enable: %w", err)
	}

	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("fixture: bad localStorage origin %q", origin)
		}
		var nav struct {
			ErrorText string `json:"errorText"`
		}
		if err := conn.Call(ctx, sid, "Page.navigate", map[string]any{"url": origin + "/"}, &nav); err != nil {
			return fmt.Errorf("fixture: navigate %s: %w", origin, err)
		}
		if nav.ErrorText != "" {
			return fmt.Errorf("fixture: navigate %s: %s", origin, nav.ErrorText)
		}
		select {
		case <-loads:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("fixture: timeout loading %s", origin)
		case <-ctx.Done():
			return ctx.Err()
		}
		for _, it := range byOrigin[origin] {
			k, _ := json.Marshal(it.Key)
			v, _ := json.Marshal(it.Value)
			var res struct {
				ExceptionDetails *struct {
					Text string `json:"text"`
				} `json:"exceptionDetails"`
			}
			err := conn.Call(ctx, sid, "Runtime.evaluate", map[string]any{
				"expression": "localStorage.setItem(" + string(k) + "," + string(v) + ")",
			}, &res)
			if err != nil {
				return fmt.Errorf("fixture: set localStorage on %s: %w", origin, err)
			}
			if res.ExceptionDetails != nil {
				return fmt.Errorf("fixture: set localStorage on %s: script exception: %s", origin, res.ExceptionDetails.Text)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return handlerErr
}
