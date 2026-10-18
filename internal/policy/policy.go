// Package policy loads, validates and enforces curd site policies (spec
// sections 6 and 8): which hosts a policy covers, which credentials it may
// use, which methods, paths and request bodies it allows, and how requests
// and responses are filtered.
//
// Messages and hints produced here never echo request bodies or header
// values, since those may carry secrets.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/domnit/curd/internal/creds"
)

// Defaults applied by Parse when a field is omitted.
const (
	DefaultRequestMaxBody  int64 = 1 << 20  // 1 MiB
	DefaultResponseMaxBody int64 = 10 << 20 // 10 MiB
	DefaultRedirects             = RedirectsSameHost
	DefaultTTL                   = 8 * time.Hour
)

// Redirect modes.
const (
	RedirectsNone     = "none"
	RedirectsSameHost = "same-host-only"
	RedirectsPolicy   = "policy-hosts"
)

// Policy statuses.
const (
	StatusActive = "active"
	StatusDraft  = "draft"
	StatusError  = "error"
)

// Rule scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// Inspector names.
const (
	InspectGraphQLQueryOnly = "graphql_query_only"
	InspectExecPrefix       = "exec:"
)

// Duration is a time.Duration that parses from YAML strings such as "8h" or
// "7d".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"8h\": %w", err)
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func parseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil || fmt.Sprint(n) != days {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return v, nil
}

// Policy is one site's policy file.
type Policy struct {
	Name    string `yaml:"name"`
	Profile string `yaml:"profile,omitempty"`
	// Status is "" or "active" for an active policy, "draft" for an inert one.
	Status string `yaml:"status,omitempty"`
	Match  struct {
		Hosts []string `yaml:"hosts"`
	} `yaml:"match"`
	Credentials struct {
		Cookies      []string           `yaml:"cookies,omitempty"`
		LocalStorage []LocalStorageRule `yaml:"local_storage,omitempty"`
	} `yaml:"credentials,omitempty"`
	Allow   []Rule `yaml:"allow"`
	Request struct {
		HeaderAllowlist []string `yaml:"header_allowlist,omitempty"`
		MaxBodyBytes    int64    `yaml:"max_body_bytes,omitempty"`
	} `yaml:"request,omitempty"`
	Response struct {
		StripHeaders []string `yaml:"strip_headers,omitempty"`
		MaxBodyBytes int64    `yaml:"max_body_bytes,omitempty"`
		Redact       []string `yaml:"redact,omitempty"`
	} `yaml:"response,omitempty"`
	Redirects  string       `yaml:"redirects,omitempty"`
	TTLDefault Duration     `yaml:"ttl_default,omitempty"`
	Test       *TestSection `yaml:"test,omitempty"`

	// File is the path the policy was loaded from. Source is the raw YAML.
	File   string `yaml:"-"`
	Source []byte `yaml:"-"`
	// Warnings lists non-fatal problems found by Parse (for example
	// unanchored path regexes).
	Warnings []string `yaml:"-"`

	redact []*regexp.Regexp
}

// TestSection holds test-mode-only settings. The caller must honor it only in
// test mode.
type TestSection struct {
	HostMap map[string]string `yaml:"host_map,omitempty"`
}

// LocalStorageRule names localStorage keys to extract for an origin and,
// optionally, how to inject a value as a request header.
type LocalStorageRule struct {
	Origin   string   `yaml:"origin"`
	Keys     []string `yaml:"keys"`
	InjectAs string   `yaml:"inject_as,omitempty"`
}

// Rule is one entry of the allow list.
type Rule struct {
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
	Inspect string   `yaml:"inspect,omitempty"`
	// Scope is "", "read" or "write". When empty it is derived, see
	// EffectiveScope.
	Scope    string        `yaml:"scope,omitempty"`
	Disabled bool          `yaml:"disabled,omitempty"`
	GraphQL  *GraphQLAllow `yaml:"graphql,omitempty"`
	Note     string        `yaml:"note,omitempty"`

	paths []*regexp.Regexp
}

// GraphQLAllow narrows graphql_query_only further.
type GraphQLAllow struct {
	// Operations, if non-empty, is the set of allowed operation names.
	Operations []string `yaml:"operations,omitempty"`
	// PersistedHashes lists sha256 hashes of persisted queries that may be
	// sent without query text.
	PersistedHashes []string `yaml:"persisted_hashes,omitempty"`
}

// Injection says to send a localStorage value as a request header.
type Injection struct {
	Origin   string
	Key      string
	Header   string
	Template string // contains "{value}"
}

// Render substitutes value into the template. It fails if the result would
// not be a valid header value.
func (i Injection) Render(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("localStorage value is not usable as a header value")
	}
	return strings.ReplaceAll(i.Template, "{value}", value), nil
}

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	labelRe  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$`)
	tokenRe  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	methodRe = regexp.MustCompile(`^[A-Z]+$`)
)

// Parse parses and validates one policy file. file is the path it came from
// (may be empty); when set, the policy name must equal the file's basename
// without ".yaml" / ".draft.yaml". A ".draft.yaml" file is always a draft.
func Parse(data []byte, file string) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy file is empty")
		}
		return nil, fmt.Errorf("invalid policy YAML: %w", err)
	}
	p.File = file
	p.Source = append([]byte(nil), data...)
	if err := p.validate(); err != nil {
		return nil, err
	}
	if file != "" {
		base := filepath.Base(file)
		stem, isDraft := strings.CutSuffix(base, ".draft.yaml")
		if !isDraft {
			stem = strings.TrimSuffix(base, ".yaml")
		}
		if p.Name != stem {
			return nil, fmt.Errorf("policy name %q must match its file name %q", p.Name, base)
		}
		if isDraft {
			p.Status = StatusDraft
		}
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.Name == "" {
		return errors.New("name is required")
	}
	if !nameRe.MatchString(p.Name) {
		return fmt.Errorf("name %q must contain only letters, digits, '-' and '_'", p.Name)
	}
	switch p.Status {
	case "":
	case StatusActive, StatusDraft:
	default:
		return fmt.Errorf("status %q must be \"active\" or \"draft\"", p.Status)
	}
	if len(p.Match.Hosts) == 0 {
		return errors.New("match.hosts must list at least one host")
	}
	for i, h := range p.Match.Hosts {
		n, err := validateHostPattern(h)
		if err != nil {
			return fmt.Errorf("match.hosts[%d]: %w", i, err)
		}
		p.Match.Hosts[i] = n
	}
	for i, c := range p.Credentials.Cookies {
		if c == "" {
			return fmt.Errorf("credentials.cookies[%d]: empty cookie name pattern", i)
		}
		if _, err := path.Match(c, ""); err != nil {
			return fmt.Errorf("credentials.cookies[%d]: invalid glob %q", i, c)
		}
	}
	for i := range p.Credentials.LocalStorage {
		if err := p.Credentials.LocalStorage[i].validate(); err != nil {
			return fmt.Errorf("credentials.local_storage[%d]: %w", i, err)
		}
	}
	if len(p.Allow) == 0 {
		return errors.New("allow must contain at least one rule")
	}
	for i := range p.Allow {
		if err := p.Allow[i].validate(&p.Warnings); err != nil {
			return fmt.Errorf("allow[%d]: %w", i, err)
		}
	}
	for i, h := range p.Request.HeaderAllowlist {
		if !tokenRe.MatchString(h) {
			return fmt.Errorf("request.header_allowlist[%d]: invalid header name", i)
		}
		if alwaysDropped[strings.ToLower(h)] {
			p.Warnings = append(p.Warnings, fmt.Sprintf("request.header_allowlist: %q is always dropped and cannot be allowed", h))
		}
	}
	if p.Request.MaxBodyBytes < 0 {
		return errors.New("request.max_body_bytes must not be negative")
	}
	if p.Request.MaxBodyBytes == 0 {
		p.Request.MaxBodyBytes = DefaultRequestMaxBody
	}
	for i, h := range p.Response.StripHeaders {
		if !tokenRe.MatchString(h) {
			return fmt.Errorf("response.strip_headers[%d]: invalid header name", i)
		}
	}
	if p.Response.MaxBodyBytes < 0 {
		return errors.New("response.max_body_bytes must not be negative")
	}
	if p.Response.MaxBodyBytes == 0 {
		p.Response.MaxBodyBytes = DefaultResponseMaxBody
	}
	p.redact = nil
	for i, r := range p.Response.Redact {
		re, err := regexp.Compile(r)
		if err != nil {
			return fmt.Errorf("response.redact[%d]: invalid regexp: %w", i, err)
		}
		p.redact = append(p.redact, re)
	}
	switch p.Redirects {
	case "":
		p.Redirects = DefaultRedirects
	case RedirectsNone, RedirectsSameHost, RedirectsPolicy:
	default:
		return fmt.Errorf("redirects %q must be one of none, same-host-only, policy-hosts", p.Redirects)
	}
	if p.TTLDefault < 0 {
		return errors.New("ttl_default must be positive")
	}
	if p.TTLDefault == 0 {
		p.TTLDefault = Duration(DefaultTTL)
	}
	if p.Test != nil {
		for h, to := range p.Test.HostMap {
			if _, err := validateHostPattern(h); err != nil || strings.HasPrefix(h, "*") {
				return fmt.Errorf("test.host_map: key %q must be an exact hostname", h)
			}
			if to == "" {
				return fmt.Errorf("test.host_map[%q]: empty target", h)
			}
		}
	}
	return nil
}

// validateHostPattern accepts an exact hostname or a single leading "*."
// wildcard over a multi-label suffix, and returns it lowercased.
func validateHostPattern(h string) (string, error) {
	if h == "" {
		return "", errors.New("empty host")
	}
	l := strings.ToLower(h)
	if strings.ContainsAny(l, "/: \t@?#") {
		return "", fmt.Errorf("host %q must be a bare hostname (no scheme, port or path)", h)
	}
	body := l
	wild := false
	if s, ok := strings.CutPrefix(l, "*."); ok {
		body, wild = s, true
	}
	if strings.Contains(body, "*") {
		return "", fmt.Errorf("host %q: '*' is only allowed as a single leading \"*.\" label", h)
	}
	labels := strings.Split(body, ".")
	for _, lb := range labels {
		if !labelRe.MatchString(lb) {
			return "", fmt.Errorf("host %q is not a valid hostname", h)
		}
	}
	if wild && len(labels) < 2 {
		return "", fmt.Errorf("host %q: wildcard must cover a domain such as \"*.example.com\"", h)
	}
	return l, nil
}

func (l *LocalStorageRule) validate() error {
	u, err := url.Parse(l.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("origin %q must look like https://host[:port]", l.Origin)
	}
	if len(l.Keys) == 0 {
		return errors.New("keys must list at least one localStorage key")
	}
	for _, k := range l.Keys {
		if k == "" {
			return errors.New("empty key")
		}
	}
	if l.InjectAs != "" {
		if _, _, err := parseInjectAs(l.InjectAs); err != nil {
			return fmt.Errorf("inject_as: %w", err)
		}
		if len(l.Keys) != 1 {
			return errors.New("inject_as requires exactly one key")
		}
	}
	return nil
}

// parseInjectAs parses "header:<Name>:<template with {value}>".
func parseInjectAs(s string) (header, tmpl string, err error) {
	rest, ok := strings.CutPrefix(s, "header:")
	if !ok {
		return "", "", errors.New("must have the form 'header:<Name>:<template containing {value}>'")
	}
	header, tmpl, ok = strings.Cut(rest, ":")
	if !ok || header == "" || !tokenRe.MatchString(header) {
		return "", "", errors.New("must have the form 'header:<Name>:<template containing {value}>'")
	}
	if alwaysDropped[strings.ToLower(header)] && !strings.EqualFold(header, "authorization") && !strings.EqualFold(header, "cookie") {
		return "", "", fmt.Errorf("header %q cannot be injected", header)
	}
	if !strings.Contains(tmpl, "{value}") {
		return "", "", errors.New("template must contain {value}")
	}
	if strings.ContainsAny(tmpl, "\r\n\x00") {
		return "", "", errors.New("template contains control characters")
	}
	return header, tmpl, nil
}

func (r *Rule) validate(warnings *[]string) error {
	if len(r.Methods) == 0 {
		return errors.New("methods must list at least one HTTP method")
	}
	for i, m := range r.Methods {
		u := strings.ToUpper(m)
		if !methodRe.MatchString(u) {
			return fmt.Errorf("methods[%d]: %q is not a valid HTTP method", i, m)
		}
		r.Methods[i] = u
	}
	if len(r.Paths) == 0 {
		return errors.New("paths must list at least one path regexp")
	}
	r.paths = r.paths[:0]
	for i, s := range r.Paths {
		re, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("paths[%d]: invalid regexp: %w", i, err)
		}
		if !strings.HasPrefix(s, "^") || !strings.HasSuffix(s, "$") {
			*warnings = append(*warnings, fmt.Sprintf("path regexp %q is not fully anchored; use ^...$ so it matches the whole path", s))
		}
		r.paths = append(r.paths, re)
	}
	switch {
	case r.Inspect == "", r.Inspect == InspectGraphQLQueryOnly:
	case strings.HasPrefix(r.Inspect, InspectExecPrefix):
		if !filepath.IsAbs(strings.TrimPrefix(r.Inspect, InspectExecPrefix)) {
			return errors.New("inspect exec: path must be absolute")
		}
	default:
		return fmt.Errorf("inspect %q must be graphql_query_only or exec:<absolute path>", r.Inspect)
	}
	switch r.Scope {
	case "", ScopeRead, ScopeWrite:
	default:
		return fmt.Errorf("scope %q must be \"read\" or \"write\"", r.Scope)
	}
	if r.GraphQL != nil && r.Inspect != InspectGraphQLQueryOnly {
		return errors.New("graphql block requires inspect: graphql_query_only")
	}
	return nil
}

// Marshal serializes p as YAML suitable for writing a draft. The output
// round-trips through Parse.
func Marshal(p *Policy) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return buf.Bytes(), nil
}

// IsDraft reports whether the policy is inert.
func (p *Policy) IsDraft() bool { return p.Status == StatusDraft }

// MatchesHost reports whether host (a port is ignored) is covered by the
// policy's match.hosts.
func (p *Policy) MatchesHost(host string) bool {
	return creds.MatchAnyHost(p.Match.Hosts, host)
}

// CookieNameAllowed reports whether a cookie name passes
// credentials.cookies; an empty list allows all.
func (p *Policy) CookieNameAllowed(name string) bool {
	if len(p.Credentials.Cookies) == 0 {
		return true
	}
	for _, g := range p.Credentials.Cookies {
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

// InjectRules returns the localStorage-to-header injections.
func (p *Policy) InjectRules() []Injection {
	var out []Injection
	for _, ls := range p.Credentials.LocalStorage {
		if ls.InjectAs == "" || len(ls.Keys) != 1 {
			continue
		}
		h, t, err := parseInjectAs(ls.InjectAs)
		if err != nil {
			continue
		}
		out = append(out, Injection{Origin: ls.Origin, Key: ls.Keys[0], Header: h, Template: t})
	}
	return out
}

// Redact applies response.redact to body, replacing matches with
// "[REDACTED]".
func (p *Policy) Redact(body []byte) []byte {
	for _, re := range p.redact {
		body = re.ReplaceAll(body, []byte("[REDACTED]"))
	}
	return body
}

// StripsResponseHeader reports whether the response header name must be
// removed. Set-Cookie is always stripped.
func (p *Policy) StripsResponseHeader(name string) bool {
	if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Set-Cookie2") {
		return true
	}
	for _, h := range p.Response.StripHeaders {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}
