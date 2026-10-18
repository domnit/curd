package consent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Scripted is a Prompter for test mode (spec 15.4). It never shows UI.
type Scripted struct {
	mu       sync.Mutex
	mode     string // "allow-all", "deny-all", "script"
	prompts  []scriptPrompt
	next     int
	failures []string
}

type scriptFile struct {
	Prompts []scriptPrompt `yaml:"prompts"`
}

type scriptPrompt struct {
	Expect expectation `yaml:"expect"`
	Answer string      `yaml:"answer"`
}

// expectation lists optional constraints; unset fields match anything.
type expectation struct {
	Kind       string   `yaml:"kind"`
	Policies   []string `yaml:"policies"`
	Hosts      []string `yaml:"hosts"`
	Scope      string   `yaml:"scope"`
	ClientName string   `yaml:"client_name"`
	SessionKey string   `yaml:"session_key"`
	Purpose    string   `yaml:"purpose"`
}

// NewScripted builds a responder from spec: "allow-all", "deny-all" or
// "script:<path>".
func NewScripted(spec string) (*Scripted, error) {
	switch {
	case spec == "allow-all" || spec == "deny-all":
		return &Scripted{mode: spec}, nil
	case strings.HasPrefix(spec, "script:"):
		path := strings.TrimPrefix(spec, "script:")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read consent script: %w", err)
		}
		var f scriptFile
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("parse consent script %s: %w", path, err)
		}
		for i, sp := range f.Prompts {
			switch Answer(sp.Answer) {
			case Deny, Once, Session, Approve:
			default:
				return nil, fmt.Errorf("consent script %s: prompt %d: invalid answer %q (want once, session, deny or approve)", path, i+1, sp.Answer)
			}
			switch Kind(sp.Expect.Kind) {
			case "", KindGrant, KindApprovePolicy, KindShutdown:
			default:
				return nil, fmt.Errorf("consent script %s: prompt %d: invalid kind %q", path, i+1, sp.Expect.Kind)
			}
		}
		return &Scripted{mode: "script", prompts: f.Prompts}, nil
	default:
		return nil, fmt.Errorf("invalid consent spec %q (want allow-all, deny-all or script:<file>)", spec)
	}
}

// Ask implements Prompter.
func (s *Scripted) Ask(_ context.Context, p Prompt) (Answer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.mode {
	case "allow-all":
		if p.Kind == KindApprovePolicy || p.Kind == KindShutdown {
			return Approve, nil
		}
		return Session, nil
	case "deny-all":
		return Deny, nil
	}
	if s.next >= len(s.prompts) {
		s.fail("unexpected prompt #%d (%s): the script has no more prompts", s.next+1, describe(p))
		s.next++
		return Deny, nil
	}
	sp := s.prompts[s.next]
	s.next++
	if diff := sp.Expect.mismatch(p); diff != "" {
		s.fail("prompt #%d (%s) did not match the script: %s", s.next, describe(p), diff)
		return Deny, nil
	}
	return Answer(sp.Answer), nil
}

func (s *Scripted) fail(format string, args ...any) {
	s.failures = append(s.failures, fmt.Sprintf(format, args...))
}

// Failures returns the recorded script violations (unexpected or mismatched
// prompts). The test harness turns a non-empty list into a failed run.
func (s *Scripted) Failures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failures...)
}

// Remaining reports how many scripted prompts have not been asked yet.
func (s *Scripted) Remaining() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next >= len(s.prompts) {
		return 0
	}
	return len(s.prompts) - s.next
}

func describe(p Prompt) string {
	return fmt.Sprintf("kind=%s policies=%v scope=%s", p.Kind, p.Policies, p.Scope)
}

func (e expectation) mismatch(p Prompt) string {
	var d []string
	if e.Kind != "" && Kind(e.Kind) != p.Kind {
		d = append(d, fmt.Sprintf("kind %q != %q", p.Kind, e.Kind))
	}
	if e.Policies != nil && !sameSet(e.Policies, p.Policies) {
		d = append(d, fmt.Sprintf("policies %v != %v", p.Policies, e.Policies))
	}
	if e.Hosts != nil && !sameSet(e.Hosts, p.Hosts) {
		d = append(d, fmt.Sprintf("hosts %v != %v", p.Hosts, e.Hosts))
	}
	if e.Scope != "" && e.Scope != p.Scope {
		d = append(d, fmt.Sprintf("scope %q != %q", p.Scope, e.Scope))
	}
	if e.ClientName != "" && e.ClientName != p.ClientName {
		d = append(d, fmt.Sprintf("client_name %q != %q", p.ClientName, e.ClientName))
	}
	if e.SessionKey != "" && e.SessionKey != p.SessionKey {
		d = append(d, fmt.Sprintf("session_key %q != %q", p.SessionKey, e.SessionKey))
	}
	if e.Purpose != "" && e.Purpose != p.Purpose {
		d = append(d, fmt.Sprintf("purpose %q != %q", p.Purpose, e.Purpose))
	}
	return strings.Join(d, "; ")
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
