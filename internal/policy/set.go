package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domnit/curd/internal/api"
)

// LoadError describes a policy file that failed to load.
type LoadError struct {
	File string
	Err  error
}

func (e LoadError) Error() string { return fmt.Sprintf("%s: %v", e.File, e.Err) }

// Unwrap returns the underlying error.
func (e LoadError) Unwrap() error { return e.Err }

// Set is an immutable collection of loaded policies.
type Set struct {
	byName map[string]*Policy
	errs   []LoadError
}

// NewSet builds a Set from already-parsed policies; later duplicates of a
// name are ignored.
func NewSet(ps ...*Policy) *Set {
	s := &Set{byName: map[string]*Policy{}}
	for _, p := range ps {
		if _, dup := s.byName[p.Name]; !dup {
			s.byName[p.Name] = p
		}
	}
	return s
}

// LoadDir loads every *.yaml file in dir. Draft files (*.draft.yaml or
// status: draft) are loaded but inert. Files that fail to parse are reported
// and skipped. A missing dir yields an empty set. If a draft shares its name
// with an active policy, the draft is reported as an error.
func LoadDir(dir string) (*Set, []LoadError) {
	s := &Set{byName: map[string]*Policy{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		s.errs = append(s.errs, LoadError{File: dir, Err: err})
		return s, s.errs
	}
	var parsed []*Policy
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		file := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(file)
		if err != nil {
			s.errs = append(s.errs, LoadError{File: file, Err: err})
			continue
		}
		p, err := Parse(data, file)
		if err != nil {
			s.errs = append(s.errs, LoadError{File: file, Err: err})
			continue
		}
		parsed = append(parsed, p)
	}
	for _, drafts := range []bool{false, true} {
		for _, p := range parsed {
			if p.IsDraft() != drafts {
				continue
			}
			if prev, dup := s.byName[p.Name]; dup {
				s.errs = append(s.errs, LoadError{File: p.File, Err: fmt.Errorf("policy name %q is already used by %s", p.Name, filepath.Base(prev.File))})
				continue
			}
			s.byName[p.Name] = p
		}
	}
	return s, s.errs
}

// Errors returns the load errors recorded by LoadDir.
func (s *Set) Errors() []LoadError { return s.errs }

// Get returns the active policy with the given name, or nil.
func (s *Set) Get(name string) *Policy {
	if p := s.byName[name]; p != nil && !p.IsDraft() {
		return p
	}
	return nil
}

// GetAny returns the policy with the given name including drafts, or nil.
func (s *Set) GetAny(name string) *Policy { return s.byName[name] }

// ForHost returns the active policies whose hosts match host, ordered by name.
func (s *Set) ForHost(host string) []*Policy {
	var out []*Policy
	for _, p := range s.All() {
		if !p.IsDraft() && p.MatchesHost(host) {
			out = append(out, p)
		}
	}
	return out
}

// All returns every policy including drafts, ordered by name.
func (s *Set) All() []*Policy {
	out := make([]*Policy, 0, len(s.byName))
	for _, p := range s.byName {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Statuses summarizes every policy and load error for the status RPC.
func (s *Set) Statuses() []api.PolicyStatus {
	var out []api.PolicyStatus
	for _, p := range s.All() {
		st := api.PolicyStatus{Name: p.Name, File: p.File, Status: StatusActive, Hosts: p.Match.Hosts}
		if p.IsDraft() {
			st.Status = StatusDraft
		}
		for i := range p.Allow {
			st.Rules = append(st.Rules, p.Allow[i].Summary())
		}
		out = append(out, st)
	}
	for _, e := range s.errs {
		out = append(out, api.PolicyStatus{
			Name:   strings.TrimSuffix(strings.TrimSuffix(filepath.Base(e.File), ".yaml"), ".draft"),
			File:   e.File,
			Status: StatusError,
			Error:  e.Err.Error(),
		})
	}
	return out
}
