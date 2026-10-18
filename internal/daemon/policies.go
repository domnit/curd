package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/audit"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/rpc"
)

// policyView is one consistent load of the policy directory.
type policyView struct {
	set      *policy.Set
	statuses []api.PolicyStatus
}

// policyStore loads policies from a directory and reloads them whenever a
// file in it changed, so editing a policy takes effect without a restart.
type policyStore struct {
	dir  string
	test bool

	mu   sync.Mutex
	sig  string
	view *policyView
}

func newPolicyStore(dir string, test bool) *policyStore {
	return &policyStore{dir: dir, test: test}
}

// signature fingerprints the directory listing (names, sizes, mtimes).
func (s *policyStore) signature() string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "missing:" + err.Error()
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s|%d|%d\n", e.Name(), fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// current returns the up-to-date view, reloading if the directory changed.
func (s *policyStore) current() *policyView {
	sig := s.signature()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view != nil && sig == s.sig {
		return s.view
	}
	s.view = s.load()
	s.sig = sig
	return s.view
}

func (s *policyStore) load() *policyView {
	full, errs := policy.LoadDir(s.dir)
	var kept []*policy.Policy
	var extra []api.PolicyStatus
	for _, p := range full.All() {
		if p.Test != nil && !s.test {
			extra = append(extra, api.PolicyStatus{
				Name: p.Name, File: p.File, Status: policy.StatusError, Hosts: p.Match.Hosts,
				Error: "this policy has a test: section (test.host_map), which is only honored in test mode; remove it. The policy is unusable until then",
			})
			continue
		}
		kept = append(kept, p)
	}
	set := policy.NewSet(kept...)
	st := set.Statuses()
	for _, e := range errs {
		st = append(st, api.PolicyStatus{
			Name:   strings.TrimSuffix(strings.TrimSuffix(filepath.Base(e.File), ".yaml"), ".draft"),
			File:   e.File,
			Status: policy.StatusError,
			Error:  e.Err.Error(),
		})
	}
	st = append(st, extra...)
	sort.SliceStable(st, func(i, j int) bool { return st[i].Name < st[j].Name })
	return &policyView{set: set, statuses: st}
}

// activeNames lists the usable policy names.
func (v *policyView) activeNames() []string {
	var out []string
	for _, p := range v.set.All() {
		if !p.IsDraft() {
			out = append(out, p.Name)
		}
	}
	return out
}

// noPolicyHint lists what exists and how to create one.
func (v *policyView) noPolicyHint(host string) string {
	var b strings.Builder
	if names := v.activeNames(); len(names) > 0 {
		b.WriteString("available policies: " + strings.Join(names, ", ") + " (see `curd policies ls`); ")
	} else {
		b.WriteString("no policies are installed (see `curd policies ls`); ")
	}
	if host == "" {
		host = "<host>"
	}
	b.WriteString("create one with `curd policies new <name> --host " + host + "`, review it, and use it")
	return b.String()
}

func (d *Daemon) registerPolicyHandlers() {
	d.register(api.MethodPoliciesList, d.handlePoliciesList)
	d.register(api.MethodPoliciesShow, d.handlePoliciesShow)
	d.register(api.MethodPolicyApprove, d.handlePolicyApprove)
}

func (d *Daemon) handlePoliciesList(context.Context, rpc.Peer, json.RawMessage) (any, error) {
	return api.PoliciesListResult{Policies: d.policies.current().statuses}, nil
}

func (d *Daemon) handlePoliciesShow(_ context.Context, _ rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.PoliciesShowParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	v := d.policies.current()
	var found *api.PolicyStatus
	for i := range v.statuses {
		if v.statuses[i].Name == p.Name {
			found = &v.statuses[i]
			break
		}
	}
	if found == nil {
		return nil, apierr.Newf(apierr.NotFound, "list policies with `curd policies ls`", "no policy named %q", p.Name)
	}
	var src []byte
	if pol := v.set.GetAny(p.Name); pol != nil && pol.File == found.File {
		src = pol.Source
	} else if b, err := os.ReadFile(found.File); err == nil {
		src = b
	} else {
		return nil, apierr.Newf(apierr.Internal, "", "cannot read policy file %s: %v", found.File, err)
	}
	return api.PoliciesShowResult{Status: *found, YAML: string(src)}, nil
}

var (
	policyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	draftStatus  = regexp.MustCompile(`(?m)^(\s*)status:\s*["']?draft["']?\s*(#.*)?$`)
)

func (d *Daemon) handlePolicyApprove(ctx context.Context, peer rpc.Peer, raw json.RawMessage) (any, error) {
	var p api.PolicyApproveParams
	if err := rpc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	rec := audit.Record{Event: "policy_approve", ClientPID: peer.PID, ClientExe: peer.Exe, Policy: p.Name}
	res, err := d.approvePolicy(ctx, peer, p.Name)
	if err != nil {
		rec.Decision, rec.Code = decisionFor(apierr.CodeOf(err)), apierr.CodeOf(err)
	} else {
		rec.Decision = "allow"
	}
	d.writeAudit(rec)
	return res, err
}

func (d *Daemon) approvePolicy(ctx context.Context, peer rpc.Peer, name string) (any, error) {
	if !policyNameRe.MatchString(name) {
		return nil, apierr.New(apierr.InvalidRequest, "invalid policy name", "names contain letters, digits, '-' and '_'")
	}
	draftPath := filepath.Join(d.cfg.Paths.PolicyDir, name+".draft.yaml")
	activePath := filepath.Join(d.cfg.Paths.PolicyDir, name+".yaml")
	view := d.policies.current()
	pol := view.set.GetAny(name)
	_, draftErr := os.Stat(draftPath)
	_, activeErr := os.Stat(activePath)
	switch {
	case activeErr == nil && draftErr == nil:
		return nil, apierr.Newf(apierr.InvalidRequest,
			fmt.Sprintf("an active policy named %q already exists; rename or delete either %s or %s, then approve again", name, filepath.Base(activePath), filepath.Base(draftPath)),
			"cannot approve draft %q: it would replace the active policy", name)
	case draftErr != nil:
		if activeErr == nil {
			return nil, apierr.Newf(apierr.InvalidRequest, "nothing to approve", "policy %q is already active", name)
		}
		return nil, apierr.Newf(apierr.NotFound, "list policies and drafts with `curd policies ls`", "no draft policy named %q", name)
	case pol == nil || !pol.IsDraft():
		msg := "the draft is invalid"
		for _, s := range view.statuses {
			if s.Name == name && s.Status == policy.StatusError {
				msg = s.Error
			}
		}
		return nil, apierr.Newf(apierr.InvalidRequest, "fix the draft file "+draftPath+" (check it with `curd policies validate`), then approve again",
			"draft %q cannot be approved: %s", name, msg)
	}

	var sums []string
	for i := range pol.Allow {
		sums = append(sums, pol.Allow[i].Summary())
	}
	detail := strings.Join(sums, "; ")
	ans, err := d.prompter.Ask(ctx, consent.Prompt{
		Kind: consent.KindApprovePolicy, Policies: []string{name}, Hosts: pol.Match.Hosts,
		ClientName: clientOf(peer).Name, ClientPID: clientOf(peer).PID, Detail: detail,
	})
	if err != nil || ans != consent.Approve {
		msg := "the user declined to approve the policy"
		if err != nil {
			msg = "could not ask the user to approve the policy: " + err.Error()
		}
		return nil, apierr.New(apierr.DeniedNoGrant, msg, "review the draft with `curd policies show "+name+"` and ask the user to approve it")
	}

	data := pol.Source
	if draftStatus.Match(data) {
		data = draftStatus.ReplaceAll(data, []byte("${1}status: active"))
	}
	np, err := policy.Parse(data, activePath)
	if err != nil || np.IsDraft() {
		return nil, apierr.Newf(apierr.Internal, "", "activating policy %q failed validation: %v", name, err)
	}
	f, err := os.OpenFile(activePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, apierr.Newf(apierr.Internal, "", "write %s: %v", activePath, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(activePath)
		return nil, apierr.Newf(apierr.Internal, "", "write %s: %v", activePath, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(activePath)
		return nil, apierr.Newf(apierr.Internal, "", "write %s: %v", activePath, err)
	}
	if err := os.Remove(draftPath); err != nil {
		return nil, apierr.Newf(apierr.Internal, "", "remove %s: %v", draftPath, err)
	}
	st := api.PolicyStatus{Name: name, File: activePath, Status: policy.StatusActive, Hosts: np.Match.Hosts}
	for i := range np.Allow {
		st.Rules = append(st.Rules, np.Allow[i].Summary())
	}
	return st, nil
}
