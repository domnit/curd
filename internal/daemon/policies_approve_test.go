package daemon

import (
	"reflect"
	"strings"
	"testing"

	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/policy"
	"github.com/domnit/curd/internal/rpc"
)

func TestApprovePromptDescribesPolicy(t *testing.T) {
	p, err := policy.Parse([]byte(`
name: wide
status: draft
match:
  hosts: [app.example.com, '*.example.net']
credentials:
  local_storage:
    - origin: https://app.example.com
      keys: [authToken]
      inject_as: 'header:Authorization:Bearer {value}'
allow:
  - methods: [GET]
    paths: ['^/api/.*$']
  - methods: [POST]
    paths: ['^/check$']
    inspect: 'exec:/opt/bin/inspect'
redirects: policy-hosts
request:
  header_allowlist: [accept, x-csrf-token]
`), "")
	if err != nil {
		t.Fatal(err)
	}
	pr := approvePrompt(p, rpc.Peer{PID: 9, Exe: "/bin/agent"})
	ps := pr.Policy
	if pr.Kind != consent.KindApprovePolicy || ps == nil {
		t.Fatalf("%+v", pr)
	}
	if len(ps.Rules) != 2 || len(ps.Cookies) != 0 || ps.CookiesNone || ps.Redirects != "policy-hosts" ||
		!reflect.DeepEqual(ps.HeaderAllowlist, []string{"accept", "x-csrf-token"}) ||
		!reflect.DeepEqual(ps.ExecInspectors, []string{"/opt/bin/inspect"}) ||
		!reflect.DeepEqual(ps.LocalStorage, []string{"https://app.example.com authToken -> header Authorization"}) {
		t.Fatalf("summary %+v", ps)
	}
	s := consent.BuildScript(pr)
	for _, want := range []string{"ALL cookies", "authToken", "policy-hosts", "x-csrf-token", "/opt/bin/inspect", "Rules (2):"} {
		if !strings.Contains(s, want) {
			t.Errorf("dialog lacks %q: %s", want, s)
		}
	}
}
