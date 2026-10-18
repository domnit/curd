package testenv

import (
	"strings"
	"testing"

	"github.com/domnit/curd/internal/policy"
)

func TestPoliciesParseCleanly(t *testing.T) {
	for _, set := range []map[string]string{Policies(4443), ExtraPolicies(4443)} {
		for file, y := range set {
			p, err := policy.Parse([]byte(y), file)
			if err != nil {
				t.Errorf("%s: %v", file, err)
				continue
			}
			if len(p.Warnings) != 0 {
				t.Errorf("%s: warnings %v", file, p.Warnings)
			}
			if p.Test == nil {
				t.Errorf("%s: test policies need test.host_map", file)
			}
		}
	}
}

func TestFixtureHasNoSecretsOutsideValues(t *testing.T) {
	for _, c := range FixtureCookies() {
		if !strings.Contains(c.Value, "SECRET") {
			t.Errorf("cookie %s value must contain SECRET so leaks are greppable", c.Name)
		}
	}
	for _, l := range FixtureLocalStorage(1) {
		if !strings.Contains(l.Value, "SECRET") {
			t.Errorf("localStorage %s value must contain SECRET", l.Key)
		}
	}
}

func TestChildEnv(t *testing.T) {
	e := &Env{Dir: "/d", Socket: "/d/s", TLSPort: 1, ControlURL: "http://c"}
	out := childEnv([]string{"A=1", "CURD_TOKEN=crd_x", "CURD_SOCKET=/old"}, e)
	var sock, tok int
	for _, kv := range out {
		switch {
		case kv == "CURD_SOCKET=/d/s":
			sock++
		case strings.HasPrefix(kv, "CURD_SOCKET="), strings.HasPrefix(kv, "CURD_TOKEN="):
			tok++
		}
	}
	if sock != 1 || tok != 0 {
		t.Fatalf("%v", out)
	}
}
