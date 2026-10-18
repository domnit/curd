package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/domnit/curd/internal/api"
	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/config"
	"github.com/domnit/curd/internal/daemon"
	"github.com/domnit/curd/internal/rpc"
)

func goodTest(dir string) *daemon.TestConfig {
	return &daemon.TestConfig{
		Dir: dir, Consent: "allow-all",
		Source: daemon.TestSource{Kind: daemon.SourceStatic, File: filepath.Join(dir, "f.yaml")},
	}
}

func TestIsolationRules(t *testing.T) {
	dir := shortDir(t)
	tp := config.TestPaths(dir)
	cases := []struct {
		name string
		cfg  daemon.Config
		want string // substring of the error; "" = valid
	}{
		{"valid test", daemon.Config{Mode: config.ModeTest, Paths: tp, Test: goodTest(dir)}, ""},
		{"test without config", daemon.Config{Mode: config.ModeTest, Paths: tp}, "needs a test config"},
		{"test with prod paths", daemon.Config{Mode: config.ModeTest, Paths: config.ProdPaths(), Test: goodTest(dir)}, "test paths"},
		{"test bad consent", daemon.Config{Mode: config.ModeTest, Paths: tp, Test: func() *daemon.TestConfig { c := goodTest(dir); c.Consent = "native"; return c }()}, "consent"},
		{"test real keychain provider", daemon.Config{Mode: config.ModeTest, Paths: tp, Test: func() *daemon.TestConfig {
			c := goodTest(dir)
			c.Source = daemon.TestSource{Kind: daemon.SourceChrome, UserDataDir: dir, KeyProvider: "keychain"}
			return c
		}()}, "mock"},
		{"test unknown source", daemon.Config{Mode: config.ModeTest, Paths: tp, Test: func() *daemon.TestConfig { c := goodTest(dir); c.Source.Kind = "real"; return c }()}, "source.kind"},
		{"test relative dir", daemon.Config{Mode: config.ModeTest, Paths: tp, Test: func() *daemon.TestConfig { c := goodTest("rel"); return c }()}, "absolute"},
		{"prod with test config", daemon.Config{Mode: config.ModeProd, Paths: config.ProdPaths(), Test: goodTest(dir)}, "only allowed in test mode"},
		{"prod bad keychain", daemon.Config{Mode: config.ModeProd, Paths: config.ProdPaths(), KeychainMode: "mock"}, "keychain mode"},
		{"prod ok", daemon.Config{Mode: config.ModeProd, Paths: config.ProdPaths(), KeychainMode: "strict"}, ""},
		{"unknown mode", daemon.Config{Mode: "weird"}, "unknown mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	// New enforces the same rules (not just flag parsing).
	if _, err := daemon.New(daemon.Config{Mode: config.ModeProd, Paths: config.ProdPaths(), Test: goodTest(dir)}); err == nil {
		t.Fatal("prod New accepted a test config")
	}
}

func TestLoadTestConfig(t *testing.T) {
	dir := shortDir(t)
	p := filepath.Join(dir, "t.yaml")
	if err := goodTest(dir).Write(p); err != nil {
		t.Fatal(err)
	}
	tc, err := daemon.LoadTestConfig(p)
	if err != nil || tc.Dir != dir || tc.Source.Kind != "static" {
		t.Fatalf("%+v %v", tc, err)
	}
	os.WriteFile(p, []byte("dir: /x\nbogus: 1\n"), 0o600)
	if _, err := daemon.LoadTestConfig(p); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestUserConfigKeychain(t *testing.T) {
	dir := shortDir(t)
	uc, err := daemon.LoadUserConfig(dir)
	if err != nil || uc.Keychain != "prompt" {
		t.Fatalf("%+v %v", uc, err)
	}
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("keychain: always-allow\nfuture_key: 1\n"), 0o600)
	if uc, err = daemon.LoadUserConfig(dir); err != nil || uc.Keychain != "always-allow" {
		t.Fatalf("%+v %v", uc, err)
	}
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("chrome_binary: /opt/x/chrome\n"), 0o600)
	if uc, err = daemon.LoadUserConfig(dir); err != nil || uc.ChromeBinary != "/opt/x/chrome" {
		t.Fatalf("chrome_binary: %+v %v", uc, err)
	}
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("keychain: whenever\n"), 0o600)
	if _, err = daemon.LoadUserConfig(dir); err == nil {
		t.Fatal("invalid keychain mode accepted")
	}
}

// A production daemon never honors a policy's test: section.
func TestProdRefusesTestPolicies(t *testing.T) {
	home := shortDir(t)
	t.Setenv("HOME", home)
	paths := config.ProdPaths()
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	pol := `name: sneaky
match: {hosts: [app.example.com]}
allow:
  - {methods: [GET], paths: ['^/.*$']}
test:
  host_map: {app.example.com: 127.0.0.1}
`
	os.WriteFile(filepath.Join(paths.PolicyDir, "sneaky.yaml"), []byte(pol), 0o600)
	d, err := daemon.New(daemon.Config{Mode: config.ModeProd, Paths: paths, KeychainMode: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	var cl *rpc.Client
	for i := 0; i < 200 && cl == nil; i++ {
		cl, _ = rpc.Dial(paths.Socket)
		time.Sleep(10 * time.Millisecond)
	}
	if cl == nil {
		t.Fatal("no daemon")
	}
	defer cl.Close()
	var list api.PoliciesListResult
	if err := cl.Call(ctx, api.MethodPoliciesList, nil, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Policies) != 1 || list.Policies[0].Status != "error" || !strings.Contains(list.Policies[0].Error, "test mode") {
		t.Fatalf("%+v", list)
	}
	var res api.FetchResult
	err = cl.Call(ctx, api.MethodFetch, api.FetchParams{Method: "GET", URL: "https://app.example.com/x"}, &res)
	if apierr.CodeOf(err) != apierr.DeniedNoPolicy {
		t.Fatalf("unusable policy was used: %v", err)
	}
	// Plain http is refused in production before anything is sent.
	err = cl.Call(ctx, api.MethodFetch, api.FetchParams{Method: "GET", URL: "http://app.example.com/x", Policy: "sneaky"}, &res)
	if apierr.CodeOf(err) != apierr.DeniedNoPolicy {
		t.Fatalf("%v", err)
	}
}
