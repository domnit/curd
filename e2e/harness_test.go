// Package e2e drives the real curd binary through `curd test-env` exactly as
// an agent would: CLI in, stdout/stderr/exit codes out, with the mock
// upstream's request log and the audit log as ground truth.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domnit/curd/internal/mockup"
	"github.com/domnit/curd/internal/testenv"
)

var curdBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "curd-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	curdBin = filepath.Join(tmp, "curd")
	_, file, _, _ := runtime.Caller(0)
	cmd := exec.Command("go", "build", "-o", curdBin, "./cmd/curd")
	cmd.Dir = filepath.Dir(filepath.Dir(file))
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building curd failed: %v\n%s", err, out)
		os.RemoveAll(tmp)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

type result struct {
	stdout, stderr string
	code           int
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
}

// env is a running `curd test-env`.
type env struct {
	t    *testing.T
	dir  string // test root
	home string // scratch dir for the curd processes (HOME, cwd, scripts)
	vars map[string]string
	port string

	mu      sync.Mutex
	stderrs []string
}

func tempDir(t *testing.T, prefix string) string {
	t.Helper()
	d, err := os.MkdirTemp("", prefix) // short: unix socket paths have a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// newEnv runs `curd test-env up --dir D <args>` and registers cleanup, which
// first checks that no credential value leaked into logs or CLI stderr.
func newEnv(t *testing.T, upArgs ...string) *env {
	t.Helper()
	e := &env{t: t, home: tempDir(t, "ch"), vars: map[string]string{}}
	e.dir = filepath.Join(tempDir(t, "ce"), "t")
	args := append([]string{"test-env", "up", "--dir", e.dir}, upArgs...)
	r := e.exec(nil, "", args...)
	if r.code != 0 {
		t.Fatalf("test-env up failed: %s", r)
	}
	for _, line := range strings.Split(r.stdout, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			e.vars[k] = v
		}
	}
	u, err := url.Parse(e.vars["CURD_TEST_BASE"])
	if err != nil || e.vars["CURD_SOCKET"] == "" {
		t.Fatalf("bad test-env output: %q", r.stdout)
	}
	e.port = u.Port()
	t.Cleanup(func() {
		e.checkNoLeaks()
		d := e.exec(nil, "", "test-env", "down", "--dir", e.dir)
		if d.code != 0 {
			t.Errorf("test-env down: %s", d)
		}
		if _, err := os.Stat(e.dir); !os.IsNotExist(err) {
			t.Errorf("test-env down left %s behind", e.dir)
		}
	})
	return e
}

func (e *env) base() string { return e.vars["CURD_TEST_BASE"] }
func (e *env) api() string  { return e.vars["CURD_TEST_API"] }
func (e *env) url(host, path string) string {
	return fmt.Sprintf("https://%s:%s%s", host, e.port, path)
}

func (e *env) environ(extra []string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.home, "CURD_SESSION_KEY=e2e-default"}
	for k, v := range e.vars {
		env = append(env, k+"="+v)
	}
	return append(env, extra...) // later entries win
}

// exec runs curd with extra environment entries (KEY=VALUE) and stdin.
func (e *env) exec(extra []string, stdin string, args ...string) result {
	e.t.Helper()
	cmd := exec.Command(curdBin, args...)
	cmd.Dir = e.home
	cmd.Env = e.environ(extra)
	if len(e.vars) == 0 { // test-env up itself
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + e.home, "CURD_NO_AUTOSTART=1"}
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := result{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("running curd: %v", err)
	}
	e.mu.Lock()
	e.stderrs = append(e.stderrs, r.stderr)
	e.mu.Unlock()
	return r
}

func (e *env) curd(args ...string) result { return e.exec(nil, "", args...) }

// curdKey runs curd with a specific session key.
func (e *env) curdKey(key string, args ...string) result {
	return e.exec([]string{"CURD_SESSION_KEY=" + key}, "", args...)
}

func (e *env) fetch(args ...string) result { return e.curd(append([]string{"fetch"}, args...)...) }

// mock helpers

func (e *env) control(method, path string, body any) []byte {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.vars["CURD_TEST_CONTROL"]+path, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

// seen returns what the mock recorded, optionally filtered by host and path.
func (e *env) seen(host, path string) []mockup.Recorded {
	e.t.Helper()
	q := url.Values{}
	if host != "" {
		q.Set("host", host)
	}
	if path != "" {
		q.Set("path", path)
	}
	var rs []mockup.Recorded
	if err := json.Unmarshal(e.control("GET", "/requests?"+q.Encode(), nil), &rs); err != nil {
		e.t.Fatal(err)
	}
	return rs
}

func (e *env) resetMock() { e.control("POST", "/reset", nil) }

func (e *env) installPolicies(files map[string]string) {
	e.t.Helper()
	if err := testenv.WritePolicyFiles(filepath.Join(e.dir, "policies"), files); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) writeScript(yaml string) string {
	e.t.Helper()
	p := filepath.Join(e.home, fmt.Sprintf("script-%d.yaml", time.Now().UnixNano()))
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// auditRecords returns the audit log as records.
func (e *env) auditRecords() []map[string]any {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "state", "audit.jsonl"))
	if err != nil {
		e.t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			e.t.Fatalf("bad audit line %q", line)
		}
		out = append(out, m)
	}
	return out
}

// checkNoLeaks enforces the spec 15.6 row "audit log never contains
// credential values": every mock secret contains "SECRET", and none may be in
// the audit log, the daemon log, or anything curd printed to stderr.
func (e *env) checkNoLeaks() {
	e.t.Helper()
	var files []string
	filepath.Walk(filepath.Join(e.dir, "state"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	files = append(files, filepath.Join(e.dir, "daemon.log"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "SECRET") {
			e.t.Errorf("credential value leaked into %s:\n%s", f, b)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.stderrs {
		if strings.Contains(s, "SECRET") {
			e.t.Errorf("credential value leaked into CLI stderr:\n%s", s)
		}
	}
}

// assertions

func wantCode(t *testing.T, r result, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("want exit %d: %s", code, r)
	}
}

func wantContains(t *testing.T, what, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", what, sub, s)
		}
	}
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

func statDir(p string) (os.FileInfo, error) { return os.Stat(p) }
