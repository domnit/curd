package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/domnit/curd/internal/apierr"
)

func sockPath(t *testing.T) string {
	d, err := os.MkdirTemp("", "rpc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "run", "curd.sock")
}

func start(t *testing.T, s *Server, path string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, path) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	})
	for i := 0; i < 200; i++ {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start")
}

func echoServer() *Server {
	s := NewServer()
	s.Register("echo", func(ctx context.Context, p Peer, params json.RawMessage) (any, error) {
		var v map[string]any
		if err := DecodeParams(params, &v); err != nil {
			return nil, err
		}
		return v, nil
	})
	s.Register("fail", func(context.Context, Peer, json.RawMessage) (any, error) {
		return nil, apierr.New(apierr.DeniedNoGrant, "no grant", "run curd grants request").With("policy", "x")
	})
	s.Register("boom", func(context.Context, Peer, json.RawMessage) (any, error) {
		return nil, fmt.Errorf("kaput")
	})
	s.Register("peer", func(_ context.Context, p Peer, _ json.RawMessage) (any, error) { return p.PID, nil })
	s.Register("sleep", func(ctx context.Context, _ Peer, params json.RawMessage) (any, error) {
		var d int
		_ = DecodeParams(params, &d)
		select {
		case <-time.After(time.Duration(d) * time.Millisecond):
		case <-ctx.Done():
		}
		return d, nil
	})
	return s
}

func TestRoundTripAndErrors(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	var out map[string]any
	if err := c.Call(ctx, "echo", map[string]any{"a": "b"}, &out); err != nil || out["a"] != "b" {
		t.Fatalf("echo: %v %v", out, err)
	}
	err = c.Call(ctx, "fail", nil, nil)
	ae, ok := err.(*apierr.Error)
	if !ok || ae.Code != apierr.DeniedNoGrant || ae.Hint != "run curd grants request" || ae.Data["policy"] != "x" {
		t.Fatalf("fail: %#v", err)
	}
	if apierr.CodeOf(c.Call(ctx, "boom", nil, nil)) != apierr.Internal {
		t.Fatal("boom should map to internal")
	}
	if err := c.Call(ctx, "nope", nil, nil); apierr.CodeOf(err) != apierr.Internal {
		t.Fatalf("unknown method: %v", err)
	}
	if err := c.Call(ctx, "echo", []int{1}, nil); apierr.CodeOf(err) != apierr.InvalidRequest {
		t.Fatalf("invalid params: %v", err)
	}
}

func TestRawProtocol(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	send := func(s string) map[string]any {
		t.Helper()
		fmt.Fprintln(conn, s)
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	code := func(m map[string]any) float64 { return m["error"].(map[string]any)["code"].(float64) }
	if m := send(`{not json`); code(m) != -32700 {
		t.Fatalf("parse: %v", m)
	}
	if m := send(`{"jsonrpc":"2.0","id":1,"method":"zzz"}`); code(m) != -32601 {
		t.Fatalf("method: %v", m)
	}
	if m := send(`{"jsonrpc":"2.0","id":"s1","method":"echo","params":[1]}`); code(m) != -32602 || m["id"] != "s1" {
		t.Fatalf("params: %v", m)
	}
	m := send(`{"jsonrpc":"2.0","id":"abc","method":"fail"}`)
	d := m["error"].(map[string]any)
	if d["code"].(float64) != -32000 || d["data"].(map[string]any)["code"] != apierr.DeniedNoGrant {
		t.Fatalf("app error: %v", m)
	}
	// Notification: no response; the next reply must belong to the next request.
	fmt.Fprintln(conn, `{"jsonrpc":"2.0","method":"echo","params":{}}`)
	if m := send(`{"jsonrpc":"2.0","id":7,"method":"echo","params":{"k":1}}`); m["id"].(float64) != 7 {
		t.Fatalf("notification produced a response: %v", m)
	}
}

func TestPipeliningAndConcurrency(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A slow call must not block a fast one on the same connection.
	slowDone := make(chan struct{})
	go func() {
		var d int
		_ = c.Call(context.Background(), "sleep", 400, &d)
		close(slowDone)
	}()
	time.Sleep(50 * time.Millisecond)
	start0 := time.Now()
	var d int
	if err := c.Call(context.Background(), "sleep", 1, &d); err != nil {
		t.Fatal(err)
	}
	if time.Since(start0) > 300*time.Millisecond {
		t.Fatal("fast call was blocked behind slow call")
	}
	<-slowDone

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl, err := Dial(path)
			if err != nil {
				t.Error(err)
				return
			}
			defer cl.Close()
			for j := 0; j < 20; j++ {
				var out map[string]any
				if err := cl.Call(context.Background(), "echo", map[string]any{"i": i, "j": j}, &out); err != nil || out["j"].(float64) != float64(j) {
					t.Errorf("call: %v %v", out, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestLargeBody(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	c, _ := Dial(path)
	defer c.Close()
	big := make([]byte, 5<<20)
	for i := range big {
		big[i] = 'a'
	}
	var out map[string]any
	if err := c.Call(context.Background(), "echo", map[string]any{"b": string(big)}, &out); err != nil || len(out["b"].(string)) != len(big) {
		t.Fatalf("large: %v", err)
	}
}

func TestContextCancelAndConnClose(t *testing.T) {
	path := sockPath(t)
	s := NewServer()
	cancelled := make(chan struct{})
	s.Register("hang", func(ctx context.Context, _ Peer, _ json.RawMessage) (any, error) {
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	start(t, s, path)
	c, _ := Dial(path)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, "hang", nil, nil); err != context.DeadlineExceeded {
		t.Fatalf("got %v", err)
	}
	c.Close()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler ctx not cancelled on connection close")
	}
}

func TestDialNoDaemon(t *testing.T) {
	_, err := Dial(filepath.Join(t.TempDir(), "none.sock"))
	ae, ok := err.(*apierr.Error)
	if !ok || ae.Code != apierr.DaemonDown || ae.Hint == "" {
		t.Fatalf("got %#v", err)
	}
}

func TestSocketMode(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(path))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("leftover temp entries: %v", ents)
	}
}

func TestStaleSocketRemoved(t *testing.T) {
	path := sockPath(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close() // leaves a stale socket file behind
	if _, err := os.Stat(path); err != nil {
		t.Fatal("expected stale file")
	}
	start(t, echoServer(), path)
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestLiveSocketRefused(t *testing.T) {
	path := sockPath(t)
	start(t, echoServer(), path)
	err := NewServer().Serve(context.Background(), path)
	if err == nil {
		t.Fatal("expected refusal")
	}
	// First daemon must still be healthy.
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestPeerInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer pid details asserted on linux only")
	}
	path := sockPath(t)
	start(t, echoServer(), path)
	c, _ := Dial(path)
	defer c.Close()
	var pid int
	if err := c.Call(context.Background(), "peer", nil, &pid); err != nil || pid != os.Getpid() {
		t.Fatalf("pid %d err %v", pid, err)
	}
	var got Peer
	s := NewServer()
	s.Register("p", func(_ context.Context, p Peer, _ json.RawMessage) (any, error) { got = p; return true, nil })
	path2 := sockPath(t)
	start(t, s, path2)
	c2, _ := Dial(path2)
	defer c2.Close()
	if err := c2.Call(context.Background(), "p", nil, nil); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	if got.UID != os.Getuid() || got.Exe == "" || got.ParentPID != os.Getppid() || got.ParentExe == "" {
		t.Fatalf("peer %+v (self %s)", got, self)
	}
}
