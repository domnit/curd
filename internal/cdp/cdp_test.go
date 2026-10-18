package cdp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakeBrowser is an in-memory browser end of the pipe.
type fakeBrowser struct {
	in  *bufio.Reader // commands from the client
	out io.Writer     // responses to the client
	mu  sync.Mutex
}

func (f *fakeBrowser) read(t *testing.T) message {
	t.Helper()
	b, err := f.in.ReadBytes(0)
	if err != nil {
		t.Errorf("fake read: %v", err)
		return message{}
	}
	var m message
	if err := json.Unmarshal(b[:len(b)-1], &m); err != nil {
		t.Errorf("fake unmarshal: %v", err)
	}
	return m
}

func (f *fakeBrowser) send(v any) {
	b, _ := json.Marshal(v)
	b = append(b, 0)
	f.mu.Lock()
	f.out.Write(b)
	f.mu.Unlock()
}

func newPair(t *testing.T) (*Conn, *fakeBrowser, func()) {
	t.Helper()
	cr, bw := io.Pipe() // browser -> client
	br, cw := io.Pipe() // client -> browser
	c := NewConn(cr, cw)
	fb := &fakeBrowser{in: bufio.NewReader(br), out: bw}
	return c, fb, func() { c.Close(); bw.Close(); br.Close() }
}

func TestCallResultAndSession(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	go func() {
		m := fb.read(t)
		if m.Method != "Foo.bar" || m.SessionID != "S1" {
			t.Errorf("got %+v", m)
		}
		fb.send(map[string]any{"id": m.ID, "sessionId": "S1", "result": map[string]any{"x": 7}})
	}()
	var res struct{ X int }
	if err := c.Call(context.Background(), "S1", "Foo.bar", map[string]any{"a": 1}, &res); err != nil {
		t.Fatal(err)
	}
	if res.X != 7 {
		t.Fatalf("res %+v", res)
	}
}

func TestCallError(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	go func() {
		m := fb.read(t)
		fb.send(map[string]any{"id": m.ID, "error": map[string]any{"code": -32601, "message": "nope"}})
	}()
	err := c.Call(context.Background(), "", "X.y", nil, nil)
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != -32601 || ce.Message != "nope" {
		t.Fatalf("err = %v", err)
	}
}

func TestPendingFailsOnDeath(t *testing.T) {
	cr, bw := io.Pipe()
	br, cw := io.Pipe()
	c := NewConn(cr, cw)
	go io.Copy(io.Discard, br)
	errc := make(chan error, 1)
	go func() { errc <- c.Call(context.Background(), "", "A.b", nil, nil) }()
	time.Sleep(50 * time.Millisecond)
	bw.Close() // browser dies
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending call not failed")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed")
	}
	if err := c.Call(context.Background(), "", "A.b", nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-death call err = %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	go fb.read(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, "", "A.b", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// A handler that calls Call (as a Fetch.requestPaused handler would) must not
// deadlock the read loop.
func TestEventHandlerCanCall(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	got := make(chan error, 1)
	c.Subscribe(func(ev Event) {
		if ev.Method != "Fetch.requestPaused" || ev.SessionID != "S" {
			return
		}
		got <- c.Call(context.Background(), ev.SessionID, "Fetch.continueRequest", map[string]string{"requestId": "r1"}, nil)
	})
	go func() {
		fb.send(map[string]any{"method": "Fetch.requestPaused", "sessionId": "S", "params": map[string]any{"requestId": "r1"}})
		m := fb.read(t)
		if m.Method != "Fetch.continueRequest" {
			t.Errorf("got %s", m.Method)
		}
		fb.send(map[string]any{"id": m.ID, "sessionId": "S", "result": map[string]any{}})
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock")
	}
}

func TestEventOrderAndUnsubscribe(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	var mu sync.Mutex
	var seen []int
	ch := make(chan struct{}, 100)
	unsub := c.Subscribe(func(ev Event) {
		var p struct{ N int }
		json.Unmarshal(ev.Params, &p)
		mu.Lock()
		seen = append(seen, p.N)
		mu.Unlock()
		ch <- struct{}{}
	})
	for i := 0; i < 50; i++ {
		fb.send(map[string]any{"method": "E.e", "params": map[string]any{"N": i}})
	}
	for i := 0; i < 50; i++ {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout")
		}
	}
	mu.Lock()
	for i, n := range seen {
		if n != i {
			t.Fatalf("out of order: %v", seen)
		}
	}
	mu.Unlock()
	unsub()
	fb.send(map[string]any{"method": "E.e", "params": map[string]any{"N": 99}})
	select {
	case <-ch:
		t.Fatal("event after unsubscribe")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSlowSubscriberDoesNotBlockCalls(t *testing.T) {
	c, fb, done := newPair(t)
	defer done()
	block := make(chan struct{})
	c.Subscribe(func(Event) { <-block })
	defer close(block)
	go func() {
		for i := 0; i < 1000; i++ {
			fb.send(map[string]any{"method": "E.e"})
		}
		m := fb.read(t)
		fb.send(map[string]any{"id": m.ID, "result": map[string]any{}})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Call(ctx, "", "A.b", nil, nil); err != nil {
		t.Fatal(err)
	}
}
