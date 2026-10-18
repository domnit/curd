// Package cdp is a minimal Chrome DevTools Protocol client for
// --remote-debugging-pipe. Messages are JSON objects terminated by a NUL
// byte. Flat sessions are used: a message belongs to a target session when it
// carries a "sessionId" field.
package cdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Error is a protocol-level error returned by the browser.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error implements error.
func (e *Error) Error() string { return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message) }

// ErrClosed is returned by calls on a connection that has been closed or
// whose transport has died.
var ErrClosed = errors.New("cdp: connection closed")

// Event is a CDP event delivered to subscribers.
type Event struct {
	SessionID string
	Method    string
	Params    json.RawMessage
}

type message struct {
	ID        int64           `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *Error          `json:"error,omitempty"`
}

type reply struct {
	result json.RawMessage
	err    error
}

// Conn is a CDP connection over a pair of byte streams.
type Conn struct {
	w  io.Writer
	rc io.Closer // closed on Close, may be nil
	wc io.Closer

	wmu sync.Mutex // serializes writes

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan reply
	subs    map[int]*subscriber
	nextSub int
	closed  bool
	err     error

	done chan struct{}
}

// NewConn starts a connection reading from r (the browser's output, fd 4) and
// writing to w (the browser's input, fd 3). If r or w implement io.Closer,
// Close closes them.
func NewConn(r io.Reader, w io.Writer) *Conn {
	c := &Conn{
		w:       w,
		pending: make(map[int64]chan reply),
		subs:    make(map[int]*subscriber),
		done:    make(chan struct{}),
	}
	if x, ok := r.(io.Closer); ok {
		c.rc = x
	}
	if x, ok := w.(io.Closer); ok {
		c.wc = x
	}
	go c.readLoop(r)
	return c
}

// Done is closed when the connection has terminated.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the connection terminated, or nil while it is open.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close terminates the connection; pending calls fail with ErrClosed.
func (c *Conn) Close() error {
	c.shutdown(ErrClosed)
	return nil
}

func (c *Conn) shutdown(cause error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = cause
	pend := c.pending
	c.pending = map[int64]chan reply{}
	subs := c.subs
	c.subs = map[int]*subscriber{}
	c.mu.Unlock()

	close(c.done)
	for _, ch := range pend {
		ch <- reply{err: ErrClosed} // buffered
	}
	for _, s := range subs {
		s.stop()
	}
	if c.rc != nil {
		c.rc.Close()
	}
	if c.wc != nil {
		c.wc.Close()
	}
}

func (c *Conn) readLoop(r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		raw, err := br.ReadBytes(0)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				c.shutdown(ErrClosed)
			} else {
				c.shutdown(fmt.Errorf("cdp: read: %w", err))
			}
			return
		}
		raw = bytes.TrimRight(raw, "\x00")
		if len(raw) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(raw, &m); err != nil {
			continue // ignore malformed message
		}
		if m.Method != "" && m.ID == 0 {
			c.dispatch(Event{SessionID: m.SessionID, Method: m.Method, Params: m.Params})
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch == nil {
			continue
		}
		if m.Error != nil {
			ch <- reply{err: m.Error}
		} else {
			ch <- reply{result: m.Result}
		}
	}
}

// Call sends a command and waits for its response. sessionID may be empty for
// browser-level commands. params is JSON-marshaled; result, if non-nil,
// receives the decoded response. Protocol errors are returned as *Error.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params, result any) error {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("cdp: marshal params for %s: %w", method, err)
		}
		rawParams = b
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	b, err := json.Marshal(message{ID: id, SessionID: sessionID, Method: method, Params: rawParams})
	if err == nil {
		b = append(b, 0)
		c.wmu.Lock()
		_, err = c.w.Write(b)
		c.wmu.Unlock()
	}
	if err != nil {
		c.forget(id)
		c.shutdown(ErrClosed)
		return ErrClosed
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if result != nil && len(r.result) > 0 {
			if err := json.Unmarshal(r.result, result); err != nil {
				return fmt.Errorf("cdp: decode %s result: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.forget(id)
		return ctx.Err()
	case <-c.done:
		// A reply may have raced in just before shutdown.
		select {
		case r := <-ch:
			if r.err != nil && !errors.Is(r.err, ErrClosed) {
				return r.err
			}
		default:
		}
		return ErrClosed
	}
}

func (c *Conn) forget(id int64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Subscribe registers fn to receive every event, in order. Each subscriber has
// its own unbounded queue and goroutine, so fn may itself call Call. The
// returned function unsubscribes; events queued but not yet delivered are
// dropped.
func (c *Conn) Subscribe(fn func(Event)) (unsubscribe func()) {
	s := newSubscriber(fn)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.stop()
		return func() {}
	}
	id := c.nextSub
	c.nextSub++
	c.subs[id] = s
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
		s.stop()
	}
}

func (c *Conn) dispatch(ev Event) {
	c.mu.Lock()
	subs := make([]*subscriber, 0, len(c.subs))
	for _, s := range c.subs {
		subs = append(subs, s)
	}
	c.mu.Unlock()
	for _, s := range subs {
		s.push(ev)
	}
}

type subscriber struct {
	fn      func(Event)
	mu      sync.Mutex
	queue   []Event
	wake    chan struct{}
	stopped bool
	quit    chan struct{}
}

func newSubscriber(fn func(Event)) *subscriber {
	s := &subscriber{fn: fn, wake: make(chan struct{}, 1), quit: make(chan struct{})}
	go s.run()
	return s
}

func (s *subscriber) push(ev Event) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.queue = append(s.queue, ev)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *subscriber) stop() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		s.queue = nil
		close(s.quit)
	}
	s.mu.Unlock()
}

func (s *subscriber) run() {
	for {
		select {
		case <-s.quit:
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			if s.stopped || len(s.queue) == 0 {
				s.mu.Unlock()
				break
			}
			ev := s.queue[0]
			s.queue[0] = Event{}
			s.queue = s.queue[1:]
			s.mu.Unlock()
			s.fn(ev)
		}
	}
}
