package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/domnit/curd/internal/apierr"
)

// Handler serves one RPC method. The context is cancelled when the client
// connection closes or the server shuts down. Returning an *apierr.Error
// yields a structured error; other errors become apierr.Internal.
type Handler func(ctx context.Context, peer Peer, params json.RawMessage) (any, error)

// Server is a JSON-RPC server on a unix socket.
type Server struct {
	mu       sync.Mutex
	handlers map[string]Handler
	ln       net.Listener
	conns    map[net.Conn]struct{}
	closed   bool
}

// NewServer returns a Server with no methods registered.
func NewServer() *Server {
	return &Server{handlers: map[string]Handler{}, conns: map[net.Conn]struct{}{}}
}

// Register installs h for method, replacing any earlier handler.
func (s *Server) Register(method string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = h
}

func (s *Server) handler(method string) Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handlers[method]
}

// Serve listens on socketPath (mode 0600) and serves until ctx is done or
// Close is called. A live socket at the path is an error; a stale one is
// removed.
func (s *Server) Serve(ctx context.Context, socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if fi, err := os.Lstat(socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", socketPath)
		}
		if c, err := net.Dial("unix", socketPath); err == nil {
			c.Close()
			return fmt.Errorf("another daemon is running (socket %s is live)", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	}

	// Bind inside a private 0700 directory, chmod, then rename into place so
	// the socket is never reachable with looser permissions.
	tmp, err := os.MkdirTemp(dir, ".curd-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	tmpSock := filepath.Join(tmp, "s")
	ln, err := net.Listen("unix", tmpSock)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(tmpSock, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}
	if err := os.Rename(tmpSock, socketPath); err != nil {
		ln.Close()
		return fmt.Errorf("install socket: %w", err)
	}
	os.RemoveAll(tmp)
	defer os.Remove(socketPath)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return nil
	}
	s.ln = ln
	s.mu.Unlock()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-sctx.Done()
		s.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ul.AcceptUnix()
		if err != nil {
			if sctx.Err() != nil || s.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		peer, err := peerOf(conn)
		if err != nil || peer.UID != os.Getuid() {
			conn.Close()
			continue
		}
		if !s.track(conn) {
			conn.Close()
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(conn)
			s.serveConn(sctx, conn, peer)
		}()
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

// Close stops accepting and closes all connections. It is idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	return err
}

func (s *Server) serveConn(parent context.Context, conn net.Conn, peer Peer) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wmu sync.Mutex
	write := func(r response) {
		r.JSONRPC = "2.0"
		b, err := json.Marshal(r)
		if err != nil {
			b, _ = json.Marshal(response{JSONRPC: "2.0", ID: r.ID,
				Error: &rpcError{Code: codeInternal, Message: "encode response: " + err.Error()}})
		}
		b = append(b, '\n')
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = conn.Write(b)
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineSize)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(trimSpace(line)) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeParse, Message: "parse error"}})
			continue
		}
		isNotification := len(req.ID) == 0
		id := req.ID
		if isNotification {
			id = json.RawMessage("null")
		} else if !validID(id) {
			write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeInvalidRequest, Message: "id must be a number or string"}})
			continue
		}
		if req.Method == "" {
			if !isNotification {
				write(response{ID: id, Error: &rpcError{Code: codeInvalidRequest, Message: "missing method"}})
			}
			continue
		}
		h := s.handler(req.Method)
		if h == nil {
			if !isNotification {
				write(response{ID: id, Error: &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}})
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := safeCall(ctx, h, peer, req.Params)
			if isNotification {
				return
			}
			if err != nil {
				write(response{ID: id, Error: toRPCError(err)})
				return
			}
			if res == nil {
				res = struct{}{}
			}
			write(response{ID: id, Result: res})
		}()
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		write(response{ID: json.RawMessage("null"), Error: &rpcError{Code: codeInvalidRequest, Message: "request too large or unreadable"}})
	}
}

func safeCall(ctx context.Context, h Handler, peer Peer, params json.RawMessage) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, apierr.New(apierr.Internal, fmt.Sprintf("handler panic: %v", r), "")
		}
	}()
	return h(ctx, peer, params)
}

func validID(id json.RawMessage) bool {
	b := trimSpace(id)
	if len(b) == 0 {
		return false
	}
	return b[0] == '"' || b[0] == '-' || (b[0] >= '0' && b[0] <= '9')
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// peerOf gathers credentials for conn via platform-specific calls.
func peerOf(conn *net.UnixConn) (Peer, error) {
	uid, pid, err := peerCred(conn)
	if err != nil {
		return Peer{}, err
	}
	p := Peer{UID: uid, PID: pid}
	if pid > 0 {
		p.Exe, p.ParentPID, p.ParentExe = procInfo(pid)
	}
	return p, nil
}
