package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/domnit/curd/internal/apierr"
)

type clientResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// Client is a JSON-RPC client; it is safe for concurrent use and supports
// pipelined calls.
type Client struct {
	conn net.Conn
	wmu  sync.Mutex

	mu      sync.Mutex
	nextID  int64
	pending map[string]chan clientResponse
	err     error // set once the read loop ends
	done    chan struct{}
}

// Dial connects to the daemon socket. When nobody is listening the error is
// an *apierr.Error with code daemon_unreachable.
func Dial(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, apierr.New(apierr.DaemonDown, "cannot reach the curd daemon at "+socketPath,
			"start it with `curd daemon` (or check --socket / CURD_SOCKET)")
	}
	c := &Client{conn: conn, pending: map[string]chan clientResponse{}, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *Client) readLoop() {
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineSize)
	for sc.Scan() {
		var r clientResponse
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		c.mu.Lock()
		ch := c.pending[string(trimSpace(r.ID))]
		delete(c.pending, string(trimSpace(r.ID)))
		c.mu.Unlock()
		if ch != nil {
			ch <- r
		}
	}
	c.mu.Lock()
	c.err = apierr.New(apierr.DaemonDown, "connection to the curd daemon closed", "restart it with `curd daemon`")
	close(c.done)
	c.mu.Unlock()
}

// Call invokes method with params and decodes the result into result (which
// may be nil). Errors from the daemon come back as *apierr.Error. There is no
// built-in timeout; cancel ctx to give up.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return apierr.New(apierr.InvalidRequest, "encode params: "+err.Error(), "")
		}
		rawParams = b
	}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.nextID++
	id := strconv.FormatInt(c.nextID, 10)
	ch := make(chan clientResponse, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	b, err := json.Marshal(request{JSONRPC: "2.0", ID: json.RawMessage(id), Method: method, Params: rawParams})
	if err != nil {
		c.forget(id)
		return apierr.New(apierr.InvalidRequest, "encode request: "+err.Error(), "")
	}
	c.wmu.Lock()
	_, err = c.conn.Write(append(b, '\n'))
	c.wmu.Unlock()
	if err != nil {
		c.forget(id)
		return apierr.New(apierr.DaemonDown, "write to the curd daemon failed", "restart it with `curd daemon`")
	}

	select {
	case r := <-ch:
		return finish(r, result)
	case <-c.done:
		select { // a response may have raced with the close
		case r := <-ch:
			return finish(r, result)
		default:
		}
		return c.err
	case <-ctx.Done():
		c.forget(id)
		return ctx.Err()
	}
}

func finish(r clientResponse, result any) error {
	if r.Error != nil {
		return fromRPCError(r.Error)
	}
	if result == nil || len(r.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(r.Result, result); err != nil {
		return apierr.New(apierr.Internal, "decode result: "+err.Error(), "")
	}
	return nil
}

func (c *Client) forget(id string) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Close closes the connection; pending calls fail with daemon_unreachable.
func (c *Client) Close() error {
	err := c.conn.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
