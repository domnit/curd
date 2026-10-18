package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"github.com/domnit/curd/internal/apierr"
	"github.com/domnit/curd/internal/consent"
	"github.com/domnit/curd/internal/rpc"
)

// client describes who is behind a call, for consent dialogs and grants.
// Every CLI call is a fresh `curd` process, so the interesting identity is
// its parent: the agent's shell or process.
type client struct {
	Name string
	PID  int
	Exe  string
}

func clientOf(p rpc.Peer) client {
	c := client{Name: filepath.Base(p.Exe), PID: p.PID, Exe: p.Exe}
	if p.ParentPID > 0 {
		c.PID = p.ParentPID
		if p.ParentExe != "" {
			c.Name = filepath.Base(p.ParentExe)
			c.Exe = p.ParentExe
		}
	}
	if c.Name == "" || c.Name == "." || c.Name == "/" {
		c.Name = "unknown process"
	}
	return c
}

func joinPolicies(ps []string) string { return strings.Join(ps, ",") }

func apierrMessage(err error) string { return apierr.As(err).Message }

// promptGroup coalesces concurrent identical consent prompts so that N
// parallel calls show one dialog.
type promptGroup struct {
	mu sync.Mutex
	m  map[string]*promptCall
}

type promptCall struct {
	done chan struct{}
	ans  consent.Answer
	err  error
}

// do runs fn once per key at a time. Callers that arrive while it runs wait
// and receive its result with shared == true.
func (g *promptGroup) do(ctx context.Context, key string, fn func() (consent.Answer, error)) (ans consent.Answer, shared bool, err error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*promptCall{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.ans, true, c.err
		case <-ctx.Done():
			return consent.Deny, true, ctx.Err()
		}
	}
	c := &promptCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.ans, c.err = fn()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	close(c.done)
	return c.ans, false, c.err
}
