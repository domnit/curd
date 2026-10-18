//go:build darwin

package consent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

type native struct{ mu sync.Mutex }

// NewNative returns the macOS osascript dialog prompter. Dialogs are
// serialized: one is shown at a time.
func NewNative() Prompter { return &native{} }

func (n *native) Ask(ctx context.Context, p Prompt) (Answer, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Deny, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", BuildScript(p))
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return Deny, ctx.Err()
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "-128") {
			return Deny, nil // user pressed the cancel button (Deny)
		}
		return Deny, fmt.Errorf("consent dialog failed: %w", err)
	}
	return ParseOutput(string(out)), nil
}
