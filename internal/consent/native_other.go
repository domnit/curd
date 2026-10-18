//go:build !darwin

package consent

import (
	"context"
	"errors"
)

type native struct{}

// NewNative returns a prompter that always denies: there is no native dialog
// on this platform. Use test mode with scripted consent instead.
func NewNative() Prompter { return native{} }

func (native) Ask(context.Context, Prompt) (Answer, error) {
	return Deny, errors.New("no native consent dialog on this platform; run in test mode with --consent=allow-all, deny-all or script:<file>")
}
