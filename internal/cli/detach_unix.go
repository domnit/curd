//go:build unix

package cli

import (
	"os/exec"
	"syscall"
)

// detachProcess starts cmd in its own session so it outlives the CLI.
func detachProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
