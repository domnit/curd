//go:build unix

package chrome

import (
	"os/exec"
	"syscall"
)

// newProcessGroup puts the browser in its own process group so helper
// processes can be cleaned up with it.
func newProcessGroup() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// killGroup SIGKILLs the browser's whole process group (no-op if already gone).
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
