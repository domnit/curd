//go:build unix

package testenv

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// detach makes cmd start in its own session so it outlives this process and
// does not receive the terminal's signals.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// alive reports whether pid is a running (non-zombie) process.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	// A terminated child whose parent has not reaped it still answers
	// signal 0; Linux shows it as state Z.
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i >= 0 && len(s) > i+2 && s[i+2] == 'Z' {
			return false
		}
	}
	return true
}

func signal(pid int, sig syscall.Signal) { _ = syscall.Kill(pid, sig) }

const (
	sigTerm = syscall.SIGTERM
	sigKill = syscall.SIGKILL
)
