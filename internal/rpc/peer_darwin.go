//go:build darwin

package rpc

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// peerCred returns the uid (LOCAL_PEERCRED) and pid (LOCAL_PEERPID) of the
// process on the other end of conn.
func peerCred(conn *net.UnixConn) (uid, pid int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		var x *unix.Xucred
		x, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if serr != nil {
			return
		}
		uid = int(x.Uid)
		// The pid is best effort; the uid check above is the boundary.
		if p, perr := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); perr == nil {
			pid = p
		}
	}); err != nil {
		return 0, 0, err
	}
	return uid, pid, serr
}

// psInfo runs `ps -o ppid=,comm= -p pid` and returns the parent pid and the
// executable path (comm is the full path on macOS).
func psInfo(pid int) (ppid int, comm string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, ""
	}
	line := strings.TrimSpace(string(out))
	sp := strings.IndexAny(line, " \t")
	if sp < 0 {
		return 0, ""
	}
	ppid, _ = strconv.Atoi(line[:sp])
	return ppid, strings.TrimSpace(line[sp:])
}

// procInfo returns the executable path of pid plus its parent pid and
// executable, all best effort.
func procInfo(pid int) (exe string, ppid int, parentExe string) {
	ppid, exe = psInfo(pid)
	if ppid > 0 {
		_, parentExe = psInfo(ppid)
	}
	return exe, ppid, parentExe
}
