//go:build linux

package rpc

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// peerCred returns the uid and pid of the process on the other end of conn
// using SO_PEERCRED.
func peerCred(conn *net.UnixConn) (uid, pid int, err error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if serr != nil {
		return 0, 0, serr
	}
	return int(cred.Uid), int(cred.Pid), nil
}

// procInfo returns the executable path of pid plus its parent pid and
// executable, all best effort.
func procInfo(pid int) (exe string, ppid int, parentExe string) {
	exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return exe, 0, ""
	}
	// Format: pid (comm) state ppid ...; comm may contain spaces/parens.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return exe, 0, ""
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return exe, 0, ""
	}
	ppid, _ = strconv.Atoi(f[1])
	if ppid > 0 {
		parentExe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
	}
	return exe, ppid, parentExe
}
