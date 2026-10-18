//go:build !linux && !darwin

package rpc

import (
	"errors"
	"net"
)

func peerCred(conn *net.UnixConn) (uid, pid int, err error) {
	return 0, 0, errors.New("peer credentials unsupported on this platform")
}

func procInfo(pid int) (exe string, ppid int, parentExe string) { return "", 0, "" }
