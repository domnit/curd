//go:build !linux && !darwin

package rpc

import "os"

// lockFile is a no-op where flock is unavailable; the live-socket check in
// Serve is the only guard there.
func lockFile(path string) (*os.File, error) { return nil, nil }
