package mockup

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Main is the entry point for running the mock as a background process:
// --info <path> --cert-dir <dir>. It serves until SIGTERM/SIGINT.
func Main(args []string) int {
	fs := flag.NewFlagSet("mockup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	infoPath := fs.String("info", "", "path to write Info JSON")
	certDir := fs.String("cert-dir", "", "directory to write cert.pem")
	addr := fs.String("addr", "", "listen address (default 127.0.0.1:0)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "mockup:", err)
		return 2
	}
	if *infoPath == "" {
		fmt.Fprintln(os.Stderr, "mockup: --info is required")
		return 2
	}
	srv, err := Start(Options{Addr: *addr, CertDir: *certDir})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mockup:", err)
		return 1
	}
	certFile := ""
	if *certDir != "" {
		certFile = srv.certFile
	}
	err = WriteInfo(*infoPath, Info{
		TLSPort: srv.TLSPort(), HTTPPort: srv.HTTPPort(),
		ControlURL: srv.ControlURL(), CertFile: certFile, PID: os.Getpid(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mockup:", err)
		srv.Close()
		return 1
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	srv.Close()
	return 0
}
