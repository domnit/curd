package mockup

// Synthetic credentials. Every secret contains "SECRET" so tests can grep
// any output for leaks.
const (
	SessionCookie     = "sess-test-SECRET-1"
	RotatedCookie     = "sess-rotated-SECRET-3"
	LoginCookie       = "sess-login-SECRET-4"
	AuthToken         = "lsauth-test-SECRET-2"
	CSRFCookie        = "csrfcookie-test-SECRET-5"
	SessionCookieName = "session"

	HostApp   = "app.example.com"
	HostAPI   = "api.example.com"
	HostOther = "other.example.net"
)
