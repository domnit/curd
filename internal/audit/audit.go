// Package audit writes curd's JSONL audit log (spec section 11). Records
// deliberately have no header, body, cookie or token fields: only a token
// hash, grant ids and redacted paths can be logged.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one audit log line.
type Record struct {
	Time       time.Time `json:"ts"`
	Event      string    `json:"event"` // fetch, browse, consent, grant, revoke, session_open, session_close, capture, distill, policy_approve, daemon_start
	Test       bool      `json:"test,omitempty"`
	Tags       []string  `json:"tags,omitempty"` // e.g. "explore"
	ClientPID  int       `json:"client_pid,omitempty"`
	ClientExe  string    `json:"client_exe,omitempty"`
	GrantID    string    `json:"grant_id,omitempty"`
	TokenHash  string    `json:"token_hash,omitempty"`
	SessionKey string    `json:"session_key,omitempty"`
	Policy     string    `json:"policy,omitempty"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path,omitempty"` // query redacted; see RedactPath
	Verb       string    `json:"verb,omitempty"`
	Decision   string    `json:"decision,omitempty"` // allow | deny
	Code       string    `json:"code,omitempty"`     // error or denial code
	Status     int       `json:"status,omitempty"`
	Bytes      int64     `json:"bytes,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
}

// Options configures a Log.
type Options struct {
	MaxBytes int64 // rotate when the file would exceed this size; default 10 MiB
	Keep     int   // rotated files to keep; default 3
	Test     bool  // tag every record as test-mode
}

// Log is an append-only, size-rotated JSONL file. It is safe for concurrent
// use.
type Log struct {
	mu   sync.Mutex
	path string
	opts Options
	f    *os.File
	size int64
}

// Open opens (creating if needed) the log at path with mode 0600, creating
// the directory with mode 0700.
func Open(path string, opts Options) (*Log, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 10 << 20
	}
	if opts.Keep <= 0 {
		opts.Keep = 3
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	l := &Log{path: path, opts: opts}
	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) openFile() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("audit: stat: %w", err)
	}
	l.f, l.size = f, fi.Size()
	return nil
}

// Write appends r, filling Time when zero and Test from the Log options.
func (l *Log) Write(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	r.Time = r.Time.UTC()
	if l.opts.Test {
		r.Test = true
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return fmt.Errorf("audit: log closed")
	}
	if l.size > 0 && l.size+int64(len(b)) > l.opts.MaxBytes {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	if err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// rotate shifts audit.jsonl -> .1 -> .2 ... dropping beyond Keep.
func (l *Log) rotate() error {
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("audit: close for rotation: %w", err)
	}
	l.f = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", l.path, l.opts.Keep))
	for i := l.opts.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return fmt.Errorf("audit: rotate: %w", err)
	}
	return l.openFile()
}

// Tail returns the last n records (oldest first) from the current log file,
// as generic maps. Malformed lines are skipped.
func (l *Log) Tail(n int) ([]map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("audit: open for tail: %w", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		out = append(out, m)
		if n > 0 && len(out) > n {
			out = out[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	if n <= 0 {
		return []map[string]any{}, nil
	}
	return out, nil
}

// Close closes the log file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// HashToken returns "sha256:" plus the first 16 hex characters of the
// token's SHA-256, suitable for correlating log lines without revealing the
// token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// RedactPath returns u's path, with "?<redacted>" appended when a query is
// present (query strings often carry secrets).
func RedactPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		p += "?<redacted>"
	}
	return p
}
