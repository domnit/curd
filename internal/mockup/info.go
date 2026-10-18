package mockup

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Info is written by the test harness so other processes can find the mock.
type Info struct {
	TLSPort    int    `json:"tls_port"`
	HTTPPort   int    `json:"http_port"`
	ControlURL string `json:"control_url"`
	CertFile   string `json:"cert_file"`
	PID        int    `json:"pid"`
}

// WriteInfo writes info as JSON to path (atomically via rename).
func WriteInfo(path string, in Info) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadInfo reads a file written by WriteInfo.
func ReadInfo(path string) (Info, error) {
	var in Info
	b, err := os.ReadFile(path)
	if err != nil {
		return in, err
	}
	err = json.Unmarshal(b, &in)
	return in, err
}
