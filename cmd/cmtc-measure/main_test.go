//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/measurement"
)

// writeStatus writes a /proc/self/status with the given effective, permitted and bounding sets (inheritable and
// ambient empty, as the container runtime leaves them).
func writeStatus(t *testing.T, caps uint64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status")
	content := fmt.Sprintf("Name:\tcmtc-measure\nCapInh:\t%016x\nCapPrm:\t%016x\nCapEff:\t%016x\nCapBnd:\t%016x\nCapAmb:\t%016x\n",
		0, caps, caps, caps, 0)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckPrivileges(t *testing.T) {
	noToken := filepath.Join(t.TempDir(), "token")
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A path below a regular file: stat fails with ENOTDIR, so the loader cannot tell whether a token is mounted.
	unknown := filepath.Join(token, "token")
	exact := measurement.LoaderCapabilities

	if err := checkPrivileges(writeStatus(t, exact), noToken); err != nil {
		t.Fatalf("the DaemonSet's loader is refused: %v", err)
	}
	for _, c := range []struct {
		name, status, token, want string
	}{
		{"CAP_SYS_ADMIN as well", writeStatus(t, exact|1<<measurement.CapSysAdmin), noToken, "CAP_SYS_ADMIN"},
		{"CAP_NET_ADMIN missing", writeStatus(t, 1<<measurement.CapBPF), noToken, "lacks CAP_NET_ADMIN"},
		{"an API token", writeStatus(t, exact), token, "an API token is mounted"},
		{"a token path it cannot read", writeStatus(t, exact), unknown, "cannot tell whether an API token is mounted"},
		{"no status file", filepath.Join(t.TempDir(), "missing"), noToken, "no such file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := checkPrivileges(c.status, c.token); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("checkPrivileges = %v, want an error containing %q", err, c.want)
			}
		})
	}
}
