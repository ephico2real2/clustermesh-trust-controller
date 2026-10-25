//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestPrivilegedObserverMetricsSocketFailureDoesNotAttach(t *testing.T) {
	_ = requirePrivileged(t)
	binaryPath := requireObserverBinary(t)
	fx := newFixture(t)
	_, baseline, err := query(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("198.18.253.3/32")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(fx.dev, addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(fx.dev, addr) })
	listener, err := net.Listen("tcp", "198.18.253.3:18085")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dir := t.TempDir()
	body, err := json.Marshal(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath, elfPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "bad.o")
	if err := os.WriteFile(configPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elfPath, []byte("invalid ELF must not load"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, address, nodeIP, want string }{
		{"occupied", "198.18.253.3:18085", "198.18.253.3", "address already in use"},
		{"missingNodeIP", "198.18.253.3:18085", "", "metrics requires"},
		{"wildcard", "0.0.0.0:18085", "198.18.253.3", "metrics must bind"},
		{"wrongPort", "198.18.253.3:18084", "198.18.253.3", "metrics must bind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaryPath, "--config="+configPath, "--elf="+elfPath, "--metrics-listen="+tc.address)
			for _, entry := range os.Environ() {
				keep := true
				for _, key := range []string{"NODE_NAME=", "CLUSTER_NAME=", "NODE_IP="} {
					if strings.HasPrefix(entry, key) {
						keep = false
					}
				}
				if keep {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "NODE_NAME="+fx.cfg.Node, "CLUSTER_NAME="+fx.cfg.Cluster, "NODE_IP="+tc.nodeIP)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !bytes.Contains(out, []byte(tc.want)) {
				t.Fatalf("socket boundary not first error: %v %s", err, out)
			}
			requireExactChain(t, fx.cfg, baseline)
			health, err := net.Listen("tcp", "127.0.0.1:18082")
			if err != nil {
				t.Fatalf("loopback listener leaked: %v", err)
			}
			health.Close()
		})
	}
}
