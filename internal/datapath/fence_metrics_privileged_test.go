//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// Runs the actual packaged CLI. Bogus ELF bytes ensure socket/config failures
// precede ELF parsing, any TCX side effect or any pin transaction.
func TestPrivilegedFenceMetricsSocketFailureDoesNotAttach(t *testing.T) {
	binaryPath := os.Getenv("CMTC_BPF_FENCE_BIN")
	if binaryPath == "" {
		t.Fatal("CMTC_BPF_FENCE_BIN required")
	}
	fx, _ := installFenceFollower(t, directionalFixture(t, "ingress"))
	cfg := fixtureFenceConfig(t, fx, privateFenceRoot(t))
	before := fenceChain(t, fx.cfg)
	dev, err := netlink.LinkByIndex(cfg.IfIndex)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("198.18.253.2/32")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(dev, addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(dev, addr) })
	listener, err := net.Listen("tcp", "198.18.253.2:18084")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dir := t.TempDir()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath, elfPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "bad.o")
	if err := os.WriteFile(configPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elfPath, []byte("invalid ELF must not be loaded"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, address, nodeIP, want string }{
		{"occupied", "198.18.253.2:18084", "198.18.253.2", "address already in use"},
		{"missingNodeIP", "198.18.253.2:18084", "", "metrics requires"},
		{"wildcard", "0.0.0.0:18084", "198.18.253.2", "metrics must bind"},
		{"wrongPort", "198.18.253.2:18085", "198.18.253.2", "metrics must bind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaryPath, "--config="+configPath, "--elf="+elfPath, "--metrics-listen="+tc.address)
			for _, entry := range os.Environ() {
				keep := true
				for _, key := range []string{"NODE_NAME=", "CLUSTER_NAME=", "NODE_IP=", "CMTC_FENCE_POD_UID="} {
					if strings.HasPrefix(entry, key) {
						keep = false
					}
				}
				if keep {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "NODE_NAME="+cfg.Node, "CLUSTER_NAME="+cfg.Cluster, "NODE_IP="+tc.nodeIP, "CMTC_FENCE_POD_UID=isolated-cli-test")
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !bytes.Contains(out, []byte(tc.want)) {
				t.Fatalf("metrics boundary not first failure: %v %s", err, out)
			}
			if got := fenceChain(t, fx.cfg); !reflect.DeepEqual(got, before) {
				t.Fatal("metrics failure changed native chain")
			}
			if _, err := os.Stat(filepath.Join(cfg.PinRoot, cfg.key())); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("metrics failure created pins: %v", err)
			}
			health, err := net.Listen("tcp", "127.0.0.1:18083")
			if err != nil {
				t.Fatalf("health listener leaked: %v", err)
			}
			health.Close()
		})
	}
}
