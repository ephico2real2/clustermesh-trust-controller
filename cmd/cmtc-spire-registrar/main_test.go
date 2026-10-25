//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/spireregistrar"
	"golang.org/x/sys/unix"
	ktypes "k8s.io/apimachinery/pkg/types"
)

func configBytes(t *testing.T) []byte {
	t.Helper()
	id := ktypes.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	d := spireregistrar.DaemonApproval{Namespace: "cilium-spire", NamespaceUID: id, Name: "spire-agent", UID: id, ServiceAccount: "spire-agent", ServiceAccountUID: id, Container: "spire-agent", Image: "example.test/spire@sha256:" + strings.Repeat("a", 64)}
	delegate := d
	delegate.Namespace = "kube-system"
	delegate.Name = "ztunnel-cilium"
	delegate.ServiceAccount = "ztunnel-cilium"
	delegate.Container = "ztunnel"
	o := spireregistrar.Options{ClusterName: "cmtc-a", ClusterUID: id, TrustDomain: "cmtc-a.mesh.example", InstallationID: string(id), Agent: d, Delegate: delegate}
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func digest(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func TestLoadPinnedRegistrarConfiguration(t *testing.T) {
	data := configBytes(t)
	path := filepath.Join(t.TempDir(), "approval.json")
	if err := os.WriteFile(path, data, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, digest(data)); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"", strings.Repeat("0", 64), "not-hex"} {
		if _, err := load(path, pin); err == nil {
			t.Fatal("invalid independent pin accepted")
		}
	}
}
func TestLoadRefusesOversizedTrailingAndUnknownConfiguration(t *testing.T) {
	valid := configBytes(t)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"oversized", []byte(strings.Repeat(" ", 65537))}, {"trailing", append(append([]byte(nil), valid...), []byte(` {}`)...)}, {"unknown", append([]byte(`{"unknown":true,`), valid[1:]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "approval.json")
			if err := os.WriteFile(path, tc.data, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := load(path, digest(tc.data)); err == nil {
				t.Fatal("invalid registrar config accepted")
			}
		})
	}
}
func TestLoadRefusesNonregularFileWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, fifo} {
		if _, err := load(path, digest(nil)); err == nil {
			t.Fatal("nonregular registrar config accepted")
		}
	}
}
