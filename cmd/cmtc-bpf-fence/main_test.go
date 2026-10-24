//go:build linux

package main

import (
	"encoding/json"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	"strings"
	"testing"
	"time"
)

func validFenceJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(datapath.FenceConfig{Cluster: "a", Node: "n", NamespaceUID: "ns", PodUID: "pod", NetNSInode: 1, IfIndex: 2, IfName: "lxc-test", MAC: "02:00:00:00:00:01", PeerIfIndex: 3, Direction: "ingress", CiliumLinkID: 4, CiliumProgramID: 5, PinRoot: "/sys/fs/bpf/cmtc", LockRoot: "/run/cmtc-locks"})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestStrictBoundedFenceConfig(t *testing.T) {
	good := validFenceJSON(t)
	if _, err := decodeConfig(strings.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"unknown": strings.TrimSuffix(good, "}") + `,"allow":true}`, "trailingObject": good + ` {}`, "trailingGarbage": good + `x`, "null": `null`, "empty": ``, "oversize": strings.Repeat(" ", maxConfigBytes+1) + good, "missingNamespaceUID": strings.Replace(good, `"namespaceUID":"ns"`, `"namespaceUID":""`, 1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfig(strings.NewReader(body)); err == nil {
				t.Fatal("invalid or unsafe configuration accepted")
			}
		})
	}
}
func TestQuarantineReadinessFreshness(t *testing.T) {
	q := newQuarantine(datapath.FenceConfig{Cluster: "a", Node: "n", Direction: "ingress"})
	now := time.Now()
	if _, ok := q.snapshot(now); ok {
		t.Fatal("zero state ready")
	}
	q.set(datapath.FenceCount{DroppedPackets: 1}, true)
	q.RLock()
	sample := q.sampled
	q.RUnlock()
	for _, when := range []time.Time{sample.Add(-time.Nanosecond), sample.Add(sampleMaxAge + time.Nanosecond)} {
		if _, ok := q.snapshot(when); ok {
			t.Fatal("future or stale sample ready")
		}
	}
	if _, ok := q.snapshot(sample.Add(sampleMaxAge)); !ok {
		t.Fatal("fresh verified sample unavailable")
	}
	q.set(datapath.FenceCount{}, false)
	if _, ok := q.snapshot(time.Now()); ok {
		t.Fatal("uncertainty retained readiness")
	}
}
