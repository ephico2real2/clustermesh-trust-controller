//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests modify only newly created veths in an explicitly authorized,
// private disposable container network namespace. They are NOT Cilium lab proof.
func requirePrivileged(t *testing.T) []byte {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CMTC_BPF_TEST_PRIVATE_NETNS") != "1" {
		t.Fatal("requires root in a disposable private container network namespace; set CMTC_BPF_TEST_PRIVATE_NETNS=1 only there")
	}
	path := os.Getenv("CMTC_BPF_ELF")
	if path == "" {
		t.Fatal("CMTC_BPF_ELF must identify the actual freshly compiled ELF")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	cfg       Config
	dev, peer netlink.Link
	policy    link.Link
	prog      *ebpf.Program
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	suffix := time.Now().UnixNano() % 1000000000
	host := fmt.Sprintf("coh%d", suffix)
	peer := fmt.Sprintf("cop%d", suffix)
	v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host}, PeerName: peer}
	if err := netlink.LinkAdd(v); err != nil {
		t.Fatalf("create owned veth: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(v) })
	dev, err := netlink.LinkByName(host)
	if err != nil {
		t.Fatal(err)
	}
	p, err := netlink.LinkByName(peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(p); err != nil {
		t.Fatal(err)
	}
	// This synthetic Cilium-named anchor is a loader fixture only. It does not
	// model Cilium policy/identity and must never qualify deployed lab behavior.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cil_fixture", Type: ebpf.SchedCLS,
		AttachType: ebpf.AttachTCXIngress, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatalf("load real TCX fixture: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	policy, err := link.AttachTCX(link.TCXOptions{Interface: dev.Attrs().Index, Program: prog,
		Attach: ebpf.AttachTCXIngress, Anchor: link.Tail()})
	if err != nil {
		t.Fatalf("actual TCX attach required, no skip/fallback: %v", err)
	}
	t.Cleanup(func() { _ = policy.Close() })
	info, err := policy.Info()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ino, err := inode(ns)
	_ = ns.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Cluster: "fixture", Node: "fixture", PodUID: "fixture-only", NetNSInode: ino,
		IfIndex: dev.Attrs().Index, IfName: host, MAC: dev.Attrs().HardwareAddr.String(),
		PeerIfIndex: dev.Attrs().ParentIndex, Direction: "ingress",
		CiliumLinkID: uint32(info.ID), CiliumProgramID: uint32(info.Program)}
	if cfg.PeerIfIndex <= 0 {
		t.Fatal("veth peer index missing; do not replace with wildcard")
	}
	return fixture{cfg: cfg, dev: dev, peer: p, policy: policy, prog: prog}
}

func TestPrivilegedVerifierReturnsNextUnchanged(t *testing.T) {
	elf := requirePrivileged(t)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("actual kernel verifier rejected ELF: %v", err)
	}
	defer coll.Close()
	packet := make([]byte, 64)
	for i := range packet {
		packet[i] = byte(i)
	}
	packet[12], packet[13] = 0x88, 0xb5
	action, out, err := coll.Programs["cmtc_observe"].Test(packet)
	if err != nil {
		t.Fatalf("actual BPF_PROG_TEST_RUN failed: %v", err)
	}
	if action != ^uint32(0) {
		t.Fatalf("return action=%d, want TCX_NEXT", action)
	}
	if !bytes.Equal(packet, out) {
		t.Fatal("observer modified packet")
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	counts := make([]Count, cpus)
	if err := coll.Maps["observed"].Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	var sum Count
	for _, c := range counts {
		sum.Packets += c.Packets
		sum.Bytes += c.Bytes
	}
	if sum.Packets != 1 || sum.Bytes != uint64(len(packet)) {
		t.Fatalf("actual map=%+v", sum)
	}
}

func TestPrivilegedAttachPacketsDriftAndRecovery(t *testing.T) {
	elf := requirePrivileged(t)
	f := newFixture(t)
	_, baseline, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	wrongNS := f.cfg
	wrongNS.NetNSInode++
	if o, err := Open(wrongNS, elf); err == nil {
		_ = o.Close()
		t.Fatal("wrong netns accepted")
	}
	wrongID := f.cfg
	wrongID.CiliumProgramID++
	if o, err := Open(wrongID, elf); err == nil {
		_ = o.Close()
		t.Fatal("wrong program accepted")
	}
	o, err := Open(f.cfg, elf)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	first, err := o.Sample()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	packet := make([]byte, 64)
	copy(packet[:6], f.dev.Attrs().HardwareAddr)
	copy(packet[6:12], f.peer.Attrs().HardwareAddr)
	packet[12], packet[13] = 0x88, 0xb5
	const sent = 20
	for i := 0; i < sent; i++ {
		if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: f.peer.Attrs().Index, Halen: 6}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := o.Sample()
		if err != nil {
			t.Fatal(err)
		}
		// Other fixture-local protocol traffic can exist. Assert positive
		// controlled packet contribution, not application request equality.
		if got.Packets-first.Packets >= sent && got.Bytes-first.Bytes >= sent*uint64(len(packet)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("real packet delta insufficient: before=%+v after=%+v", first, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	extraProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "fixture_extra", Type: ebpf.SchedCLS,
		AttachType: ebpf.AttachTCXIngress, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer extraProg.Close()
	extra, err := link.AttachTCX(link.TCXOptions{Interface: f.cfg.IfIndex, Program: extraProg,
		Attach: ebpf.AttachTCXIngress, Anchor: link.Tail()})
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_, withExtra, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Sample(); err == nil {
		t.Fatal("changed chain still reported ready")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	_, after, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, withExtra[1:]) {
		t.Fatalf("close altered another owner's links: %v vs %v", after, withExtra[1:])
	}
	if err := extra.Close(); err != nil {
		t.Fatal(err)
	}
	_, after, err = query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, baseline) {
		t.Fatalf("baseline not restored: %v", after)
	}
	recovered, err := Open(f.cfg, elf)
	if err != nil {
		t.Fatalf("same exact anchor recovery: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(f.dev); err != nil {
		t.Fatal(err)
	}
	if again, err := Open(f.cfg, elf); err == nil {
		_ = again.Close()
		t.Fatal("deleted interface accepted")
	}
}

func TestPrivilegedRejectLegacyTCWithoutMutation(t *testing.T) {
	elf := requirePrivileged(t)
	f := newFixture(t)
	_, before, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	q := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: f.cfg.IfIndex,
		Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}
	if err := netlink.QdiscAdd(q); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.QdiscDel(q) })
	legacyProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "legacy_fixture", Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer legacyProg.Close()
	filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: f.cfg.IfIndex,
		Parent: netlink.HANDLE_MIN_INGRESS, Handle: netlink.MakeHandle(0, 1), Priority: 1, Protocol: unix.ETH_P_ALL},
		Fd: legacyProg.FD(), Name: "owned_legacy_fixture", DirectAction: true}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.FilterDel(filter) })
	if o, err := Open(f.cfg, elf); err == nil {
		_ = o.Close()
		t.Fatal("legacy TC accepted")
	}
	_, after, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("reject mutated TCX chain")
	}
	// Prove rejection also preserves the owned legacy test filter.
	filters, err := netlink.FilterList(f.dev, netlink.HANDLE_MIN_INGRESS)
	if err != nil || len(filters) != 1 {
		t.Fatalf("legacy fixture unexpectedly changed: %v %v", filters, err)
	}
}

func TestPrivilegedOwnerDetachIsNotPinnedByObserver(t *testing.T) {
	elf := requirePrivileged(t)
	f := newFixture(t)
	o, err := Open(f.cfg, elf)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err := f.policy.Close(); err != nil {
		t.Fatal(err)
	}
	_, now, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(now) != 1 || now[0].Link != o.expected[0].Link {
		t.Fatalf("observer retained a link whose owner closed it: %v", now)
	}
	if _, err := o.Sample(); err == nil {
		t.Fatal("owner-detached chain reported ready")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	_, now, err = query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(now) != 0 {
		t.Fatalf("private link cleanup incomplete: %v", now)
	}
}
