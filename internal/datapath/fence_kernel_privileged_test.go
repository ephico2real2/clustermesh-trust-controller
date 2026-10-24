//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// This TestMain branch runs the ACTUAL test binary as an installing process.
// It retains its FDs/lock until real SIGKILL; no graceful ReleaseProcess occurs
// before the crash. Do not add another TestMain in this package.
func TestMain(m *testing.M) {
	if os.Getenv("CMTC_FENCE_KERNEL_CHILD") == "install" {
		os.Exit(fenceKernelChild())
	}
	os.Exit(m.Run())
}
func fenceKernelChild() int {
	if os.Geteuid() != 0 || os.Getenv("CMTC_BPF_TEST_PRIVATE_NETNS") != "1" {
		return 2
	}
	var c FenceConfig
	if err := json.Unmarshal([]byte(os.Getenv("CMTC_FENCE_KERNEL_CONFIG")), &c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	elf, err := os.ReadFile(os.Getenv("CMTC_FENCE_ELF"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 4
	}
	f, err := InstallFence(c, elf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 5
	}
	// Keep this reference alive until SIGKILL. The API owns private map/link FDs
	// and cross-process lock; do not release any before reporting ready.
	if _, err := f.Account(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 6
	}
	if err := os.WriteFile(os.Getenv("CMTC_FENCE_KERNEL_READY"), []byte("installed\n"), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 7
	}
	for {
		time.Sleep(time.Hour)
		runtime.KeepAlive(f)
	}
}
func requireFenceELF(t *testing.T) []byte {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CMTC_BPF_TEST_PRIVATE_NETNS") != "1" {
		t.Fatal("requires root in owned disposable private network namespace")
	}
	path := os.Getenv("CMTC_FENCE_ELF")
	if path == "" {
		t.Fatal("CMTC_FENCE_ELF must identify freshly compiled deny-only ELF")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func loadFenceCollection(t *testing.T, elf []byte, at ebpf.AttachType) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 1 || len(spec.Maps) != 1 {
		t.Fatalf("deny-only ELF must not contain extra grant/config objects: programs=%v maps=%v", spec.Programs, spec.Maps)
	}
	p, m := spec.Programs["cmtc_fence"], spec.Maps["accounted"]
	if p == nil || p.Type != ebpf.SchedCLS || m == nil || m.Type != ebpf.PerCPUArray || m.KeySize != 4 || m.ValueSize != 16 || m.MaxEntries != 1 {
		t.Fatal("deny-only ELF schema mismatch")
	}
	p.AttachType = at
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("actual kernel verifier rejected fence: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}
func TestPrivilegedFenceVerifierAlwaysDropUnchanged(t *testing.T) {
	elf := requireFenceELF(t)
	for _, at := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		t.Run(at.String(), func(t *testing.T) {
			c := loadFenceCollection(t, elf, at)
			count := uint64(0)
			totalBytes := uint64(0)
			for _, port := range []uint16{0, 80, 8080, 31337, 65535} {
				packet := udpFrame(net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, net.IPv4(198, 18, 254, 1), net.IPv4(198, 18, 254, 2), 40000, port)
				action, out, err := c.Programs["cmtc_fence"].Test(packet)
				if err != nil {
					t.Fatalf("actual BPF_PROG_TEST_RUN: %v", err)
				}
				if action != 2 || !bytes.Equal(packet, out) {
					t.Fatalf("port%d action%d or packet changed", port, action)
				}
				count++
				totalBytes += uint64(len(packet))
			}
			unknown := make([]byte, 64)
			unknown[12], unknown[13] = 0x88, 0xb5
			action, out, err := c.Programs["cmtc_fence"].Test(unknown)
			if err != nil || action != 2 || !bytes.Equal(unknown, out) {
				t.Fatalf("non-IP action=%d error=%v", action, err)
			}
			count++
			totalBytes += uint64(len(unknown))
			got := kernelDropCounters(t, c.Maps["accounted"])
			if got.Packets != count || got.Bytes != totalBytes {
				t.Fatalf("wrong verifier counters: %+v want %d/%d", got, count, totalBytes)
			}
			// Even a writable/tampered TELEMETRY map cannot grant traffic. There is
			// no verdict, generation or deadline map to poison in this ELF.
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			poison := make([]Count, cpus)
			for i := range poison {
				poison[i] = Count{Packets: ^uint64(0), Bytes: ^uint64(0)}
			}
			if err := c.Maps["accounted"].Update(uint32(0), poison, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			action, _, err = c.Programs["cmtc_fence"].Test(unknown)
			if err != nil || action != 2 {
				t.Fatalf("counter map contents changed verdict: action%d err%v", action, err)
			}
		})
	}
}
func kernelDropCounters(t *testing.T, m *ebpf.Map) Count {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]Count, cpus)
	if err := m.Lookup(uint32(0), &values); err != nil {
		t.Fatal(err)
	}
	var sum Count
	for _, v := range values {
		sum.Packets += v.Packets
		sum.Bytes += v.Bytes
	}
	return sum
}

// Filtered follower runs ONLY after the fence and counts our marker-bearing UDP
// frames. A post-fence AF_PACKET tap is NOT used as delivery proof: Linux packet
// taps may see packets before ingress TCX. Actual UDP sockets below prove L4 delivery.
func installFenceFollower(t *testing.T, f fixture) (fixture, *ebpf.Map) {
	t.Helper()
	if err := f.policy.Close(); err != nil {
		t.Fatal(err)
	}
	at, err := f.cfg.attachType()
	if err != nil {
		t.Fatal(err)
	}
	seen, err := ebpf.NewMap(&ebpf.MapSpec{Name: "fence_seen", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = seen.Close() })
	marker := int64(binary.LittleEndian.Uint64([]byte("CMTCFENC")))
	entryName := "cil_from_container"
	if f.cfg.Direction == "egress" {
		entryName = "cil_to_container"
	}
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: entryName, Type: ebpf.SchedCLS, AttachType: at, License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.Mov.Imm(asm.R2, 42), asm.Mov.Reg(asm.R3, asm.R10), asm.Add.Imm(asm.R3, -8), asm.Mov.Imm(asm.R4, 8),
			asm.FnSkbLoadBytes.Call(), asm.JNE.Imm(asm.R0, 0, "out"),
			asm.LoadMem(asm.R7, asm.R10, -8, asm.DWord), asm.LoadImm(asm.R8, marker, asm.DWord), asm.JNE.Reg(asm.R7, asm.R8, "out"),
			asm.LoadMapPtr(asm.R1, seen.FD()), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -12), asm.StoreImm(asm.R2, 0, 0, asm.Word),
			asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "out"),
			asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.LoadMem(asm.R1, asm.R6, 0, asm.Word), asm.Add.Imm(asm.R0, 8), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("out"), asm.Return(),
		}})
	if err != nil {
		t.Fatalf("follower actual verifier: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	l, err := link.AttachTCX(link.TCXOptions{Interface: f.cfg.IfIndex, Program: p, Attach: at, Anchor: link.Tail()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	info, err := l.Info()
	if err != nil {
		t.Fatal(err)
	}
	f.policy, f.prog = l, p
	f.cfg.CiliumLinkID, f.cfg.CiliumProgramID = uint32(info.ID), uint32(info.Program)
	return f, seen
}

func udpFrame(from, to net.HardwareAddr, src, dst net.IP, sport, dport uint16) []byte {
	payload := []byte("CMTCFENC-quarantine-wire-proof")
	packet := make([]byte, 14+20+8+len(payload))
	copy(packet[:6], to)
	copy(packet[6:12], from)
	packet[12], packet[13] = 0x08, 0x00
	ip := packet[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)-14))
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	udp := packet[34:42]
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	// UDP checksum zero is valid for IPv4. No fake TCP handshake is used.
	copy(packet[42:], payload)
	return packet
}

type udpWire struct {
	direction string
	sendFD    int
	sendIf    int
	frame     []byte
	receiver  *net.UDPConn
}

func newUDPWire(t *testing.T, f fixture) *udpWire {
	t.Helper()
	hostIP, peerIP := net.IPv4(198, 18, 254, 1), net.IPv4(198, 18, 254, 2)
	from, to, dst := f.peer, f.dev, hostIP
	if f.cfg.Direction == "egress" {
		from, to, dst = f.dev, f.peer, peerIP
	}
	// Source is deliberately NOT a local address. Assigning both veth IPs in
	// one namespace would trigger accept_local/rp_filter martian checks and
	// could make a broken fence look like a drop. Install an owned /32 reverse
	// route to the input device instead; no host/global sysctl changes.
	src := net.IPv4(198, 18, 254, 99)
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: dst, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrAdd(to, addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(to, addr) })
	route := &netlink.Route{LinkIndex: to.Attrs().Index, Dst: &net.IPNet{IP: src, Mask: net.CIDRMask(32, 32)}, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: dst, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return &udpWire{direction: f.cfg.Direction, sendFD: fd, sendIf: from.Attrs().Index, frame: udpFrame(from.Attrs().HardwareAddr, to.Attrs().HardwareAddr, src, dst, 40000, uint16(conn.LocalAddr().(*net.UDPAddr).Port)), receiver: conn}
}
func (w *udpWire) send(t *testing.T) error {
	t.Helper()
	return unix.Sendto(w.sendFD, w.frame, 0, &unix.SockaddrLinklayer{Ifindex: w.sendIf, Halen: 6})
}
func (w *udpWire) mustDeliver(t *testing.T) {
	t.Helper()
	if err := w.send(t); err != nil {
		t.Fatalf("baseline send failed: %v", err)
	}
	if err := w.receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := w.receiver.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], w.frame[42:]) {
		t.Fatalf("baseline actual UDP delivery failed: n%d err%v", n, err)
	}
}
func (w *udpWire) mustDrop(t *testing.T, ownCounter, follower *ebpf.Map) {
	t.Helper()
	before := kernelDropCounters(t, ownCounter)
	followedBefore := kernelDropCounters(t, follower)
	sendErr := w.send(t)
	if sendErr != nil {
		if w.direction != "egress" || !errors.Is(sendErr, unix.ENOBUFS) {
			t.Fatalf("unexpected %s denial send failure: %v", w.direction, sendErr)
		}
		// AF_PACKET reports egress TCX_DROP as ENOBUFS on this kernel. Do not
		// mistake a socket/queue failure for denial: the synchronous return must
		// correlate to exactly this frame in THIS attached fence's own map.
		reached := kernelDropCounters(t, ownCounter)
		if reached.Packets <= before.Packets || reached.Bytes < before.Bytes ||
			reached.Packets-before.Packets != 1 || reached.Bytes-before.Bytes != uint64(len(w.frame)) {
			t.Fatalf("ENOBUFS without exact own-fence frame accounting: before=%+v after=%+v frameBytes=%d", before, reached, len(w.frame))
		}
	}
	if err := w.receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := w.receiver.ReadFromUDP(buf)
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("quarantine leaked UDP or wrong receive failure: n%d err%v", n, err)
	}
	after := kernelDropCounters(t, ownCounter)
	if after.Packets <= before.Packets || after.Bytes < before.Bytes || after.Bytes-before.Bytes < uint64(len(w.frame)) {
		t.Fatalf("attempt lacks positive own-fence packet/byte accounting: before=%+v after=%+v", before, after)
	}
	if followedAfter := kernelDropCounters(t, follower); followedAfter != followedBefore {
		t.Fatalf("denied attempt reached following program: before=%+v after=%+v", followedBefore, followedAfter)
	}
}

// Load only the accounted map, not a link FD or an adopting/reparing handle.
// Holding this map cannot keep a process-owned TCX link alive across SIGKILL.
func pinnedFenceCounter(t *testing.T, cfg FenceConfig, programID uint32) *ebpf.Map {
	t.Helper()
	counter, err := ebpf.LoadPinnedMap(filepath.Join(cfg.PinRoot, cfg.key(), "accounted"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = counter.Close() })
	mi, err := counter.Info()
	if err != nil {
		t.Fatal(err)
	}
	mid, ok := mi.ID()
	if !ok || mi.Type != ebpf.PerCPUArray || mi.KeySize != 4 || mi.ValueSize != 16 || mi.MaxEntries != 1 {
		t.Fatal("wrong own-fence counter map")
	}
	program, err := ebpf.NewProgramFromID(ebpf.ProgramID(programID))
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	pi, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := pi.MapIDs()
	if !ok || pi.Name != "cmtc_fence" || len(ids) != 1 || ids[0] != mid {
		t.Fatal("pinned counter is not the exact attached fence program's map")
	}
	return counter
}
func attachDenyForKernelTest(t *testing.T, f fixture, elf []byte) *ebpf.Collection {
	t.Helper()
	at, err := f.cfg.attachType()
	if err != nil {
		t.Fatal(err)
	}
	coll := loadFenceCollection(t, elf, at)
	q, _, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := link.NewFromID(link.ID(f.cfg.CiliumLinkID))
	if err != nil {
		t.Fatal(err)
	}
	l, err := link.AttachTCX(link.TCXOptions{Interface: f.cfg.IfIndex, Program: coll.Programs["cmtc_fence"], Attach: at, Anchor: link.BeforeLink(anchor), ExpectedRevision: q.Revision})
	_ = anchor.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return coll
}
func TestPrivilegedFenceUDPAndFollowerStopBothDirections(t *testing.T) {
	elf := requireFenceELF(t)
	for _, dir := range []string{"ingress", "egress"} {
		t.Run(dir, func(t *testing.T) {
			f, seen := installFenceFollower(t, directionalFixture(t, dir))
			wire := newUDPWire(t, f)
			wire.mustDeliver(t)
			before := kernelDropCounters(t, seen)
			if before.Packets == 0 {
				t.Fatal("follower did not see real baseline UDP packet")
			}
			coll := attachDenyForKernelTest(t, f, elf)
			// Each timeout is independent evidence that the actual UDP socket,
			// rather than an AF_PACKET tap before TCX, did not receive the frame.
			for range 3 {
				wire.mustDrop(t, coll.Maps["accounted"], seen)
			}
			after := kernelDropCounters(t, seen)
			if after != before {
				t.Fatalf("following program executed after fence drop: before%+v after%+v", before, after)
			}
			dropped := kernelDropCounters(t, coll.Maps["accounted"])
			if dropped.Packets < 3 {
				t.Fatalf("kernel did not account actual dropped frames: %+v", dropped)
			}
		})
	}
}

func privateFenceRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := unix.Mount("bpf", root, "bpf", 0, "mode=0700"); err != nil {
		t.Fatalf("private rootful bpffs mount required: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, unix.MNT_DETACH); err != nil {
			t.Errorf("private bpffs unmount: %v", err)
		}
	})
	// Validate exact root mode after mount; underlying directory mode alone
	// does not set mode of the newly mounted filesystem root.
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func fixtureFenceConfig(t *testing.T, f fixture, root string) FenceConfig {
	t.Helper()
	lockRoot := t.TempDir()
	if err := os.Chmod(lockRoot, 0700); err != nil {
		t.Fatal(err)
	}
	return FenceConfig{Cluster: f.cfg.Cluster, Node: f.cfg.Node, NamespaceUID: "fixture-namespace-uid",
		PodUID: f.cfg.PodUID, NetNSInode: f.cfg.NetNSInode, IfIndex: f.cfg.IfIndex, IfName: f.cfg.IfName,
		MAC: f.cfg.MAC, PeerIfIndex: f.cfg.PeerIfIndex, Direction: f.cfg.Direction,
		CiliumLinkID: f.cfg.CiliumLinkID, CiliumProgramID: f.cfg.CiliumProgramID,
		PinRoot: root, LockRoot: lockRoot}
}

type fenceChild struct {
	cmd        *exec.Cmd
	done       chan struct{}
	err        error
	log, ready string
}

func installFenceInChild(t *testing.T, cfg FenceConfig) *fenceChild {
	t.Helper()
	normalRoot := t.TempDir()
	logPath := filepath.Join(normalRoot, "child.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	child := &fenceChild{done: make(chan struct{}), log: logPath, ready: filepath.Join(normalRoot, "ready")}
	child.cmd = exec.Command(os.Args[0], "-test.run=^$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "CMTC_FENCE_KERNEL_CHILD=") && !strings.HasPrefix(entry, "CMTC_FENCE_KERNEL_CONFIG=") && !strings.HasPrefix(entry, "CMTC_FENCE_KERNEL_READY=") {
			child.cmd.Env = append(child.cmd.Env, entry)
		}
	}
	child.cmd.Env = append(child.cmd.Env, "CMTC_FENCE_KERNEL_CHILD=install", "CMTC_FENCE_KERNEL_CONFIG="+string(body), "CMTC_FENCE_KERNEL_READY="+child.ready)
	child.cmd.Stdout, child.cmd.Stderr = logFile, logFile
	if err := child.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { child.err = child.cmd.Wait(); close(child.done) }()
	t.Cleanup(func() {
		_ = child.cmd.Process.Kill()
		select {
		case <-child.done:
		case <-time.After(5 * time.Second):
			t.Errorf("installer child not reaped")
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-child.done:
			logs, _ := os.ReadFile(child.log)
			t.Fatalf("installer child exited: %v\n%s", child.err, logs)
		default:
		}
		if data, err := os.ReadFile(child.ready); err == nil && string(data) == "installed\n" {
			return child
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs, _ := os.ReadFile(child.log)
	t.Fatalf("installer did not acknowledge actual pinned attach\n%s", logs)
	return nil
}
func killFenceInstaller(t *testing.T, c *fenceChild) {
	t.Helper()
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("installer SIGKILL not reaped")
	}
	var exit *exec.ExitError
	if !errors.As(c.err, &exit) {
		t.Fatalf("wanted SIGKILL ExitError, got %v", c.err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("not actual SIGKILL: %v", exit.Sys())
	}
}
func fenceChain(t *testing.T, cfg Config) []attachment {
	t.Helper()
	_, ids, err := query(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}
func TestPrivilegedFencePinnedCrashDenyAndDefunctCleanup(t *testing.T) {
	elf := requireFenceELF(t)
	for _, dir := range []string{"ingress", "egress"} {
		t.Run(dir, func(t *testing.T) {
			root := privateFenceRoot(t)
			f, seen := installFenceFollower(t, directionalFixture(t, dir))
			wire := newUDPWire(t, f)
			wire.mustDeliver(t)
			before := kernelDropCounters(t, seen)
			baseline := fenceChain(t, f.cfg)
			c := fixtureFenceConfig(t, f, root)
			child := installFenceInChild(t, c)
			installed := fenceChain(t, f.cfg)
			if len(installed) != len(baseline)+1 || !reflect.DeepEqual(installed[1:], baseline) {
				t.Fatalf("installed chain not exact own+baseline: %v vs %v", installed, baseline)
			}
			denyCounter := pinnedFenceCounter(t, c, installed[0].Program)
			wire.mustDrop(t, denyCounter, seen)
			if got := kernelDropCounters(t, seen); got != before {
				t.Fatalf("follower ran under deny: %+v vs %+v", got, before)
			}
			killFenceInstaller(t, child)
			// Real denial is checked BEFORE adoption can rewrite/reset anything.
			if got := fenceChain(t, f.cfg); !reflect.DeepEqual(got, installed) {
				t.Fatalf("SIGKILL removed/changed persistent fence: %v vs %v", got, installed)
			}
			wire.mustDrop(t, denyCounter, seen)
			if got := kernelDropCounters(t, seen); got != before {
				t.Fatalf("crash reopened following program: %+v vs %+v", got, before)
			}
			// Active quarantine may never be removed by a cleanup/adopt mismatch.
			if err := RetireDefunctFence(c, elf); err == nil {
				t.Fatal("live original fence retired")
			}
			if got := fenceChain(t, f.cfg); !reflect.DeepEqual(got, installed) {
				t.Fatal("live-retire refusal changed chain")
			}
			adopted, err := AdoptFence(c, elf)
			if err != nil {
				t.Fatalf("exact pinned adoption: %v", err)
			}
			count, err := adopted.Account()
			if err != nil {
				_ = adopted.ReleaseProcess()
				t.Fatal(err)
			}
			if count.DroppedPackets < 2 {
				_ = adopted.ReleaseProcess()
				t.Fatalf("persistent fence did not count actual pre/post-crash drops: %+v", count)
			}
			if err := adopted.ReleaseProcess(); err != nil {
				t.Fatal(err)
			}
			wire.mustDrop(t, denyCounter, seen)
			if got := fenceChain(t, f.cfg); !reflect.DeepEqual(got, installed) {
				t.Fatal("ReleaseProcess detached persistent fence")
			}
			// Only a defunct owned netdevice qualifies for this cleanup API.
			if err := netlink.LinkDel(f.dev); err != nil {
				t.Fatal(err)
			}
			if err := RetireDefunctFence(c, elf); err != nil {
				t.Fatalf("validated defunct fence cleanup: %v", err)
			}
			if _, err := AdoptFence(c, elf); err == nil {
				t.Fatal("retired defunct fence remained adoptable")
			}
			// Verify the Cilium-like follower's separately owned program FD is still
			// valid. Its device was intentionally deleted; don't claim live reachability.
			if _, err := f.prog.Info(); err != nil {
				t.Fatalf("cleanup invalidated foreign program FD: %v", err)
			}
		})
	}
}

func TestPrivilegedFenceOccupiedListenerDoesNotAttach(t *testing.T) {
	binaryPath := os.Getenv("CMTC_BPF_FENCE_BIN")
	if binaryPath == "" {
		t.Fatal("CMTC_BPF_FENCE_BIN must identify freshly compiled CLI")
	}
	fx, _ := installFenceFollower(t, directionalFixture(t, "ingress"))
	cfg := fixtureFenceConfig(t, fx, privateFenceRoot(t))
	before := fenceChain(t, fx.cfg)
	listener, err := net.Listen("tcp", "127.0.0.1:18083")
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "--config="+configPath, "--elf="+elfPath)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NODE_NAME=") && !strings.HasPrefix(entry, "CLUSTER_NAME=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "NODE_NAME="+cfg.Node, "CLUSTER_NAME="+cfg.Cluster)
	out, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil || !bytes.Contains(out, []byte("address already in use")) {
		t.Fatalf("listener not reserved before ELF load/attachment: %v %s", err, out)
	}
	if got := fenceChain(t, fx.cfg); !reflect.DeepEqual(got, before) {
		t.Fatal("occupied listener changed foreign chain")
	}
	if _, err := os.Stat(filepath.Join(cfg.PinRoot, cfg.key())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("occupied listener created a pin transaction: %v", err)
	}
}
