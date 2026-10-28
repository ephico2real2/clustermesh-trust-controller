//go:build linux && cmtc_bpf_privileged

package measurement

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests run the Plane on real sockets. A child process in a fake kubelet Pod cgroup sends DNS queries over lo
// and over a veth pair to servers in another network namespace, and the tests compare the plane's counters with what
// the child sent. They also attach programs to ancestor cgroups the way another tool may, and remove the Pod and its
// cgroup. They need root in a disposable private container (scripts/measurement/test-kernel.sh) and create a cgroup
// subtree, a veth pair and a network namespace there. They are not lab qualification.

const (
	testUID       = "4f9d2c3e-7a1b-4c5d-9e8f-0a1b2c3d4e5f"
	testNamespace = "cmtc-test"
	// helperEnv makes the test binary run the DNS client instead of the tests (TestMain).
	helperEnv = "CMTC_MEASUREMENT_TEST_HELPER"

	// The client's end of the veth pair, and the servers' addresses in their own network namespace.
	clientAddress  = "10.99.0.1/24"
	sameNodeServer = "10.99.0.2" // the tests give it to SetNodeAddresses, as the address of a Pod of this node
	offNodeServer  = "10.99.0.3"
)

// DNS IDs of the client's exchanges.
const (
	idConnected   = 0x0101
	idUnconnected = 0x0202
	idLoopback    = 0x0303
	idZtunnel     = 0x0404
	idTCP         = 0x0505
	idRetry       = 0x0606 // the client sends it twice; the server answers twice, after the second query
	idNXDomain    = 0x0707 // the server answers with rcode 3
)

// Indexes of RCodes.
const rcNoError, rcNXDomain = 0, 3

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "dns-client" {
		if err := dnsClient(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// dnsSteps are the client's exchanges, by name.
var dnsSteps = map[string]func() error{
	"connected":   func() error { return udpExchange(sameNodeServer+":53", true, idConnected, 1, 1) },
	"unconnected": func() error { return udpExchange(offNodeServer+":53", false, idUnconnected, 1, 1) },
	"loopback":    func() error { return udpExchange("127.0.0.1:53", true, idLoopback, 1, 1) },
	"ztunnel":     func() error { return udpExchange("127.0.0.1:15053", true, idZtunnel, 1, 1) },
	"tcp":         func() error { return tcpExchange(sameNodeServer+":53", idTCP) },
	"retry":       func() error { return udpExchange(offNodeServer+":53", true, idRetry, 2, 2) },
	"nxdomain":    func() error { return udpExchange(sameNodeServer+":53", true, idNXDomain, 1, 1) },
}

// dnsClient runs the named exchanges in order. Each reads every answer it expects, so the counters are final when
// the client exits.
func dnsClient(steps []string) error {
	for _, name := range steps {
		step, ok := dnsSteps[name]
		if !ok {
			return fmt.Errorf("unknown step %q", name)
		}
		if err := step(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// udpExchange sends a query with id to server the given number of times, on a connected socket or with sendto, and
// reads the given number of answers.
func udpExchange(server string, connected bool, id uint16, queries, answers int) error {
	raddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(server))
	var c *net.UDPConn
	var err error
	if connected {
		c, err = net.DialUDP("udp4", nil, raddr)
	} else {
		c, err = net.ListenUDP("udp4", nil)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	q := dnsMessage(id, false, 0, 0, 1)
	for i := 0; i < queries; i++ {
		if connected {
			_, err = c.Write(q)
		} else {
			_, err = c.WriteToUDP(q, raddr)
		}
		if err != nil {
			return err
		}
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, 512)
	for i := 0; i < answers; i++ {
		n, err := c.Read(buf)
		if err != nil {
			return fmt.Errorf("answer %d from %s: %w", i+1, server, err)
		}
		if err := checkAnswer(buf[:n], id); err != nil {
			return err
		}
	}
	return nil
}

// tcpExchange sends one length-prefixed query with id to server over TCP and reads the answer.
func tcpExchange(server string, id uint16) error {
	c, err := net.DialTimeout("tcp4", server, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := c.Write(tcpDNS(dnsMessage(id, false, 0, 0, 1))); err != nil {
		return err
	}
	var length [2]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return err
	}
	m := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(c, m); err != nil {
		return err
	}
	return checkAnswer(m, id)
}

func checkAnswer(m []byte, id uint16) error {
	if want := dnsMessage(id, true, 0, rcodeFor(id), 1); string(m) != string(want) {
		return fmt.Errorf("answer % x, want % x", m, want)
	}
	return nil
}

// rcodeFor is the response code that the test servers answer id with.
func rcodeFor(id uint16) byte {
	if id == idNXDomain {
		return rcNXDomain
	}
	return rcNoError
}

// serveUDP answers each query on c with the same message as an answer. It holds the first query with idRetry until
// the client sends it again, then answers twice: the first answer finds the waiting query, the second finds none.
func serveUDP(c *net.UDPConn) {
	held := 0
	buf := make([]byte, 512)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return // the test closed c
		}
		if n < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(buf)
		answers := 1
		if id == idRetry {
			held++
			if held < 2 {
				continue
			}
			answers = 2
		}
		for i := 0; i < answers; i++ {
			_, _ = c.WriteToUDP(dnsMessage(id, true, 0, rcodeFor(id), 1), from)
		}
	}
}

// serveTCP answers one length-prefixed query on each connection, then closes it.
func serveTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return // the test closed l
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var length [2]byte
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(length[:]))
			if _, err := io.ReadFull(c, q); err != nil || len(q) < 2 {
				return
			}
			id := binary.BigEndian.Uint16(q)
			_, _ = c.Write(tcpDNS(dnsMessage(id, true, 0, rcodeFor(id), 1)))
		}()
	}
}

func listenUDP(t testing.TB, addr string) {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go serveUDP(c)
}

// startLoopbackServers starts UDP DNS servers on 127.0.0.1:53, where an in-Pod proxy listens, and on
// 127.0.0.1:15053, ztunnel's DNS port. The test process is not in the Pod cgroup, so the servers' own packets are not
// measured.
func startLoopbackServers(t testing.TB) {
	t.Helper()
	listenUDP(t, "127.0.0.1:53")
	listenUDP(t, "127.0.0.1:15053")
}

// startServerNamespace joins this network namespace to a new one through a veth pair, and starts the DNS servers of
// sameNodeServer and offNodeServer there. A packet to them leaves the client through the veth device, the pod_network
// path, as a packet to another Pod does.
func startServerNamespace(t *testing.T) {
	t.Helper()
	ns := inNetworkNamespace(t, nil, func() {})
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cmtcv0"}, PeerName: "cmtcv1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create the veth pair: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	peer, err := netlink.LinkByName("cmtcv1")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetNsFd(peer, int(ns.Fd())); err != nil {
		t.Fatalf("move the veth peer: %v", err)
	}
	setUp(t, "cmtcv0", clientAddress)
	inNetworkNamespace(t, ns, func() {
		setUp(t, "cmtcv1", sameNodeServer+"/24", offNodeServer+"/24")
		listenUDP(t, sameNodeServer+":53")
		listenUDP(t, offNodeServer+":53")
		l, err := net.Listen("tcp4", sameNodeServer+":53")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go serveTCP(l)
	})
}

// inNetworkNamespace runs f with the calling goroutine's thread in the network namespace ns, or in a new one when ns
// is nil, and returns the namespace f ran in. Netlink requests and new sockets belong to the namespace of the thread
// that makes them. The thread returns to its own namespace afterwards; when it cannot, it stays locked, and the Go
// runtime discards it with the goroutine.
func inNetworkNamespace(t *testing.T, ns *os.File, f func()) *os.File {
	t.Helper()
	runtime.LockOSThread()
	own, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer own.Close()
	if ns == nil {
		err = unix.Unshare(unix.CLONE_NEWNET)
	} else {
		err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
	}
	if err != nil {
		runtime.UnlockOSThread() // the thread did not change namespace
		t.Fatalf("enter a network namespace: %v", err)
	}
	if ns == nil {
		if ns, err = os.Open("/proc/thread-self/ns/net"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ns.Close() })
	}
	f()
	if err := unix.Setns(int(own.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatalf("return to the test's network namespace: %v", err)
	}
	runtime.UnlockOSThread()
	return ns
}

// setUp gives the device its addresses and brings it up.
func setUp(t *testing.T, device string, addresses ...string) {
	t.Helper()
	l, err := netlink.LinkByName(device)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addresses {
		addr, err := netlink.ParseAddr(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(l, addr); err != nil {
			t.Fatalf("add %s to %s: %v", a, device, err)
		}
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
}

// cgroupTree is an empty cgroup subtree for one test. The plane treats its root as the host's cgroup mount.
type cgroupTree struct{ root string }

func newCgroupTree(t testing.TB) cgroupTree {
	t.Helper()
	root, err := os.MkdirTemp("/sys/fs/cgroup", "cmtc-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeCgroups(t, root) })
	return cgroupTree{root}
}

// createPod creates the cgroup of a BestEffort Pod where kubelet's systemd cgroup driver puts it, and returns it.
func (c cgroupTree) createPod(t testing.TB, uid string) string {
	t.Helper()
	dir := filepath.Join(c.root, "kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// removeCgroups removes root and every cgroup below it, deepest first.
func removeCgroups(t testing.TB, root string) {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := unix.Rmdir(dirs[i]); err != nil && !errors.Is(err, unix.ENOENT) {
			t.Errorf("remove cgroup %s: %v", dirs[i], err)
		}
	}
}

// openTestPlane opens a plane on the cgroup tree at root. It loads the programs with the loader's capabilities
// (asLoader), and so does reconcile, which loads a copy of them for each Pod it attaches.
func openTestPlane(t *testing.T, root string) *Plane {
	t.Helper()
	spec, err := LoadSpec()
	if err != nil {
		t.Fatal(err)
	}
	var p *Plane
	asLoader(t, func() { p, err = OpenPlane(spec, root, testr.New(t)) })
	if err != nil {
		t.Fatal(err)
	}
	if p.loadErr != nil {
		t.Fatalf("the kernel refused the programs: %s", verifierLog(p.loadErr))
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func reconcile(t testing.TB, p *Plane, desired []DesiredPod, now time.Time) {
	t.Helper()
	asLoader(t, func() { p.Reconcile(desired, now) })
}

// requireState fails unless the plane's snapshot shows the Pod in state, with a reason that contains reason.
func requireState(t *testing.T, p *Plane, uid, state, reason string) {
	t.Helper()
	for _, s := range p.Snapshot("boot", 0).Pods {
		if s.UID == uid {
			if s.State != state || !strings.Contains(s.Reason, reason) {
				t.Fatalf("Pod %s is %s (%q), want %s with a reason containing %q", uid, s.State, s.Reason, state, reason)
			}
			return
		}
	}
	t.Fatalf("Pod %s is not in the snapshot, want %s", uid, state)
}

// running returns the programs of the attach type that run for the cgroup at dir: its own and the inherited ones.
func running(t testing.TB, dir string, attach ebpf.AttachType) programSet {
	t.Helper()
	set, err := queryPrograms(dir, attach, unix.BPF_F_QUERY_EFFECTIVE)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// requireNoPrograms fails if a program of either hook runs for the cgroup at dir.
func requireNoPrograms(t *testing.T, dir string) {
	t.Helper()
	for _, prog := range Programs {
		if ids := running(t, dir, prog.Attach); len(ids) != 0 {
			t.Fatalf("%d %s programs still run for %s", len(ids), prog.Attach, dir)
		}
	}
}

// runClient runs the test binary as the DNS client, with the named steps of dnsSteps, in the cgroup at dir.
func runClient(t *testing.T, dir string, steps ...string) {
	t.Helper()
	cg, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	cmd := exec.Command(os.Args[0], steps...)
	cmd.Env = append(os.Environ(), helperEnv+"=dns-client")
	// The kernel starts the child in the Pod cgroup (clone3 with CLONE_INTO_CGROUP), so every socket of the child
	// belongs to that cgroup.
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("DNS client: %v\n%s", err, out)
	}
}

// passProgram returns a cgroup_skb program that keeps every packet, as another tool's observer would.
func passProgram(t *testing.T) (*ebpf.Program, ebpf.ProgramID) {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cmtc_test_pass", Type: ebpf.CGroupSKB, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { prog.Close() })
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("the kernel reports no program ID")
	}
	return prog, id
}

// legacyAttach attaches prog to the egress hook of dir with BPF_PROG_ATTACH and flags (0 is the kernel's mode
// "none"), as another tool may. Such an attachment outlives its descriptor: the returned function detaches it, and so
// does the test's cleanup.
func legacyAttach(t *testing.T, dir string, prog *ebpf.Program, flags uint32) (detach func()) {
	t.Helper()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := link.RawAttachProgramOptions{Target: int(f.Fd()), Program: prog, Attach: ebpf.AttachCGroupInetEgress,
		Flags: flags}
	if err := link.RawAttachProgram(opts); err != nil {
		f.Close()
		t.Fatalf("attach a program with flags %#x to %s: %v", flags, dir, err)
	}
	var once sync.Once
	detach = func() {
		once.Do(func() {
			if err := link.RawDetachProgram(link.RawDetachProgramOptions(opts)); err != nil {
				t.Errorf("detach the program from %s: %v", dir, err)
			}
			f.Close()
		})
	}
	t.Cleanup(detach)
	return detach
}

// linkAttach attaches prog to the egress hook of dir through a bpf_link, which always uses BPF_F_ALLOW_MULTI.
func linkAttach(t *testing.T, dir string, prog *ebpf.Program) {
	t.Helper()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l, err := link.AttachRawLink(link.RawLinkOptions{Target: int(f.Fd()), Program: prog,
		Attach: ebpf.AttachCGroupInetEgress})
	if err != nil {
		t.Fatalf("attach a program to %s through a bpf_link: %v", dir, err)
	}
	t.Cleanup(func() { l.Close() })
}

// The client's seven exchanges, with every counter they must change.
func TestPlaneCountsDNSOnRealSockets(t *testing.T) {
	requirePrivileged(t)
	startLoopbackServers(t)
	startServerNamespace(t)
	tree := newCgroupTree(t)
	pod := tree.createPod(t, testUID)
	p := openTestPlane(t, tree.root)
	if err := p.SetNodeAddresses([]string{sameNodeServer}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	reconcile(t, p, []DesiredPod{{UID: testUID, Namespace: testNamespace, Required: true}}, now)
	requireState(t, p, testUID, StateAttached, "")

	runClient(t, pod, "connected", "unconnected", "loopback", "ztunnel", "tcp", "retry", "nxdomain")
	p.Read(now)
	s := p.Snapshot("boot", 0)
	got := s.Namespaces[testNamespace]

	var want PodCounters
	want.DNSQueries[tUDP][sameNode] = 2 // connected, nxdomain
	want.DNSQueries[tUDP][offNode] = 3  // unconnected, retry twice
	want.DNSQueries[tUDP][inPod] = 2    // loopback, ztunnel
	want.DNSQueries[tTCP][sameNode] = 1
	want.DNSAnswers[tUDP][sameNode][rcNoError] = 1
	want.DNSAnswers[tUDP][sameNode][rcNXDomain] = 1
	want.DNSAnswers[tUDP][offNode][rcNoError] = 3 // unconnected, both answers of retry
	want.DNSAnswers[tUDP][inPod][rcNoError] = 2
	want.DNSAnswers[tTCP][sameNode][rcNoError] = 1
	if got.DNSQueries != want.DNSQueries {
		t.Errorf("DNS queries %v, want %v", got.DNSQueries, want.DNSQueries)
	}
	if got.DNSAnswers != want.DNSAnswers {
		t.Errorf("DNS answers %v, want %v", got.DNSAnswers, want.DNSAnswers)
	}

	// lo carried the exchanges with the two in-Pod servers: one query and one answer each, of 47 bytes (IPv4 20,
	// UDP 8, DNS 19).
	for _, d := range []int{egress, ingress} {
		if c := got.Traffic[d][loopback][pDNS]; c != (Counter{Packets: 2, Bytes: 94}) {
			t.Errorf("%s loopback dns %+v, want 2 packets of 94 bytes", Directions[d], c)
		}
	}
	// The veth device carried five UDP queries and five UDP answers, and the TCP connection: at least the SYN, the ACK
	// and the query out (21 bytes of payload), and the SYN-ACK and the answer in.
	if c := got.Traffic[egress][network][pDNS]; c.Packets < 5+3 || c.Bytes < 5*47+3*40+21 {
		t.Errorf("egress pod_network dns %+v, want at least 8 packets and 376 bytes", c)
	}
	if c := got.Traffic[ingress][network][pDNS]; c.Packets < 5+2 || c.Bytes < 5*47+2*40+21 {
		t.Errorf("ingress pod_network dns %+v, want at least 7 packets and 336 bytes", c)
	}
	for d := range got.Traffic {
		for path := range got.Traffic[d] {
			for proto, c := range got.Traffic[d][path] {
				if proto != pDNS && c != (Counter{}) {
					t.Errorf("%s %s %s %+v, want no packet", Directions[d], Paths[path], Protocols[proto], c)
				}
			}
		}
	}

	// Every answer but the second of retry found its query, so the pending table is empty.
	var wantMatched [NumTransports][NumLocalities]uint64
	wantMatched[tUDP][sameNode], wantMatched[tUDP][offNode], wantMatched[tUDP][inPod] = 2, 2, 2
	wantMatched[tTCP][sameNode] = 1
	for tr := range wantMatched {
		for l := range wantMatched[tr] {
			var n uint64
			for _, c := range s.Node.LatencyCount[tr][l] {
				n += c
			}
			sum := s.Node.LatencySumNs[tr][l]
			if n != wantMatched[tr][l] || (n > 0) != (sum > 0) {
				t.Errorf("%s %s: %d timed answers with %d ns in total, want %d", Transports[tr], Localities[l], n, sum,
					wantMatched[tr][l])
			}
		}
	}
	if s.Node.Unmatched != [NumTransports]uint64{1, 0} {
		t.Errorf("unmatched answers %v, want [1 0]", s.Node.Unmatched)
	}
	if s.Node.Replaced != [NumTransports]uint64{1, 0} {
		t.Errorf("replaced queries %v, want [1 0]", s.Node.Replaced)
	}
	var key pendingKey
	var sent uint64
	entries := p.maps[MapPending].Iterate()
	waiting := 0
	for entries.Next(&key, &sent) {
		waiting++
	}
	if err := entries.Err(); err != nil {
		t.Fatal(err)
	}
	if waiting != 0 {
		t.Errorf("%d queries still wait for an answer, want 0", waiting)
	}
}

// The plane never attaches below a cgroup whose programs a program on the Pod cgroup would stop (checkAncestors), and
// detaches when such a program appears later (verify).
func TestPlaneNeverStopsAnAncestorProgram(t *testing.T) {
	requirePrivileged(t)
	desired := []DesiredPod{{UID: testUID, Namespace: testNamespace, Required: true}}

	t.Run("a program attached with BPF_F_ALLOW_OVERRIDE after the plane's", func(t *testing.T) {
		tree := newCgroupTree(t)
		pod := tree.createPod(t, testUID)
		p := openTestPlane(t, tree.root)
		reconcile(t, p, desired, time.Now())
		requireState(t, p, testUID, StateAttached, "")
		prog, id := passProgram(t)
		detach := legacyAttach(t, filepath.Dir(pod), prog, unix.BPF_F_ALLOW_OVERRIDE)
		// The kernel accepts the attachment, and does not run it for the Pod cgroup while the plane's program is there
		// (kernel/bpf/cgroup.c, compute_effective_progs). This is the override the plane must not cause.
		if running(t, pod, ebpf.AttachCGroupInetEgress)[id] {
			t.Fatal("the kernel runs the ancestor's program for the Pod cgroup; the premise of the guard does not hold")
		}
		reconcile(t, p, desired, time.Now())
		requireState(t, p, testUID, StateUnavailable, "without BPF_F_ALLOW_MULTI")
		if !running(t, pod, ebpf.AttachCGroupInetEgress)[id] {
			t.Fatal("the ancestor's program does not run for the Pod after the plane detached")
		}
		detach()
		reconcile(t, p, desired, time.Now())
		requireState(t, p, testUID, StateAttached, "")
	})

	t.Run("a program attached without flags before the plane's", func(t *testing.T) {
		tree := newCgroupTree(t)
		pod := tree.createPod(t, testUID)
		p := openTestPlane(t, tree.root)
		prog, id := passProgram(t)
		legacyAttach(t, filepath.Dir(pod), prog, 0)
		reconcile(t, p, desired, time.Now())
		requireState(t, p, testUID, StateUnavailable, "without BPF_F_ALLOW_MULTI")
		if ids := running(t, pod, ebpf.AttachCGroupInetEgress); len(ids) != 1 || !ids[id] {
			t.Fatalf("programs %v run for the Pod cgroup, want only the ancestor's %d", ids, id)
		}
		if ids := running(t, pod, ebpf.AttachCGroupInetIngress); len(ids) != 0 {
			t.Fatalf("programs %v run on ingress for the Pod cgroup; the plane must attach neither hook", ids)
		}
	})

	t.Run("a program attached through a bpf_link", func(t *testing.T) {
		tree := newCgroupTree(t)
		pod := tree.createPod(t, testUID)
		p := openTestPlane(t, tree.root)
		prog, id := passProgram(t)
		linkAttach(t, filepath.Dir(pod), prog)
		reconcile(t, p, desired, time.Now())
		reconcile(t, p, desired, time.Now()) // verify passes too
		requireState(t, p, testUID, StateAttached, "")
		ids := running(t, pod, ebpf.AttachCGroupInetEgress)
		if len(ids) != 2 || !ids[id] || !ids[p.attached[testUID].progIDs[egress]] {
			t.Fatalf("programs %v run for the Pod cgroup, want the ancestor's %d and the plane's", ids, id)
		}
	})

	t.Run("a program that runs for the root from above it", func(t *testing.T) {
		tree := newCgroupTree(t)
		tree.createPod(t, testUID)
		p := openTestPlane(t, tree.root)
		prog, _ := passProgram(t)
		// The tree's parent stands for a cgroup above the host's mount, whose attach flags the loader cannot read.
		linkAttach(t, filepath.Dir(tree.root), prog)
		reconcile(t, p, desired, time.Now())
		requireState(t, p, testUID, StateUnavailable, "above the mount")
	})
}

// A Pod waits for its cgroup, is attached, detached and retired, attached again, and loses its cgroup; the namespace's
// counters only grow, and Close leaves no program.
func TestPlaneLifecycle(t *testing.T) {
	requirePrivileged(t)
	startLoopbackServers(t)
	tree := newCgroupTree(t)
	p := openTestPlane(t, tree.root)
	desired := []DesiredPod{{UID: testUID, Namespace: testNamespace, Required: true}}
	start := time.Now()
	at := func(seconds float64) time.Time { return start.Add(time.Duration(seconds * float64(time.Second))) }
	queries := func() uint64 { return p.Snapshot("boot", 0).Namespaces[testNamespace].DNSQueries[tUDP][inPod] }

	reconcile(t, p, desired, at(0))
	requireState(t, p, testUID, StateWaiting, "not created yet")

	pod := tree.createPod(t, testUID)
	reconcile(t, p, desired, at(0))
	requireState(t, p, testUID, StateAttached, "")
	first := p.attached[testUID]
	for i, prog := range Programs {
		if !running(t, pod, prog.Attach)[first.progIDs[i]] {
			t.Fatalf("%s does not run for the Pod cgroup", prog.Name)
		}
	}
	runClient(t, pod, "loopback")
	p.Read(at(0))
	if n := queries(); n != 1 {
		t.Fatalf("%d queries, want 1", n)
	}

	// A Pod that leaves the desired list is detached at once. Its arrays are read a last time retireDelay later and
	// closed; the namespace keeps its counts.
	reconcile(t, p, nil, at(1))
	requireNoPrograms(t, pod)
	if pods := p.Snapshot("boot", 0).Pods; len(pods) != 0 {
		t.Fatalf("snapshot Pods %+v, want none", pods)
	}
	reconcile(t, p, nil, at(1.5))
	if len(p.retiring) != 1 {
		t.Fatalf("%d attachments retiring at half the retire delay, want 1", len(p.retiring))
	}
	reconcile(t, p, nil, at(2))
	if len(p.retiring) != 0 || len(p.acc.last) != 0 {
		t.Fatalf("%d attachments retiring and %d read after the retire delay, want none", len(p.retiring),
			len(p.acc.last))
	}
	if fd := first.coll.Maps[MapTraffic].FD(); fd != -1 {
		t.Fatalf("the retired Pod's %s is still open (descriptor %d)", MapTraffic, fd)
	}
	if n := queries(); n != 1 {
		t.Fatalf("%d queries after the Pod left, want 1", n)
	}

	// Measured again, the Pod adds to the namespace's total.
	reconcile(t, p, desired, at(3))
	requireState(t, p, testUID, StateAttached, "")
	runClient(t, pod, "loopback")
	p.Read(at(3))
	if n := queries(); n != 2 {
		t.Fatalf("%d queries, want 2", n)
	}

	// When the Pod cgroup goes away, the Pod waits for a new one, and is attached to it.
	if err := unix.Rmdir(pod); err != nil {
		t.Fatal(err)
	}
	reconcile(t, p, desired, at(4))
	requireState(t, p, testUID, StateWaiting, "not created yet")
	tree.createPod(t, testUID)
	reconcile(t, p, desired, at(5))
	requireState(t, p, testUID, StateAttached, "")
	if p.attached[testUID].cgroupID == first.cgroupID {
		t.Fatal("attached to the removed cgroup")
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoPrograms(t, pod)
}

// Each Pod's copy of the programs counts into arrays of its own: one Pod's packets never show in another Pod's
// namespace.
func TestPlaneKeepsEachPodsCountsApart(t *testing.T) {
	requirePrivileged(t)
	startLoopbackServers(t)
	const otherUID, otherNamespace = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "cmtc-test-other"
	tree := newCgroupTree(t)
	pod, other := tree.createPod(t, testUID), tree.createPod(t, otherUID)
	p := openTestPlane(t, tree.root)
	now := time.Now()
	reconcile(t, p, []DesiredPod{{UID: testUID, Namespace: testNamespace, Required: true},
		{UID: otherUID, Namespace: otherNamespace, Required: true}}, now)
	requireState(t, p, testUID, StateAttached, "")
	requireState(t, p, otherUID, StateAttached, "")

	runClient(t, pod, "loopback")
	p.Read(now)
	got := p.Snapshot("boot", 0).Namespaces
	if n := got[testNamespace].DNSQueries[tUDP][inPod]; n != 1 {
		t.Fatalf("%s has %d queries, want 1", testNamespace, n)
	}
	if got[otherNamespace] != (PodCounters{}) {
		t.Fatalf("%s counted the other Pod's packets: %+v", otherNamespace, got[otherNamespace])
	}

	runClient(t, other, "loopback", "loopback")
	p.Read(now)
	got = p.Snapshot("boot", 0).Namespaces
	if a, b := got[testNamespace].DNSQueries[tUDP][inPod], got[otherNamespace].DNSQueries[tUDP][inPod]; a != 1 || b != 2 {
		t.Fatalf("queries %d in %s and %d in %s, want 1 and 2", a, testNamespace, b, otherNamespace)
	}
}

// openPlaneWithPods opens a plane with a quiet log and attaches n Pods of testNamespace. It returns the plane, the
// desired list and the time the first Reconcile took to attach the Pods.
func openPlaneWithPods(tb testing.TB, n int) (*Plane, []DesiredPod, time.Duration) {
	tb.Helper()
	tree := newCgroupTree(tb)
	spec, err := LoadSpec()
	if err != nil {
		tb.Fatal(err)
	}
	var p *Plane
	asLoader(tb, func() { p, err = OpenPlane(spec, tree.root, logr.Discard()) })
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = p.Close() })
	if p.loadErr != nil {
		tb.Fatalf("the kernel refused the programs: %s", verifierLog(p.loadErr))
	}
	var desired []DesiredPod
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		tree.createPod(tb, uid)
		desired = append(desired, DesiredPod{UID: uid, Namespace: testNamespace, Required: true})
	}
	start := time.Now()
	reconcile(tb, p, desired, start)
	elapsed := time.Since(start)
	if len(p.attached) != n {
		tb.Fatalf("%d Pods attached, want %d", len(p.attached), n)
	}
	return p, desired, elapsed
}

// mapMemory returns a map's kernel ID and the memory the kernel charges for it (memlock in the map's fdinfo).
func mapMemory(t *testing.T, m *ebpf.Map) (ebpf.MapID, uint64) {
	t.Helper()
	info, err := m.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, hasID := info.ID()
	bytes, hasMemlock := info.Memlock()
	if !hasID || !hasMemlock {
		t.Fatalf("the kernel reports no ID or no memlock for map %s", info.Name)
	}
	return id, bytes
}

// One Pod's own kernel memory is its MapTraffic and MapDNS arrays, its read-only data and its copy of the two
// programs; all Pods share the SharedMaps. The arrays hold every cell once per possible CPU, plus a header of less
// than a page, so the memory of a Pod grows with the possible CPUs and nothing else (contract.go). The test logs the
// measured memory and the attach time, which docs/evidence/measurement-plane records.
func TestPlaneMemoryPerPod(t *testing.T) {
	requirePrivileged(t)
	const pods = 100
	const podBytesPerCPU = TrafficCells*16 + PodDNSCells*8 // a Counter is 16 bytes, a DNS cell 8
	p, desired, elapsed := openPlaneWithPods(t, pods)
	cpus := possibleCPUs(t)
	first, second := p.attached[desired[0].UID].coll, p.attached[desired[1].UID].coll

	var shared uint64
	for _, name := range SharedMaps {
		id, bytes := mapMemory(t, p.maps[name])
		for _, coll := range []*ebpf.Collection{first, second} {
			if got, _ := mapMemory(t, coll.Maps[name]); got != id {
				t.Errorf("a Pod's map %s is map %d, want the shared map %d", name, got, id)
			}
		}
		shared += bytes
	}

	var own, perCPU uint64
	for name, m := range first.Maps {
		if slices.Contains(SharedMaps, name) {
			continue
		}
		id, bytes := mapMemory(t, m)
		if other, _ := mapMemory(t, second.Maps[name]); other == id {
			t.Errorf("two Pods share map %s (ID %d)", name, id)
		}
		own += bytes
		if m.Type() != ebpf.PerCPUArray {
			continue
		}
		cells := uint64(m.MaxEntries()) * uint64(m.ValueSize())
		perCPU += cells
		if want := cells * uint64(cpus); bytes < want || bytes >= want+uint64(os.Getpagesize()) {
			t.Errorf("map %s takes %d bytes, want %d for its cells on %d CPUs plus less than a page", name, bytes,
				want, cpus)
		}
	}
	if perCPU != podBytesPerCPU {
		t.Errorf("a Pod's arrays hold %d bytes per possible CPU, want %d", perCPU, podBytesPerCPU)
	}
	for name, prog := range first.Programs {
		info, err := prog.Info()
		if err != nil {
			t.Fatal(err)
		}
		bytes, ok := info.Memlock()
		if !ok {
			t.Fatalf("the kernel reports no memlock for program %s", name)
		}
		own += bytes
	}
	t.Logf("%d possible CPUs: one Pod takes %d bytes (%d per possible CPU, %d that do not grow with the CPUs); the "+
		"shared maps take %d bytes; Reconcile attached %d Pods in %v (%v per Pod)", cpus, own, perCPU,
		own-perCPU*uint64(cpus), shared, pods, elapsed, elapsed/pods)
}

// BenchmarkPlaneTick measures the loader's work of one second for benchPods attached Pods: one Reconcile, which
// verifies every attachment, and one Read. The ns/pod metric is the cost of one Pod.
func BenchmarkPlaneTick(b *testing.B) {
	requirePrivileged(b)
	const benchPods = 100
	p, desired, _ := openPlaneWithPods(b, benchPods)
	now := time.Now()
	b.ResetTimer()
	asLoader(b, func() {
		for i := 0; i < b.N; i++ {
			p.Reconcile(desired, now)
			p.Read(now)
		}
	})
	b.StopTimer()
	if len(p.attached) != benchPods {
		b.Fatalf("%d Pods attached after the benchmark, want %d", len(p.attached), benchPods)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/benchPods, "ns/pod")
}
