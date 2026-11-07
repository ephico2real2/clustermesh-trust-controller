//go:build linux && cmtc_bpf_privileged

package measurement

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests load the embedded object into the running kernel and run its programs with BPF_PROG_TEST_RUN. They
// need root in a disposable private container (scripts/measurement/test-kernel.sh) and create only a dummy device
// in that container's network namespace. They prove the verifier accepts the programs, the pass verdict, that no
// context field or packet byte changes, and the exact change of every counter. They are not lab qualification.

func requirePrivileged(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CMTC_BPF_TEST_PRIVATE_NETNS") != "1" {
		t.Fatal("requires root in a disposable private container; set CMTC_BPF_TEST_PRIVATE_NETNS=1 only there")
	}
}

// skbContext mirrors struct __sk_buff of include/uapi/linux/bpf.h (v6.8), which BPF_PROG_TEST_RUN takes as context.
type skbContext struct {
	Len, PktType, Mark, QueueMapping, Protocol, VlanPresent, VlanTCI, VlanProto uint32
	Priority, IngressIfindex, Ifindex, TCIndex                                  uint32
	CB                                                                          [5]uint32
	Hash, TCClassID, Data, DataEnd, NapiID, Family, RemoteIP4, LocalIP4         uint32
	RemoteIP6, LocalIP6                                                         [4]uint32
	RemotePort, LocalPort, DataMeta                                             uint32
	FlowKeys, Tstamp                                                            uint64
	WireLen, GSOSegs                                                            uint32
	SK                                                                          uint64
	GSOSize                                                                     uint32
	TstampType                                                                  uint8
	_                                                                           [3]uint8
	HWTstamp                                                                    uint64
}

// loadTestCollection loads both programs with maps of their own, as the plane loads them for one Pod.
func loadTestCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	spec, err := LoadSpec()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Variables[VariableBounds].Set(DNSDurationBoundsNs()); err != nil {
		t.Fatal(err)
	}
	var coll *ebpf.Collection
	asLoader(t, func() { coll, err = ebpf.NewCollection(spec) })
	if err != nil {
		t.Fatalf("the kernel refused the measurement object: %s", verifierLog(err))
	}
	t.Cleanup(coll.Close)
	return coll
}

// verifierLog returns err with the verifier's whole log, when the verifier refused a program.
func verifierLog(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Sprintf("%v\n%+v", err, ve)
	}
	return err.Error()
}

// asLoader runs f on a thread whose effective capabilities are the loader's (LoaderCapabilities), so that the
// verifier checks every program that f loads as it checks them for cmd/cmtc-measure. Without CAP_PERFMON and
// CAP_SYS_ADMIN, the verifier keeps its Spectre v1 and v4 hardening and also checks the paths that only speculative
// execution can take (kernel/bpf/verifier.c, bpf_check and sanitize_speculative_path); a test run as root would skip
// both. Capabilities belong to a thread, so the thread gets its own back before Go may run anything else on it.
func asLoader(t testing.TB, f func()) {
	t.Helper()
	runtime.LockOSThread()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var own [2]unix.CapUserData
	if err := unix.Capget(&header, &own[0]); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	loader := own
	caps := LoaderCapabilities
	loader[0].Effective, loader[1].Effective = uint32(caps), uint32(caps>>32)
	if err := unix.Capset(&header, &loader[0]); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("set the loader's capabilities: %v", err)
	}
	f()
	if err := unix.Capset(&header, &own[0]); err != nil {
		t.Fatalf("restore the thread's capabilities: %v", err) // the thread stays locked; Go discards it
	}
	runtime.UnlockOSThread()
}

// dummyDevice creates a device other than lo, for packets on the pod_network path. BPF_PROG_TEST_RUN runs a
// cgroup_skb program on lo unless the context names another device (net/bpf/test_run.c, bpf_prog_test_run_skb).
func dummyDevice(t *testing.T) uint32 {
	t.Helper()
	d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cmtcm0"}}
	if err := netlink.LinkAdd(d); err != nil {
		t.Fatalf("create the dummy device: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(d) })
	l, err := netlink.LinkByName("cmtcm0")
	if err != nil {
		t.Fatal(err)
	}
	return uint32(l.Attrs().Index)
}

// readPod and readNode read the collection's counters as the plane reads them.
func readPod(t *testing.T, coll *ebpf.Collection) PodCounters {
	t.Helper()
	c, err := readPodCounters(coll.Maps[MapTraffic], coll.Maps[MapDNS], possibleCPUs(t))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readNode(t *testing.T, coll *ebpf.Collection) NodeCounters {
	t.Helper()
	n, err := readNodeCounters(coll.Maps[MapNode], possibleCPUs(t))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func possibleCPUs(t *testing.T) int {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	return cpus
}

// Packet builders. Checksums stay zero: the programs never read them.

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func ipv4(src, dst string, proto byte, fragment uint16, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[6:], fragment)
	h[8], h[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(h, payload...)
}

func ipv6(src, dst string, next byte, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	h[6], h[7] = next, 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(h, payload...)
}

// extension returns an IPv6 extension header of 8 bytes (AH: 12 bytes) followed by payload.
func extension(kind, next byte, payload []byte) []byte {
	if kind == 51 {
		return append([]byte{next, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, payload...) // (1+2)*4 = 12 bytes
	}
	return append([]byte{next, 0, 0, 0, 0, 0, 0, 0}, payload...)
}

func udp(sport, dport uint16, payload []byte) []byte {
	h := append(be16(sport), be16(dport)...)
	h = append(h, be16(uint16(8+len(payload)))...)
	return append(append(h, 0, 0), payload...)
}

// tcp returns a TCP header of 4*words bytes (options zero) with the PSH and ACK flags, followed by payload.
func tcp(sport, dport uint16, words int, payload []byte) []byte {
	h := make([]byte, 4*words)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = byte(words << 4)
	h[13] = 0x18
	return append(h, payload...)
}

// dnsMessage returns a DNS header and one question ("a." A IN).
func dnsMessage(id uint16, answer bool, opcode, rcode byte, questions uint16) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:], id)
	m[2] = opcode << 3
	if answer {
		m[2] |= 0x80
	}
	m[3] = rcode
	binary.BigEndian.PutUint16(m[4:], questions)
	return append(m, 1, 'a', 0, 0, 1, 0, 1)
}

func tcpDNS(m []byte) []byte { return append(be16(uint16(len(m))), m...) }

type runCase struct {
	name      string
	program   string
	packet    []byte
	ipv6      bool
	loopback  bool
	gsoSegs   uint32
	nodeAddrs []string
	// pod and node are the expected changes of the counters.
	pod  func(*PodCounters)
	node func(*NodeCounters)
}

func traffic(dir, path, proto int, packets uint64, bytes int) func(*PodCounters) {
	return func(c *PodCounters) {
		c.Traffic[dir][path][proto].Packets += packets
		c.Traffic[dir][path][proto].Bytes += uint64(bytes)
	}
}

func both(fs ...func(*PodCounters)) func(*PodCounters) {
	return func(c *PodCounters) {
		for _, f := range fs {
			f(c)
		}
	}
}

// Index names of the arrays, in the order of contract.go.
const (
	egress, ingress    = 0, 1
	loopback, network  = 0, 1
	pTCP, pUDP, pDNS   = 0, 1, 2
	pICMP, pFrag, pOth = 3, 4, 5
	tUDP, tTCP         = 0, 1
	inPod, sameNode    = 0, 1
	offNode            = 2
)

func query(t, l int) func(*PodCounters) {
	return func(c *PodCounters) { c.DNSQueries[t][l]++ }
}

func answer(t, l, r int) func(*PodCounters) {
	return func(c *PodCounters) { c.DNSAnswers[t][l][r]++ }
}

func unmatched(t int) func(*NodeCounters) {
	return func(n *NodeCounters) { n.Unmatched[t]++ }
}

func runCases() []runCase {
	q := dnsMessage(0x1234, false, 0, 0, 1)
	udpQuery := ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 53, q))
	answerFrom := func(rcode byte) []byte {
		return ipv4("10.0.0.53", "10.0.0.5", 17, 0, udp(53, 40000, dnsMessage(0x1234, true, 0, rcode, 1)))
	}
	cases := []runCase{
		{name: "UDP DNS query off node", program: ProgramEgress, packet: udpQuery,
			pod: both(traffic(egress, network, pDNS, 1, len(udpQuery)), query(tUDP, offNode))},
		{name: "UDP DNS query to a Pod of this node", program: ProgramEgress, packet: udpQuery,
			nodeAddrs: []string{"10.0.0.53"},
			pod:       both(traffic(egress, network, pDNS, 1, len(udpQuery)), query(tUDP, sameNode))},
		{name: "UDP DNS query to an in-Pod proxy on lo", program: ProgramEgress, loopback: true,
			packet: ipv4("127.0.0.1", "127.0.0.1", 17, 0, udp(40000, 53, q)),
			pod:    both(traffic(egress, loopback, pDNS, 1, 47), query(tUDP, inPod))},
		{name: "UDP to ztunnel's DNS port on lo is DNS", program: ProgramEgress, loopback: true,
			packet: ipv4("127.0.0.1", "127.0.0.1", 17, 0, udp(40000, 15053, q)),
			pod:    both(traffic(egress, loopback, pDNS, 1, 47), query(tUDP, inPod))},
		{name: "UDP to port 15053 off the Pod is not DNS", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 15053, q)),
			pod:    traffic(egress, network, pUDP, 1, 47)},
		{name: "TCP DNS query", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 6, 0, tcp(40000, 53, 5, tcpDNS(q))),
			pod:    both(traffic(egress, network, pDNS, 1, 20+20+2+len(q)), query(tTCP, offNode))},
		{name: "TCP DNS query after TCP options", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 6, 0, tcp(40000, 53, 8, tcpDNS(q))),
			pod:    both(traffic(egress, network, pDNS, 1, 20+32+2+len(q)), query(tTCP, offNode))},
		{name: "TCP DNS segment without payload", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 6, 0, tcp(40000, 53, 5, nil)),
			pod:    traffic(egress, network, pDNS, 1, 40)},
		{name: "TCP DNS answer", program: ProgramIngress,
			packet: ipv4("10.0.0.53", "10.0.0.5", 6, 0, tcp(53, 40000, 5, tcpDNS(dnsMessage(7, true, 0, 0, 1)))),
			pod:    both(traffic(ingress, network, pDNS, 1, 20+20+2+19), answer(tTCP, offNode, 0)),
			node:   unmatched(tTCP)},
		{name: "DNS NOTIFY is not a query", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 53, dnsMessage(1, false, 4, 0, 1))),
			pod:    traffic(egress, network, pDNS, 1, 47)},
		{name: "DNS query with two questions is not counted", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 53, dnsMessage(1, false, 0, 0, 2))),
			pod:    traffic(egress, network, pDNS, 1, 47)},
		{name: "an answer the Pod sends is not a query", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.9", 17, 0, udp(1053, 53, dnsMessage(1, true, 0, 0, 1))),
			pod:    traffic(egress, network, pDNS, 1, 47)},
		{name: "a query the Pod receives is not an answer", program: ProgramIngress,
			packet: ipv4("10.0.0.9", "10.0.0.5", 17, 0, udp(53, 1053, dnsMessage(1, false, 0, 0, 1))),
			pod:    traffic(ingress, network, pDNS, 1, 47)},
		{name: "TCP off the Pod", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.80", 6, 0, tcp(40000, 8080, 5, []byte("GET /"))),
			pod:    traffic(egress, network, pTCP, 1, 45)},
		{name: "TCP on lo", program: ProgramEgress, loopback: true,
			packet: ipv4("127.0.0.1", "127.0.0.1", 6, 0, tcp(40000, 15001, 5, nil)),
			pod:    traffic(egress, loopback, pTCP, 1, 40)},
		{name: "GSO packet counts its segments", program: ProgramEgress, gsoSegs: 5,
			packet: ipv4("10.0.0.5", "10.0.0.80", 6, 0, tcp(40000, 8080, 5, make([]byte, 100))),
			pod:    traffic(egress, network, pTCP, 5, 140)},
		{name: "UDP", program: ProgramIngress,
			packet: ipv4("10.0.0.80", "10.0.0.5", 17, 0, udp(9999, 40000, []byte("x"))),
			pod:    traffic(ingress, network, pUDP, 1, 29)},
		{name: "ICMP", program: ProgramIngress,
			packet: ipv4("10.0.0.80", "10.0.0.5", 1, 0, []byte{0, 0, 0, 0, 0, 0, 0, 0}),
			pod:    traffic(ingress, network, pICMP, 1, 28)},
		{name: "first IPv4 fragment", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 17, 0x2000, udp(40000, 53, q)),
			pod:    traffic(egress, network, pFrag, 1, 47)},
		{name: "later IPv4 fragment", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.53", 17, 0x0010, q),
			pod:    traffic(egress, network, pFrag, 1, 39)},
		{name: "other IP protocol", program: ProgramEgress,
			packet: ipv4("10.0.0.5", "10.0.0.80", 47, 0, []byte{0, 0, 0, 0}),
			pod:    traffic(egress, network, pOth, 1, 24)},
		{name: "truncated IPv4 header", program: ProgramEgress, packet: []byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17},
			pod: traffic(egress, network, pOth, 1, 10)},
		{name: "IPv4 header length below 20", program: ProgramEgress,
			packet: func() []byte { p := ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 53, q)); p[0] = 0x44; return p }(),
			pod:    traffic(egress, network, pOth, 1, 47)},
	}
	v6q := ipv6("fd00::5", "fd00::53", 17, udp(40000, 53, q))
	cases = append(cases,
		runCase{name: "IPv6 UDP DNS query", program: ProgramEgress, ipv6: true, packet: v6q,
			pod: both(traffic(egress, network, pDNS, 1, len(v6q)), query(tUDP, offNode))},
		runCase{name: "IPv6 UDP DNS query to a Pod of this node", program: ProgramEgress, ipv6: true, packet: v6q,
			nodeAddrs: []string{"fd00::53"},
			pod:       both(traffic(egress, network, pDNS, 1, len(v6q)), query(tUDP, sameNode))},
		runCase{name: "IPv6 UDP DNS answer", program: ProgramIngress, ipv6: true,
			packet: ipv6("fd00::53", "fd00::5", 17, udp(53, 40000, dnsMessage(9, true, 0, 2, 1))),
			pod:    both(traffic(ingress, network, pDNS, 1, 40+8+19), answer(tUDP, offNode, 2)),
			node:   unmatched(tUDP)},
		runCase{name: "IPv6 extension headers before UDP DNS", program: ProgramEgress, ipv6: true,
			packet: ipv6("fd00::5", "fd00::53", 0, extension(0, 60, extension(60, 51, extension(51, 17,
				udp(40000, 53, q))))),
			pod: both(traffic(egress, network, pDNS, 1, 40+8+8+12+8+19), query(tUDP, offNode))},
		runCase{name: "IPv6 fragment", program: ProgramEgress, ipv6: true,
			packet: ipv6("fd00::5", "fd00::53", 44, extension(44, 17, udp(40000, 53, q))),
			pod:    traffic(egress, network, pFrag, 1, 40+8+8+19)},
		runCase{name: "IPv6 with five extension headers", program: ProgramEgress, ipv6: true,
			packet: ipv6("fd00::5", "fd00::53", 0, extension(0, 60, extension(60, 60, extension(60, 60,
				extension(60, 60, extension(60, 17, udp(40000, 53, q))))))),
			pod: traffic(egress, network, pOth, 1, 40+5*8+8+19)},
		runCase{name: "ICMPv6", program: ProgramIngress, ipv6: true,
			packet: ipv6("fd00::53", "fd00::5", 58, []byte{128, 0, 0, 0, 0, 0, 0, 0}),
			pod:    traffic(ingress, network, pICMP, 1, 48)},
	)
	rcodes := []byte{0, 1, 2, 3, 4, 5, 9}
	for i, rcode := range rcodes {
		p := answerFrom(rcode)
		cases = append(cases, runCase{name: fmt.Sprintf("UDP DNS answer rcode %d", rcode), program: ProgramIngress,
			packet: p, pod: both(traffic(ingress, network, pDNS, 1, len(p)), answer(tUDP, offNode, i)),
			node: unmatched(tUDP)})
	}
	return cases
}

func TestProgramsPassAndCountEveryClass(t *testing.T) {
	requirePrivileged(t)
	ifindex := dummyDevice(t)
	for _, c := range runCases() {
		t.Run(c.name, func(t *testing.T) {
			coll := loadTestCollection(t)
			for _, a := range c.nodeAddrs {
				if err := coll.Maps[MapNodeAddresses].Put(nodeAddress(netip.MustParseAddr(a).As16()), uint32(1)); err != nil {
					t.Fatal(err)
				}
			}
			ethertype := uint16(0x0800)
			if c.ipv6 {
				ethertype = 0x86dd
			}
			data := append(append(make([]byte, 12), be16(ethertype)...), c.packet...)
			in := skbContext{Mark: 0x1234, Priority: 7, CB: [5]uint32{1, 2, 3, 4, 5}, Tstamp: 1_000_000, GSOSegs: c.gsoSegs}
			if !c.loopback {
				in.Ifindex = ifindex
			}
			var out skbContext
			dataOut := make([]byte, len(data))
			ret, err := coll.Programs[c.program].Run(&ebpf.RunOptions{Data: data, DataOut: dataOut, Context: in,
				ContextOut: &out})
			if err != nil {
				t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
			}
			if ret != 1 {
				t.Fatalf("returned %d, want 1 (pass)", ret)
			}
			if out.Mark != in.Mark || out.Priority != in.Priority || out.CB != in.CB || out.Tstamp != in.Tstamp {
				t.Fatalf("context changed: mark %#x priority %d cb %v tstamp %d", out.Mark, out.Priority, out.CB, out.Tstamp)
			}
			if string(dataOut[14:]) != string(c.packet) {
				t.Fatal("packet changed")
			}
			// Every cell is compared, so a count in any other cell fails the case.
			var wantPod PodCounters
			var wantNode NodeCounters
			if c.pod != nil {
				c.pod(&wantPod)
			}
			if c.node != nil {
				c.node(&wantNode)
			}
			if got := readPod(t, coll); !reflect.DeepEqual(got, wantPod) {
				t.Fatalf("Pod counters\n got %+v\nwant %+v", got, wantPod)
			}
			if got := readNode(t, coll); !reflect.DeepEqual(got, wantNode) {
				t.Fatalf("node counters\n got %+v\nwant %+v", got, wantNode)
			}
		})
	}
}

// A query leaves a waiting entry in the pending table, keyed by the socket cookie. BPF_PROG_TEST_RUN gives every run
// a new socket, so here a later answer never matches; plane_privileged_test.go matches answers on real sockets.
func TestQueryWaitsInThePendingTable(t *testing.T) {
	requirePrivileged(t)
	ifindex := dummyDevice(t)
	coll := loadTestCollection(t)
	q := ipv4("10.0.0.5", "10.0.0.53", 17, 0, udp(40000, 53, dnsMessage(0x4242, false, 0, 0, 1)))
	data := append(append(make([]byte, 12), be16(0x0800)...), q...)
	if _, err := coll.Programs[ProgramEgress].Run(&ebpf.RunOptions{Data: data,
		Context: skbContext{Ifindex: ifindex}}); err != nil {
		t.Fatal(err)
	}
	var key pendingKey
	var sent uint64
	entries := coll.Maps[MapPending].Iterate()
	n := 0
	for entries.Next(&key, &sent) {
		n++
		if key.ID != 0x4242 || key.Transport != tUDP || key.Cookie == 0 || sent == 0 {
			t.Fatalf("pending entry %+v sent %d", key, sent)
		}
	}
	if err := entries.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d pending entries, want 1", n)
	}
}
