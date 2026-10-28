package measurement

import (
	"testing"
)

// Every label combination has its own cell, and every cell belongs to one combination: the cell functions number each
// array from 0 to its length without a gap or an overlap. The kernel tests prove that bpf/measure.c numbers the cells
// the same way.
func TestCellsNumberEachArrayExactly(t *testing.T) {
	check := func(name string, length int, cells []int) {
		t.Helper()
		seen := make([]bool, length)
		for _, c := range cells {
			if c < 0 || c >= length {
				t.Fatalf("%s: cell %d outside 0..%d", name, c, length-1)
			}
			if seen[c] {
				t.Fatalf("%s: cell %d used twice", name, c)
			}
			seen[c] = true
		}
		if len(cells) != length {
			t.Fatalf("%s: %d cells numbered, want %d", name, len(cells), length)
		}
	}

	var traffic []int
	for d := range NumDirections {
		for p := range NumPaths {
			for k := range NumProtocols {
				traffic = append(traffic, trafficCell(d, p, k))
			}
		}
	}
	check("cmtc_traffic", TrafficCells, traffic)

	var dns, node []int
	for tr := range NumTransports {
		for l := range NumLocalities {
			dns = append(dns, queryCell(tr, l))
			for r := range NumRCodes {
				dns = append(dns, answerCell(tr, l, r))
			}
			for b := range NumBounds + 1 {
				node = append(node, latencyCountCell(tr, l, b))
			}
			node = append(node, latencySumCell(tr, l))
		}
		node = append(node, unmatchedCell(tr), replacedCell(tr))
	}
	check("cmtc_dns", PodDNSCells, dns)
	check("cmtc_node", NodeCells, node)

	// The lengths are the numbers bpf/measure.c uses (N_TRAFFIC, N_POD_DNS, N_NODE).
	if TrafficCells != 24 || PodDNSCells != 48 || NodeCells != 94 {
		t.Fatalf("cells %d, %d, %d; bpf/measure.c has 24, 48, 94", TrafficCells, PodDNSCells, NodeCells)
	}
}

// Each cell lands in the counter of its labels: a distinct value in every cell shows any cell read into the wrong
// place.
func TestCountersFromCells(t *testing.T) {
	var traffic [TrafficCells]Counter
	for i := range traffic {
		traffic[i] = Counter{Packets: uint64(1000 + i), Bytes: uint64(2000 + i)}
	}
	var dns [PodDNSCells]uint64
	for i := range dns {
		dns[i] = uint64(3000 + i)
	}
	c := PodCountersFromCells(traffic, dns)
	// Spot values, computed by hand from the row-major order of contract.go.
	if got := c.Traffic[1][1][2]; got != (Counter{Packets: 1000 + 20, Bytes: 2000 + 20}) { // ingress, pod_network, dns
		t.Fatalf("ingress pod_network dns = %+v, want cell 20", got)
	}
	if got := c.DNSQueries[1][2]; got != 3000+5 { // tcp, off_node
		t.Fatalf("tcp off_node queries = %d, want cell 5", got)
	}
	if got := c.DNSAnswers[0][1][3]; got != 3000+6+7+3 { // udp, same_node, nxdomain
		t.Fatalf("udp same_node nxdomain answers = %d, want cell 16", got)
	}

	var cells [NodeCells]uint64
	for i := range cells {
		cells[i] = uint64(4000 + i)
	}
	n := NodeCountersFromCells(cells)
	if got := n.LatencyCount[1][0][13]; got != 4000+3*14+13 { // tcp, in_pod, above the last bound
		t.Fatalf("tcp in_pod overflow bucket = %d, want cell 55", got)
	}
	if got := n.LatencySumNs[0][2]; got != 4000+84+2 { // udp, off_node
		t.Fatalf("udp off_node latency sum = %d, want cell 86", got)
	}
	if n.Unmatched != [NumTransports]uint64{4000 + 90, 4000 + 91} || n.Replaced != [NumTransports]uint64{4000 + 92, 4000 + 93} {
		t.Fatalf("unmatched %v replaced %v, want cells 90-93", n.Unmatched, n.Replaced)
	}
}

func TestPodCountersDelta(t *testing.T) {
	var a, b PodCounters
	a.Traffic[0][1][0] = Counter{Packets: 5, Bytes: 500}
	a.DNSQueries[0][2] = 3
	a.DNSAnswers[1][0][6] = 2
	b = a
	b.Traffic[0][1][0].Packets += 2
	b.DNSAnswers[1][0][6]++

	d, ok := b.Delta(a)
	if !ok {
		t.Fatal("Delta refused counters that only grew")
	}
	var want PodCounters
	want.Traffic[0][1][0].Packets = 2
	want.DNSAnswers[1][0][6] = 1
	if d != want {
		t.Fatalf("delta %+v, want %+v", d, want)
	}
	var sum PodCounters
	sum.Add(a)
	sum.Add(d)
	if sum != b {
		t.Fatalf("a + delta = %+v, want %+v", sum, b)
	}
	if _, ok := a.Delta(b); ok {
		t.Fatal("Delta accepted a counter that decreased")
	}
}

func TestDNSDurationBoundsNs(t *testing.T) {
	ns := DNSDurationBoundsNs()
	if ns[0] != 500_000 || ns[NumBounds-1] != 5_000_000_000 {
		t.Fatalf("bounds %v, want 500000 ns first and 5 s last", ns)
	}
	for i := 1; i < NumBounds; i++ {
		if ns[i] <= ns[i-1] {
			t.Fatalf("bounds %v do not increase at %d", ns, i)
		}
	}
}
