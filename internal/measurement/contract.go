// Package measurement is the CMTC eBPF measurement plane (ADR-005): observe-only counters from cgroup_skb programs
// on the cgroups of enrolled Pods. Two containers of the node DaemonSet share the work:
//   - the loader (cmd/cmtc-measure) holds CAP_BPF and CAP_NET_ADMIN, no API token and no listener. It loads and
//     attaches the programs and reads their maps;
//   - the node agent (cmd/cmtc --mode=node) holds the API token and no capability. It chooses the Pods and exports
//     the metrics.
//
// They exchange two JSON files (exchange.go). The programs never decide a verdict: they return the pass value on
// every path and write only their own maps.
package measurement

import (
	"math"
	"time"
)

// Metric names. This file is the only definition of the measurement plane's metric contract until
// observability/v2/metrics/ lists these names (issue #37). Every family carries the cluster and node labels.
const (
	// MetricReady is 1 when the loader's snapshot is fresh, both programs are loaded and every required enrolled Pod
	// of the node (DesiredPod.Required) is attached. It is always exported. It never means that traffic is protected.
	MetricReady = "cmtc_measurement_ready"
	// MetricHookAvailable is 1 when the loader has the hook (label hook): the kernel accepted the program, or the
	// loader can read the source.
	MetricHookAvailable = "cmtc_measurement_hook_available"
	// MetricWorkloads counts the enrolled Pods of the node by measurement state (label state).
	MetricWorkloads = "cmtc_measurement_workloads"
	// MetricPackets and MetricBytes count the packets of the enrolled Pods' sockets at the cgroup socket layer, by
	// namespace, direction, path and protocol class.
	MetricPackets = "cmtc_measurement_packets_total"
	MetricBytes   = "cmtc_measurement_bytes_total"
	// MetricDNSQueries counts client DNS queries by namespace, transport and the locality of the server.
	MetricDNSQueries = "cmtc_measurement_dns_queries_total"
	// MetricDNSAnswers counts client DNS answers by namespace, transport, locality and response code.
	MetricDNSAnswers = "cmtc_measurement_dns_answers_total"
	// MetricDNSDuration is the histogram of the time from a query to its answer, by transport and locality.
	MetricDNSDuration = "cmtc_measurement_dns_answer_duration_seconds"
	// MetricDNSUnmatched counts answers with no waiting query, by transport.
	MetricDNSUnmatched = "cmtc_measurement_dns_unmatched_answers_total"
	// MetricDNSReplaced counts queries sent again with an ID that was still waiting on the same socket, by transport.
	MetricDNSReplaced = "cmtc_measurement_dns_pending_replaced_total"
	// MetricProgramRunTime and MetricProgramRuns are the kernel's run statistics of the programs, by direction. They
	// exist only while the node owner sets kernel.bpf_stats_enabled=1.
	MetricProgramRunTime = "cmtc_measurement_program_run_seconds_total"
	MetricProgramRuns    = "cmtc_measurement_program_runs_total"
)

// Dimensions of the counters. bpf/measure.c uses the same numbers; CheckSpec refuses an object whose maps differ.
const (
	NumDirections = 2
	NumPaths      = 2
	NumProtocols  = 6
	NumTransports = 2
	NumLocalities = 3
	NumRCodes     = 7
	NumBounds     = 13
	// MaxPending bounds the DNS queries that wait for an answer, node-wide. When the table is full, the kernel's
	// LRU evicts an old entry.
	MaxPending = 4096
	// MaxNodeAddresses bounds the Pod IP addresses of the node that the programs know (two per dual-stack Pod).
	MaxNodeAddresses = 1024
)

// The programs keep every counter in a cell of a per-CPU array (bpf/measure.c explains why). Each measured Pod has
// its own traffic and DNS arrays and its own copy of the programs: TrafficCells*16 + PodDNSCells*8 = 768 bytes of
// kernel memory per possible CPU, plus about 21 KiB that does not grow with the CPUs (the programs, the read-only
// data, the map headers). With 8 possible CPUs one Pod took 27,968 bytes (fdinfo memlock, Linux 6.8,
// TestPlaneMemoryPerPod). The node array and the two hash maps are created once per node (450 KiB).
const (
	// TrafficCells is the length of cmtc_traffic: a Counter for each direction, path and protocol.
	TrafficCells = NumDirections * NumPaths * NumProtocols
	// PodDNSCells is the length of cmtc_dns: the queries by transport and locality, then the answers by transport,
	// locality and response code.
	PodDNSCells = NumTransports*NumLocalities + NumTransports*NumLocalities*NumRCodes
	// NodeCells is the length of cmtc_node: the latency histogram buckets by transport and locality, then the
	// latency sums by transport and locality, then the unmatched answers and the replaced queries by transport.
	NodeCells = NumTransports*NumLocalities*(NumBounds+1) + NumTransports*NumLocalities + 2*NumTransports
)

// Label values, in the index order of the BPF arrays in bpf/measure.c.
var (
	Directions = [NumDirections]string{"egress", "ingress"}
	// Paths: loopback is the Pod's lo device, which also carries every packet to the Pod's own addresses. Every TCP
	// connection that ztunnel captures stays on it: the in-Pod rules redirect outbound TCP to ztunnel on 15001 and
	// inbound TCP to 15006, and route the replies back to ztunnel through lo. pod_network is any other device: the
	// packet leaves or enters the Pod.
	Paths = [NumPaths]string{"loopback", "pod_network"}
	// Protocols: dns is TCP or UDP with peer port 53 (or 15053, ztunnel's DNS proxy, on loopback); tcp and udp are
	// the rest of TCP and UDP. fragment is an IP fragment, which the socket layer rarely sees (egress runs before
	// fragmentation, ingress after reassembly).
	Protocols = [NumProtocols]string{"tcp", "udp", "dns", "icmp", "fragment", "other"}
	// Transports of a DNS message.
	Transports = [NumTransports]string{"udp", "tcp"}
	// Localities of the DNS server: in_pod is an in-Pod proxy on the loopback path; same_node is an IP address of
	// a Pod on this node (a hostNetwork Pod gives the node's own address); off_node is anything else.
	Localities = [NumLocalities]string{"in_pod", "same_node", "off_node"}
	// RCodes are the DNS response codes of RFC 1035 and RFC 2136; other is any other code.
	RCodes = [NumRCodes]string{"noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "other"}
)

// Hooks reported by MetricHookAvailable.
const (
	HookEgress  = "cgroup_skb_egress"
	HookIngress = "cgroup_skb_ingress"
	// HookNodeAddresses is the list of the node's Pod addresses, which same_node needs.
	HookNodeAddresses = "node_addresses"
	// HookProgramStats is the kernel's run statistics (kernel.bpf_stats_enabled).
	HookProgramStats = "program_stats"
)

// Hooks lists every hook the loader reports, in export order.
var Hooks = []string{HookEgress, HookIngress, HookNodeAddresses, HookProgramStats}

// Measurement states of a Pod, reported by MetricWorkloads.
const (
	// StateAttached: both programs are attached to the Pod's cgroup.
	StateAttached = "attached"
	// StateWaiting: the Pod's cgroup does not exist yet (the Pod is starting).
	StateWaiting = "waiting"
	// StateUnavailable: the Pod cannot be measured; the loader logs the reason.
	StateUnavailable = "unavailable"
)

// States lists every state, in export order.
var States = []string{StateAttached, StateWaiting, StateUnavailable}

// DNSDurationBuckets are the upper bounds, in seconds, of the DNS answer histogram. The loader writes them into the
// program (cmtc_bounds_ns), so this list is their only definition.
var DNSDurationBuckets = [NumBounds]float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

const (
	// EnrollmentLabel is the namespace label that the Cilium fork admits on (pkg/ztunnel/admission/cell.go): only
	// the value "true" enrolls.
	EnrollmentLabel = "io.cilium/mtls-enabled"
	// SnapshotMaxAge is the age, on the monotonic clock, after which the agent stops exporting a snapshot.
	SnapshotMaxAge = 3 * time.Second
	// AttachGrace is how long a required enrolled Pod may stay unattached before the plane reports not ready.
	AttachGrace = 10 * time.Second
	// NamespaceRetention keeps a namespace's counters after its last Pod left the node, so that rate() over
	// windows up to this length stays continuous.
	NamespaceRetention = 10 * time.Minute
)

// Counter mirrors struct cmtc_counter.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// PodCounters are the counters of one measured Pod, read from its cmtc_traffic and cmtc_dns arrays, or the sums of
// the Pods of one namespace.
type PodCounters struct {
	Traffic    [NumDirections][NumPaths][NumProtocols]Counter  `json:"traffic"`
	DNSQueries [NumTransports][NumLocalities]uint64            `json:"dnsQueries"`
	DNSAnswers [NumTransports][NumLocalities][NumRCodes]uint64 `json:"dnsAnswers"`
}

// NodeCounters are the node-wide DNS latency and matching counters, read from cmtc_node.
type NodeCounters struct {
	LatencyCount [NumTransports][NumLocalities][NumBounds + 1]uint64 `json:"latencyCount"`
	LatencySumNs [NumTransports][NumLocalities]uint64                `json:"latencySumNs"`
	Unmatched    [NumTransports]uint64                               `json:"unmatchedAnswers"`
	Replaced     [NumTransports]uint64                               `json:"pendingReplaced"`
}

// Cell numbers of the counter arrays: the same functions as traffic_cell, query_cell, answer_cell,
// latency_count_cell, latency_sum_cell, unmatched_cell and replaced_cell in bpf/measure.c.
func trafficCell(direction, path, protocol int) int {
	return (direction*NumPaths+path)*NumProtocols + protocol
}

func queryCell(transport, locality int) int { return transport*NumLocalities + locality }

func answerCell(transport, locality, rcode int) int {
	return NumTransports*NumLocalities + (transport*NumLocalities+locality)*NumRCodes + rcode
}

func latencyCountCell(transport, locality, bucket int) int {
	return (transport*NumLocalities+locality)*(NumBounds+1) + bucket
}

func latencySumCell(transport, locality int) int {
	return NumTransports*NumLocalities*(NumBounds+1) + transport*NumLocalities + locality
}

func unmatchedCell(transport int) int { return NumTransports*NumLocalities*(NumBounds+2) + transport }

func replacedCell(transport int) int {
	return NumTransports*NumLocalities*(NumBounds+2) + NumTransports + transport
}

// PodCountersFromCells arranges the cells of a Pod's two arrays, each summed over the CPUs, by label value.
func PodCountersFromCells(traffic [TrafficCells]Counter, dns [PodDNSCells]uint64) PodCounters {
	var c PodCounters
	for d := range NumDirections {
		for p := range NumPaths {
			for k := range NumProtocols {
				c.Traffic[d][p][k] = traffic[trafficCell(d, p, k)]
			}
		}
	}
	for t := range NumTransports {
		for l := range NumLocalities {
			c.DNSQueries[t][l] = dns[queryCell(t, l)]
			for r := range NumRCodes {
				c.DNSAnswers[t][l][r] = dns[answerCell(t, l, r)]
			}
		}
	}
	return c
}

// NodeCountersFromCells arranges the cells of cmtc_node, each summed over the CPUs, by label value.
func NodeCountersFromCells(cells [NodeCells]uint64) NodeCounters {
	var n NodeCounters
	for t := range NumTransports {
		for l := range NumLocalities {
			for b := range NumBounds + 1 {
				n.LatencyCount[t][l][b] = cells[latencyCountCell(t, l, b)]
			}
			n.LatencySumNs[t][l] = cells[latencySumCell(t, l)]
		}
		n.Unmatched[t] = cells[unmatchedCell(t)]
		n.Replaced[t] = cells[replacedCell(t)]
	}
	return n
}

// Add adds b to a.
func (a *PodCounters) Add(b PodCounters) {
	for d := range a.Traffic {
		for p := range a.Traffic[d] {
			for k := range a.Traffic[d][p] {
				a.Traffic[d][p][k].Packets += b.Traffic[d][p][k].Packets
				a.Traffic[d][p][k].Bytes += b.Traffic[d][p][k].Bytes
			}
		}
	}
	for t := range a.DNSQueries {
		for l := range a.DNSQueries[t] {
			a.DNSQueries[t][l] += b.DNSQueries[t][l]
			for r := range a.DNSAnswers[t][l] {
				a.DNSAnswers[t][l][r] += b.DNSAnswers[t][l][r]
			}
		}
	}
}

// Delta returns a minus prev. It reports false when a counter decreased: the arrays of one attachment only grow, so
// a decrease means a wrong reading.
func (a PodCounters) Delta(prev PodCounters) (PodCounters, bool) {
	var d PodCounters
	ok := true
	sub := func(cur, old uint64) uint64 {
		if cur < old {
			ok = false
			return 0
		}
		return cur - old
	}
	for i := range a.Traffic {
		for p := range a.Traffic[i] {
			for k := range a.Traffic[i][p] {
				d.Traffic[i][p][k].Packets = sub(a.Traffic[i][p][k].Packets, prev.Traffic[i][p][k].Packets)
				d.Traffic[i][p][k].Bytes = sub(a.Traffic[i][p][k].Bytes, prev.Traffic[i][p][k].Bytes)
			}
		}
	}
	for t := range a.DNSQueries {
		for l := range a.DNSQueries[t] {
			d.DNSQueries[t][l] = sub(a.DNSQueries[t][l], prev.DNSQueries[t][l])
			for r := range a.DNSAnswers[t][l] {
				d.DNSAnswers[t][l][r] = sub(a.DNSAnswers[t][l][r], prev.DNSAnswers[t][l][r])
			}
		}
	}
	if !ok {
		return PodCounters{}, false
	}
	return d, true
}

// DNSDurationBoundsNs returns the histogram bounds in nanoseconds, the unit of bpf_ktime_get_ns, for the program's
// cmtc_bounds_ns variable.
func DNSDurationBoundsNs() [NumBounds]uint64 {
	var ns [NumBounds]uint64
	for i, s := range DNSDurationBuckets {
		ns[i] = uint64(math.Round(s * float64(time.Second)))
	}
	return ns
}
