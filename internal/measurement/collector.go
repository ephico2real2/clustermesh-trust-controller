package measurement

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Clock dates snapshots: the boot ID and the kernel's CLOCK_MONOTONIC, which the loader and the agent read in the
// same Pod. Wall time is never compared.
type Clock struct {
	BootID    func() (string, error)
	Monotonic func() (int64, error)
}

// Collector exports the loader's snapshot as the metrics of contract.go. It always exports MetricReady. It exports
// the other families only while the snapshot is fresh, so data that is absent never shows as zero. A counter series
// appears at its first event.
type Collector struct {
	path  string
	clock Clock
	now   func() time.Time

	mu sync.Mutex
	// required holds the required Pods of the last desired list, with the time the agent first saw each required.
	required   map[string]time.Time
	desiredErr error

	ready, hook, workloads, packets, bytes, queries, answers, duration, unmatched, replaced, runTime, runs *prometheus.Desc
}

// NewCollector returns a collector for the snapshot file at path. Until the first SetDesired, the enrolled Pods are
// unknown and the plane is not ready.
func NewCollector(cluster, node, path string, clock Clock) *Collector {
	labels := prometheus.Labels{"cluster": cluster, "node": node}
	desc := func(name, help string, variable ...string) *prometheus.Desc {
		return prometheus.NewDesc(name, help, variable, labels)
	}
	traffic := []string{"namespace", "direction", "path", "protocol"}
	return &Collector{
		path: path, clock: clock, now: time.Now,
		desiredErr: errors.New("enrolled Pods not listed yet"),
		ready: desc(MetricReady, "1 when the measurement loader's snapshot is fresh, the kernel accepted both programs and "+
			"every Running enrolled Pod of the node that is not terminating is attached within "+AttachGrace.String()+
			". It measures traffic; "+
			"it is never a verdict or a proof of mTLS."),
		hook: desc(MetricHookAvailable, "1 when the loader has this hook: the kernel accepted the program, the node's "+
			"Pod addresses are loaded, or the kernel's run statistics are on.", "hook"),
		workloads: desc(MetricWorkloads, "Enrolled Pods of the node by measurement state: attached, waiting (no Pod "+
			"cgroup yet) or unavailable (the loader logs the reason).", "state"),
		packets: desc(MetricPackets, "Packets that the enrolled Pods' sockets sent (egress) or received (ingress), at "+
			"the cgroup socket layer, before Cilium's egress gate; a GSO or GRO packet counts as its segments. loopback "+
			"stays in the Pod, as every TCP connection that ztunnel captures does; pod_network leaves or enters it. "+
			"tcp excludes DNS, so egress tcp on pod_network left the Pod without ztunnel.", traffic...),
		bytes: desc(MetricBytes, "Bytes of the packets of "+MetricPackets+" at the IP layer; a GSO or GRO packet "+
			"counts its headers once.", traffic...),
		queries: desc(MetricDNSQueries, "Standard DNS queries that the enrolled Pods sent, by transport and by where "+
			"the server is: in_pod (an in-Pod proxy), same_node (a Pod address of this node) or off_node.",
			"namespace", "transport", "locality"),
		answers: desc(MetricDNSAnswers, "DNS answers that the enrolled Pods received, by transport, server locality "+
			"and response code.", "namespace", "transport", "locality", "rcode"),
		duration: desc(MetricDNSDuration, "Time from a DNS query to its answer on the same socket, DNS ID and "+
			"transport, by transport and server locality.", "transport", "locality"),
		unmatched: desc(MetricDNSUnmatched, "DNS answers with no waiting query: the query left the bounded table, "+
			"or it was sent before the loader attached.", "transport"),
		replaced: desc(MetricDNSReplaced, "DNS queries sent again with an ID that was still waiting on the same "+
			"socket, normally a retry; the answer is timed from the last one.", "transport"),
		runTime: desc(MetricProgramRunTime, "Kernel run time of the plane's programs; exported only while "+
			"kernel.bpf_stats_enabled=1.", "direction"),
		runs: desc(MetricProgramRuns, "Kernel run count of the plane's programs; exported only while "+
			"kernel.bpf_stats_enabled=1.", "direction"),
	}
}

// SetDesired records the desired list that the agent wrote for the loader, or why the agent could not build it.
func (c *Collector) SetDesired(pods []DesiredPod, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.desiredErr = err
	if err != nil {
		return
	}
	now := c.now()
	next := make(map[string]time.Time, len(pods))
	for _, p := range pods {
		if !p.Required {
			continue
		}
		if first, ok := c.required[p.UID]; ok {
			next[p.UID] = first
		} else {
			next[p.UID] = now
		}
	}
	c.required = next
}

// Evaluate reads the snapshot and reports whether the plane is ready, with the reason when it is not. The snapshot
// may be exported only when fresh is nil.
func (c *Collector) Evaluate() (s Snapshot, fresh error, ready bool, reason string) {
	s, fresh = ReadSnapshot(c.path)
	if fresh == nil {
		fresh = c.fresh(s)
	}
	c.mu.Lock()
	required := make(map[string]time.Time, len(c.required))
	for uid, since := range c.required {
		required[uid] = since
	}
	desiredErr := c.desiredErr
	c.mu.Unlock()
	ready, reason = Readiness(s, fresh, required, desiredErr, c.now())
	return s, fresh, ready, reason
}

func (c *Collector) fresh(s Snapshot) error {
	boot, err := c.clock.BootID()
	if err != nil {
		return err
	}
	now, err := c.clock.Monotonic()
	if err != nil {
		return err
	}
	return s.Fresh(boot, now)
}

// Readiness is true when the enrolled Pods are known, the snapshot is fresh, the kernel accepted both programs, and
// every Pod that has been required (DesiredPod.Required) for AttachGrace is attached.
func Readiness(s Snapshot, fresh error, required map[string]time.Time, desiredErr error, now time.Time) (bool, string) {
	if desiredErr != nil {
		return false, "enrolled Pods unknown: " + desiredErr.Error()
	}
	if fresh != nil {
		return false, "loader snapshot unusable: " + fresh.Error()
	}
	if !s.Hooks[HookEgress] || !s.Hooks[HookIngress] {
		return false, "the kernel has not accepted both cgroup_skb programs"
	}
	states := make(map[string]PodState, len(s.Pods))
	for _, p := range s.Pods {
		states[p.UID] = p
	}
	uids := make([]string, 0, len(required))
	for uid := range required {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		if now.Sub(required[uid]) < AttachGrace {
			continue
		}
		p, ok := states[uid]
		switch {
		case !ok:
			return false, fmt.Sprintf("Pod %s Running for %s and absent from the loader's snapshot", uid, AttachGrace)
		case p.State != StateAttached:
			return false, fmt.Sprintf("Pod %s in namespace %s %s after %s Running: %s", uid, p.Namespace, p.State,
				AttachGrace, p.Reason)
		}
	}
	return true, ""
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.ready, c.hook, c.workloads, c.packets, c.bytes, c.queries, c.answers,
		c.duration, c.unmatched, c.replaced, c.runTime, c.runs} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s, fresh, ready, _ := c.Evaluate()
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v uint64, labels ...string) {
		if v > 0 {
			ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), labels...)
		}
	}
	gauge(c.ready, boolValue(ready))
	if fresh != nil {
		return
	}
	for _, h := range Hooks {
		gauge(c.hook, boolValue(s.Hooks[h]), h)
	}
	states := map[string]int{}
	for _, p := range s.Pods {
		states[p.State]++
	}
	for _, state := range States {
		gauge(c.workloads, float64(states[state]), state)
	}
	for ns, n := range s.Namespaces {
		for d, dir := range Directions {
			for p, path := range Paths {
				for k, proto := range Protocols {
					counter(c.packets, n.Traffic[d][p][k].Packets, ns, dir, path, proto)
					counter(c.bytes, n.Traffic[d][p][k].Bytes, ns, dir, path, proto)
				}
			}
		}
		for t, transport := range Transports {
			for l, loc := range Localities {
				counter(c.queries, n.DNSQueries[t][l], ns, transport, loc)
				for r, rcode := range RCodes {
					counter(c.answers, n.DNSAnswers[t][l][r], ns, transport, loc, rcode)
				}
			}
		}
	}
	for t, transport := range Transports {
		for l, loc := range Localities {
			counts := s.Node.LatencyCount[t][l]
			var total uint64
			buckets := make(map[float64]uint64, NumBounds)
			for b, upper := range DNSDurationBuckets {
				total += counts[b]
				buckets[upper] = total
			}
			total += counts[NumBounds]
			if total > 0 {
				ch <- prometheus.MustNewConstHistogram(c.duration, total, float64(s.Node.LatencySumNs[t][l])/1e9,
					buckets, transport, loc)
			}
		}
		counter(c.unmatched, s.Node.Unmatched[t], transport)
		counter(c.replaced, s.Node.Replaced[t], transport)
	}
	if s.Programs != nil {
		for d, dir := range Directions {
			if s.Programs.Runs[d] > 0 {
				ch <- prometheus.MustNewConstMetric(c.runTime, prometheus.CounterValue,
					float64(s.Programs.RunTimeNs[d])/1e9, dir)
			}
			counter(c.runs, s.Programs.Runs[d], dir)
		}
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
