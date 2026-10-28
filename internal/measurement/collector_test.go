package measurement

import (
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const testBoot = "6f1c3b0a-0000-4000-8000-000000000001"

// collectorAt returns a collector of the snapshot in dir whose clock reads testBoot and nowNs, and whose wall clock
// reads now.
func collectorAt(dir string, nowNs int64, now time.Time) *Collector {
	c := NewCollector("cmtc-a", "worker", filepath.Join(dir, SnapshotFile), Clock{
		BootID:    func() (string, error) { return testBoot, nil },
		Monotonic: func() (int64, error) { return nowNs, nil },
	})
	c.now = func() time.Time { return now }
	return c
}

// series gathers the collector and returns each series as name{label="value",...} with its value: a gauge's or a
// counter's value, a histogram's sample count.
func series(t *testing.T, c *Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+`"`+l.GetValue()+`"`)
			}
			sort.Strings(labels)
			key := f.GetName() + "{" + strings.Join(labels, ",") + "}"
			switch {
			case m.GetGauge() != nil:
				out[key] = m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				out[key] = m.GetCounter().GetValue()
			case m.GetHistogram() != nil:
				out[key] = float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return out
}

// seriesKey is the key series gives the series of name with the cluster and node labels and the given label pairs.
func seriesKey(name string, pairs ...string) string {
	labels := []string{`cluster="cmtc-a"`, `node="worker"`}
	for i := 0; i < len(pairs); i += 2 {
		labels = append(labels, pairs[i]+"="+`"`+pairs[i+1]+`"`)
	}
	sort.Strings(labels)
	return name + "{" + strings.Join(labels, ",") + "}"
}

func freshSnapshot() Snapshot {
	s := Snapshot{Version: ExchangeVersion, BootID: testBoot, MonotonicNs: 100 * int64(time.Second), Execution: "e1",
		Hooks: map[string]bool{HookEgress: true, HookIngress: true, HookNodeAddresses: true, HookProgramStats: false},
		Pods: []PodState{{UID: uidA, Namespace: "shop", State: StateAttached},
			{UID: uidB, Namespace: "shop", State: StateWaiting, Reason: "Pod cgroup not created yet"}},
		Namespaces: map[string]PodCounters{}}
	var shop PodCounters
	shop.Traffic[0][1][0] = Counter{Packets: 7, Bytes: 700} // egress pod_network tcp
	shop.Traffic[0][1][2] = Counter{Packets: 2, Bytes: 94}  // egress pod_network dns
	shop.DNSQueries[0][2] = 2                               // udp off_node
	shop.DNSAnswers[0][2][3] = 1                            // udp off_node nxdomain
	s.Namespaces["shop"] = shop
	s.Node.LatencyCount[0][2][4] = 1 // one answer within 10 ms
	s.Node.LatencySumNs[0][2] = 7_000_000
	s.Node.Unmatched[0] = 1
	return s
}

func TestCollectorExportsAFreshSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFileAtomic(dir, SnapshotFile, freshSnapshot()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := collectorAt(dir, 101*int64(time.Second), now)
	c.SetDesired([]DesiredPod{{UID: uidA, Namespace: "shop", Required: true}, {UID: uidB, Namespace: "shop"}}, nil)
	c.now = func() time.Time { return now.Add(AttachGrace) }

	got := series(t, c)
	want := map[string]float64{
		seriesKey(MetricReady): 1,
		seriesKey(MetricHookAvailable, "hook", "cgroup_skb_egress"):                                                    1,
		seriesKey(MetricHookAvailable, "hook", "cgroup_skb_ingress"):                                                   1,
		seriesKey(MetricHookAvailable, "hook", "node_addresses"):                                                       1,
		seriesKey(MetricHookAvailable, "hook", "program_stats"):                                                        0,
		seriesKey(MetricWorkloads, "state", "attached"):                                                                1,
		seriesKey(MetricWorkloads, "state", "unavailable"):                                                             0,
		seriesKey(MetricWorkloads, "state", "waiting"):                                                                 1,
		seriesKey(MetricPackets, "namespace", "shop", "direction", "egress", "path", "pod_network", "protocol", "tcp"): 7,
		seriesKey(MetricBytes, "namespace", "shop", "direction", "egress", "path", "pod_network", "protocol", "tcp"):   700,
		seriesKey(MetricPackets, "namespace", "shop", "direction", "egress", "path", "pod_network", "protocol", "dns"): 2,
		seriesKey(MetricBytes, "namespace", "shop", "direction", "egress", "path", "pod_network", "protocol", "dns"):   94,
		seriesKey(MetricDNSQueries, "namespace", "shop", "transport", "udp", "locality", "off_node"):                   2,
		seriesKey(MetricDNSAnswers, "namespace", "shop", "transport", "udp", "locality", "off_node", "rcode",
			"nxdomain"): 1,
		seriesKey(MetricDNSDuration, "transport", "udp", "locality", "off_node"): 1,
		seriesKey(MetricDNSUnmatched, "transport", "udp"):                        1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("series\n got %v\nwant %v", got, want)
	}
}

// Data that is absent never shows as zero: a stale, foreign or missing snapshot exports only the ready gauge, at 0.
func TestCollectorExportsOnlyReadyWithoutAFreshSnapshot(t *testing.T) {
	ready := seriesKey(MetricReady)
	for _, c := range []struct {
		name  string
		write func(dir string) error
		nowNs int64
	}{
		{"no snapshot", func(string) error { return nil }, 101 * int64(time.Second)},
		{"a stale snapshot", func(dir string) error { return WriteFileAtomic(dir, SnapshotFile, freshSnapshot()) },
			100*int64(time.Second) + SnapshotMaxAge.Nanoseconds() + 1},
		{"a snapshot from another boot", func(dir string) error {
			s := freshSnapshot()
			s.BootID = "another-boot"
			return WriteFileAtomic(dir, SnapshotFile, s)
		}, 101 * int64(time.Second)},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := c.write(dir); err != nil {
				t.Fatal(err)
			}
			col := collectorAt(dir, c.nowNs, time.Now())
			col.SetDesired(nil, nil)
			if got := series(t, col); !reflect.DeepEqual(got, map[string]float64{ready: 0}) {
				t.Fatalf("series %v, want only %s 0", got, ready)
			}
		})
	}
}

func TestReadiness(t *testing.T) {
	now := time.Now()
	s := freshSnapshot()
	long := map[string]time.Time{uidA: now.Add(-AttachGrace)}
	for _, c := range []struct {
		name       string
		snapshot   Snapshot
		fresh      error
		required   map[string]time.Time
		desiredErr error
		ready      bool
		reason     string
	}{
		{"every required Pod attached", s, nil, long, nil, true, ""},
		{"the enrolled Pods unknown", s, nil, nil, errors.New("cache not synced"), false, "enrolled Pods unknown"},
		{"a stale snapshot", s, errors.New("snapshot older than 3s"), long, nil, false, "loader snapshot unusable"},
		{"a hook the kernel refused", func() Snapshot {
			x := freshSnapshot()
			x.Hooks = map[string]bool{HookEgress: true}
			return x
		}(), nil, long, nil, false, "has not accepted both"},
		{"a required Pod waiting after the grace", s, nil,
			map[string]time.Time{uidB: now.Add(-AttachGrace)}, nil, false, "waiting after 10s Running"},
		{"a required Pod waiting within the grace", s, nil,
			map[string]time.Time{uidB: now.Add(-AttachGrace + time.Second)}, nil, true, ""},
		{"a required Pod absent from the snapshot", s, nil,
			map[string]time.Time{"00000000-0000-4000-8000-000000000009": now.Add(-time.Hour)}, nil, false,
			"absent from the loader's snapshot"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ready, reason := Readiness(c.snapshot, c.fresh, c.required, c.desiredErr, now)
			if ready != c.ready || !strings.Contains(reason, c.reason) {
				t.Fatalf("Readiness = %v %q, want %v with a reason containing %q", ready, reason, c.ready, c.reason)
			}
		})
	}
}

// A Pod stays required from the first desired list that required it: AttachGrace counts from then, not from the
// latest list.
func TestSetDesiredKeepsTheFirstTimeAPodWasRequired(t *testing.T) {
	start := time.Now()
	c := collectorAt(t.TempDir(), 0, start)
	c.SetDesired([]DesiredPod{{UID: uidA, Namespace: "shop", Required: true}}, nil)
	c.now = func() time.Time { return start.Add(5 * time.Second) }
	c.SetDesired([]DesiredPod{{UID: uidA, Namespace: "shop", Required: true}, {UID: uidB, Namespace: "shop"}}, nil)
	if got := c.required; len(got) != 1 || !got[uidA].Equal(start) {
		t.Fatalf("required %v, want only %s since %v", got, uidA, start)
	}
	c.SetDesired(nil, errors.New("list the node's Pods: forbidden"))
	if _, _, ready, reason := c.Evaluate(); ready || !strings.Contains(reason, "forbidden") {
		t.Fatalf("Evaluate after a failed list = %v %q", ready, reason)
	}
}
