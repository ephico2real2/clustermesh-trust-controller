//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	"github.com/prometheus/client_golang/prometheus"
)

func commandFixture() datapath.Config {
	return datapath.Config{Cluster: "fixture", Node: "fixture-node", PodUID: "not-a-metric-label",
		NetNSInode: 42, IfIndex: 10, IfName: "lxcfixture", MAC: "02:00:00:00:00:01", PeerIfIndex: 11,
		Direction: "ingress", CiliumLinkID: 30, CiliumProgramID: 40}
}
func TestDecodeConfigRejectsAmbiguousOrInvalidJSON(t *testing.T) {
	b, err := json.Marshal(commandFixture())
	if err != nil {
		t.Fatal(err)
	}
	good := string(b)
	tests := []struct {
		name, body string
		wantError  bool
	}{
		{"valid", good, false}, {"whitespace", good + " \n\t", false},
		{"empty", "", true}, {"null", "null", true}, {"missing", "{}", true},
		{"extra-object", good + " {}", true}, {"extra-null", good + " null", true},
		{"garbage", good + " extra", true},
		{"unknown", strings.TrimSuffix(good, "}") + `,"unknown":true}`, true},
		{"wrong-field-type", strings.Replace(good, `"ifIndex":10`, `"ifIndex":"10"`, 1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := decodeConfig(strings.NewReader(tt.body))
			if (err != nil) != tt.wantError {
				t.Fatalf("decode error=%v, wantError=%v", err, tt.wantError)
			}
			if !tt.wantError && !reflect.DeepEqual(c, commandFixture()) {
				t.Fatalf("decoded wrong config: %+v", c)
			}
		})
	}
}

func collectValues(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, family := range families {
		if len(family.Metric) != 1 {
			t.Fatalf("unexpected metric cardinality %s", family.GetName())
		}
		metric := family.Metric[0]
		labels := map[string]string{}
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if !reflect.DeepEqual(labels, map[string]string{"cluster": "fixture", "node": "fixture-node", "direction": "ingress"}) {
			t.Fatalf("unexpected/broad metric labels: %v", labels)
		}
		if metric.Counter != nil {
			values[family.GetName()] = metric.Counter.GetValue()
		} else if metric.Gauge != nil {
			values[family.GetName()] = metric.Gauge.GetValue()
		} else {
			t.Fatalf("unexpected metric type: %s", family.GetName())
		}
	}
	return values
}

func TestCollectorDistinguishesLiveZeroAndUnavailable(t *testing.T) {
	s := newObservation(commandFixture())
	reg := prometheus.NewRegistry()
	reg.MustRegister(s)
	readyOnly := map[string]float64{"cmtc_datapath_observer_ready": 0}
	if got := collectValues(t, reg); !reflect.DeepEqual(got, readyOnly) {
		t.Fatalf("unavailable emitted counters: %v", got)
	}
	s.Lock()
	s.ready = true
	s.sampledAt = time.Now()
	s.Unlock()
	zero := map[string]float64{"cmtc_datapath_observer_ready": 1, "cmtc_datapath_observer_packets_total": 0, "cmtc_datapath_observer_bytes_total": 0}
	if got := collectValues(t, reg); !reflect.DeepEqual(got, zero) {
		t.Fatalf("live zero missing: %v", got)
	}
	s.Lock()
	s.count = datapath.Count{Packets: 50, Bytes: 3200}
	s.sampledAt = time.Now()
	s.Unlock()
	expected := map[string]float64{"cmtc_datapath_observer_ready": 1, "cmtc_datapath_observer_packets_total": 50, "cmtc_datapath_observer_bytes_total": 3200}
	// A repeated scrape must expose an absolute kernel total, never Add(total).
	for range 3 {
		if got := collectValues(t, reg); !reflect.DeepEqual(got, expected) {
			t.Fatalf("absolute counters changed without packets: %v", got)
		}
	}
	s.Lock()
	s.ready = false
	s.Unlock()
	if got := collectValues(t, reg); !reflect.DeepEqual(got, readyOnly) {
		t.Fatalf("failed sample leaked last counters: %v", got)
	}
}

func TestFreshnessControlsMetricsAndReadiness(t *testing.T) {
	s := newObservation(commandFixture())
	reg := prometheus.NewRegistry()
	reg.MustRegister(s)
	now := time.Now()
	tests := []struct {
		name    string
		sampled time.Time
		ready   bool
	}{
		{"never", time.Time{}, false},
		{"fresh", now, true},
		{"expired", now.Add(-sampleMaxAge - time.Second), false},
		{"clock-future", now.Add(time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.Lock()
			s.ready = true
			s.sampledAt = tt.sampled
			s.count = datapath.Count{Packets: 99, Bytes: 500}
			s.Unlock()
			_, ok := s.snapshot(now)
			if ok != tt.ready {
				t.Fatalf("snapshot readiness %v, want %v", ok, tt.ready)
			}
			values := collectValues(t, reg)
			expected := float64(0)
			if tt.ready {
				expected = 1
			}
			if values["cmtc_datapath_observer_ready"] != expected {
				t.Fatalf("stale metric readiness: %v", values)
			}
			if _, present := values["cmtc_datapath_observer_packets_total"]; present != tt.ready {
				t.Fatalf("counter presence=%v, want %v", present, tt.ready)
			}
			recorder := httptest.NewRecorder()
			s.serveReadiness(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			status := http.StatusServiceUnavailable
			if tt.ready {
				status = http.StatusOK
			}
			if recorder.Code != status {
				t.Fatalf("HTTP readiness=%d want%d", recorder.Code, status)
			}
		})
	}
}

func TestCollectorConcurrentPublicationAndGather(t *testing.T) {
	s := newObservation(commandFixture())
	reg := prometheus.NewRegistry()
	reg.MustRegister(s)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 100 {
			s.Lock()
			s.count = datapath.Count{Packets: uint64(i), Bytes: uint64(i) * 64}
			s.ready = i%3 != 0
			s.sampledAt = time.Now()
			s.Unlock()
		}
	}()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				if _, err := reg.Gather(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	s.Lock()
	s.ready = false
	s.Unlock()
	if got := collectValues(t, reg); len(got) != 1 || got["cmtc_datapath_observer_ready"] != 0 {
		t.Fatalf("unavailable state after concurrent scrapes: %v", got)
	}
}
