//go:build linux

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	"github.com/prometheus/client_golang/prometheus"
)

func TestObserverMetricsOnlyFreshIdleAndUnavailable(t *testing.T) {
	q := newObservation(commandFixture())
	reg := prometheus.NewRegistry()
	reg.MustRegister(q)
	h := metricsOnlyHandler(reg)
	scrape := func() string {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
		if r.Code != 200 {
			t.Fatal(r.Code)
		}
		return r.Body.String()
	}
	if body := scrape(); !strings.Contains(body, "cmtc_datapath_observer_ready") || strings.Contains(body, "cmtc_datapath_observer_packets_total") {
		t.Fatal("unavailable counters exported")
	}
	q.Lock()
	q.ready = true
	q.sampledAt = time.Now()
	q.count = datapath.Count{}
	q.Unlock()
	if body := scrape(); !strings.Contains(body, `cmtc_datapath_observer_packets_total{cluster="fixture",direction="ingress",node="fixture-node"} 0`) {
		t.Fatal("real idle zero missing")
	}
	q.Lock()
	q.count = datapath.Count{Packets: 7, Bytes: 420}
	q.sampledAt = time.Now()
	q.Unlock()
	if body := scrape(); !strings.Contains(body, `} 7`) {
		t.Fatal("observed packet total missing")
	}
	q.Lock()
	q.sampledAt = time.Now().Add(-sampleMaxAge - time.Second)
	q.Unlock()
	if body := scrape(); strings.Contains(body, "cmtc_datapath_observer_packets_total") {
		t.Fatal("stale counters exported")
	}
	if err := validateMetricsAddress("192.0.2.5:18084", "192.0.2.5"); err == nil {
		t.Fatal("fence port accepted for observer")
	}
	if err := validateMetricsAddress("192.0.2.5:18085", "192.0.2.5"); err != nil {
		t.Fatal(err)
	}
}
