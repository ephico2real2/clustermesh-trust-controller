//go:build linux

package main

import (
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsExplicitAddressBinding(t *testing.T) {
	for _, tc := range []struct {
		name, addr, ip string
		ok             bool
	}{
		{"disabled", "", "", true},
		{"IPv4", "192.0.2.5:18084", "192.0.2.5", true},
		{"privateIPv4", "172.18.0.5:18084", "172.18.0.5", true},
		{"IPv6", "[2001:db8::5]:18084", "2001:db8::5", true},
		{"unsetNode", "192.0.2.5:18084", "", false},
		{"wildcard", "0.0.0.0:18084", "192.0.2.5", false},
		{"wrongNode", "192.0.2.6:18084", "192.0.2.5", false},
		{"wrongPort", "192.0.2.5:18083", "192.0.2.5", false},
		{"zeroPort", "192.0.2.5:0", "192.0.2.5", false},
		{"hostname", "node.example:18084", "192.0.2.5", false},
		{"loopback", "127.0.0.1:18084", "127.0.0.1", false},
		{"multicast", "224.0.0.1:18084", "224.0.0.1", false},
		{"linkLocal", "169.254.1.2:18084", "169.254.1.2", false},
		{"mappedIPv4", "[::ffff:192.0.2.5]:18084", "::ffff:192.0.2.5", false},
		{"notCanonical", "[2001:0db8::5]:18084", "2001:db8::5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateMetricsAddress(tc.addr, tc.ip); (got == nil) != tc.ok {
				t.Fatalf("got %v", got)
			}
		})
	}
}
func TestMetricsListenErrorsPropagateAndDisabledDoesNotListen(t *testing.T) {
	sentinel := errors.New("occupied")
	called := 0
	listen := func(network, address string) (net.Listener, error) {
		called++
		if network != "tcp" || address != "192.0.2.5:18084" {
			t.Fatal("unvalidated socket")
		}
		return nil, sentinel
	}
	if l, e := openMetricsListener("", "", listen); l != nil || e != nil || called != 0 {
		t.Fatal("disabled listener did IO")
	}
	if _, e := openMetricsListener("0.0.0.0:18084", "192.0.2.5", listen); e == nil || called != 0 {
		t.Fatal("invalid listener did IO")
	}
	if _, e := openMetricsListener("192.0.2.5:18084", "192.0.2.5", listen); !errors.Is(e, sentinel) || called != 1 {
		t.Fatal("listener failure swallowed")
	}
}
func TestMetricsOnlyEndpointFreshIdleAndAbsentCounters(t *testing.T) {
	q := newQuarantine(datapath.FenceConfig{Cluster: "cmtc-a", Node: "worker", Direction: "ingress"})
	reg := prometheus.NewRegistry()
	reg.MustRegister(q)
	h := metricsOnlyHandler(reg)
	get := func(path, method string) *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(method, path, nil))
		return r
	}
	for _, path := range []string{"/", "/readyz", "/healthz", "/config", "/debug/pprof/", "/metrics/"} {
		if r := get(path, "GET"); r.Code != 404 {
			t.Fatalf("exposed %s: %d", path, r.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "HEAD"} {
		if r := get("/metrics", method); r.Code != 405 {
			t.Fatalf("allowed %s", method)
		}
	}
	r := get("/metrics", "GET")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "cmtc_datapath_fence_quarantine_verified") || strings.Contains(r.Body.String(), "cmtc_datapath_fence_dropped_packets_total") {
		t.Fatal("unverified sample emitted counters")
	}
	q.set(datapath.FenceCount{}, true)
	r = get("/metrics", "GET")
	if !strings.Contains(r.Body.String(), `cmtc_datapath_fence_dropped_packets_total{cluster="cmtc-a",direction="ingress",node="worker"} 0`) {
		t.Fatal("observed idle zero missing")
	}
	q.set(datapath.FenceCount{DroppedPackets: 7, DroppedBytes: 420}, true)
	r = get("/metrics", "GET")
	if !strings.Contains(r.Body.String(), `} 7`) {
		t.Fatal("actual counter missing")
	}
	q.Lock()
	q.sampled = time.Now().Add(-sampleMaxAge - time.Second)
	q.Unlock()
	r = get("/metrics", "GET")
	if strings.Contains(r.Body.String(), "cmtc_datapath_fence_dropped_packets_total") || !strings.Contains(r.Body.String(), `} 0`) {
		t.Fatal("stale counters emitted or readiness not zero")
	}
}
