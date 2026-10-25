package metricsexposure

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestExplicitMetricsProfilePortsAndBindings(t *testing.T) {
	for _, port := range []uint16{FencePort, ObserverPort} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			good := fmt.Sprintf("192.0.2.5:%d", port)
			if err := ValidateAddress(good, "192.0.2.5", port); err != nil {
				t.Fatal(err)
			}
			for _, address := range []string{"0.0.0.0:18084", "192.0.2.6:18085", "192.0.2.5:1", "node.example:18085", "127.0.0.1:18085"} {
				if err := ValidateAddress(address, "192.0.2.5", port); err == nil {
					t.Fatalf("unsafe address %s accepted", address)
				}
			}
			calls := 0
			sentinel := errors.New("occupied")
			listen := func(network, address string) (net.Listener, error) {
				calls++
				if network != "tcp" || address != good {
					t.Fatal("unvalidated listen")
				}
				return nil, sentinel
			}
			if _, err := OpenListener("", "", port, listen); err != nil || calls != 0 {
				t.Fatal("disabled listener touched socket")
			}
			if _, err := OpenListener(good, "", port, listen); err == nil || calls != 0 {
				t.Fatal("unset identity reached socket")
			}
			if _, err := OpenListener(good, "192.0.2.5", port, listen); !errors.Is(err, sentinel) || calls != 1 {
				t.Fatal("bind error swallowed")
			}
		})
	}
	if err := ValidateAddress("", "", 1); err == nil {
		t.Fatal("unsupported profile accepted")
	}
}
func TestMetricsOnlyHandlerAndServerBounds(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "fixture_ready", Help: "test state"})
	reg.MustRegister(g)
	h := OnlyHandler(reg)
	for _, path := range []string{"/", "/healthz", "/readyz", "/config", "/debug/pprof/", "/metrics/"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 404 {
			t.Fatalf("exposed %s", path)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "HEAD"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(method, "/metrics", nil))
		if r.Code != 405 || r.Header().Get("Allow") != "GET" {
			t.Fatal("mutation method accepted")
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if r.Code != 200 {
		t.Fatal("metrics unavailable")
	}
	s := Server(reg)
	if s.ReadHeaderTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes != 8192 {
		t.Fatal("unbounded public HTTP server")
	}
}
