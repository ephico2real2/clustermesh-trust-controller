package metricsexposure

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	FencePort    uint16 = 18084
	ObserverPort uint16 = 18085
)

// Disabled unless explicitly configured. Bind only the Kubernetes downward
// status.hostIP, never all interfaces, a DNS hostname, or an arbitrary port.
func ValidateAddress(address, nodeIP string, port uint16) error {
	if port != FencePort && port != ObserverPort {
		return errors.New("unsupported explicit metrics profile port")
	}
	if address == "" {
		return nil
	}
	host, err := netip.ParseAddr(nodeIP)
	if err != nil || !host.IsGlobalUnicast() || host.IsLoopback() || host.Zone() != "" || host.Is4In6() {
		return errors.New("metrics requires explicit canonical unicast NODE_IP from status.hostIP")
	}
	if host.String() != nodeIP {
		return errors.New("NODE_IP must be canonical")
	}
	target, err := netip.ParseAddrPort(address)
	if err != nil || target.Addr() != host || target.Port() != port || target.String() != address {
		return fmt.Errorf("metrics must bind exact NODE_IP:%d (bracketed for IPv6)", port)
	}
	return nil
}

func OpenListener(address, nodeIP string, port uint16, listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	if err := ValidateAddress(address, nodeIP, port); err != nil {
		return nil, err
	}
	if address == "" {
		return nil, nil
	}
	return listen("tcp", address)
}

func OnlyHandler(registry *prometheus.Registry) http.Handler {
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func Server(registry *prometheus.Registry) *http.Server {
	return &http.Server{Handler: OnlyHandler(registry), ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
}
