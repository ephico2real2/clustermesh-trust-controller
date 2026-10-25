//go:build linux

package main

import (
	"net"
	"net/http"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/metricsexposure"
	"github.com/prometheus/client_golang/prometheus"
)

const metricsPort = metricsexposure.ObserverPort

func validateMetricsAddress(address, nodeIP string) error {
	return metricsexposure.ValidateAddress(address, nodeIP, metricsPort)
}
func openMetricsListener(address, nodeIP string, listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	return metricsexposure.OpenListener(address, nodeIP, metricsPort, listen)
}
func metricsOnlyHandler(registry *prometheus.Registry) http.Handler {
	return metricsexposure.OnlyHandler(registry)
}
func metricsHTTPServer(registry *prometheus.Registry) *http.Server {
	return metricsexposure.Server(registry)
}
