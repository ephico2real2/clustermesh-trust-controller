//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
)

// Off by default. "pod" derives the exact Pod IP from the downward API and
// works with IPv4 or IPv6. No wildcard, loopback, foreign address or extra port.
func registrarMetricsAddress(value, podIP string) (string, error) {
	if value == "0" {
		return value, nil
	}
	ip, err := netip.ParseAddr(podIP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" || ip.String() != podIP {
		return "", fmt.Errorf("registrar metrics requires canonical downward POD_IP")
	}
	if value == "pod" {
		value = net.JoinHostPort(podIP, "18087")
	}
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Addr() != ip || address.Port() != 18087 || address.String() != value {
		return "", fmt.Errorf("registrar metrics must bind exactly POD_IP:18087")
	}
	return value, nil
}
