//go:build linux

package main

import "testing"

func TestRegistrarMetricsAddressOptInAndExactPodIP(t *testing.T) {
	for _, tc := range []struct {
		value, ip, want string
		valid           bool
	}{
		{"0", "", "0", true}, {"pod", "10.10.1.3", "10.10.1.3:18087", true}, {"pod", "fd00::3", "[fd00::3]:18087", true},
		{"0.0.0.0:18087", "10.10.1.3", "", false}, {"pod", "", "", false}, {"pod", "127.0.0.1", "", false},
		{"10.10.1.4:18087", "10.10.1.3", "", false}, {"10.10.1.3:18086", "10.10.1.3", "", false},
	} {
		got, err := registrarMetricsAddress(tc.value, tc.ip)
		if (err == nil) != tc.valid || (tc.valid && got != tc.want) {
			t.Fatalf("%q/%q = %q,%v", tc.value, tc.ip, got, err)
		}
	}
}
