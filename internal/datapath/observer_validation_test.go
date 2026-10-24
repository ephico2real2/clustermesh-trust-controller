//go:build linux

package datapath

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateRejectsNoncanonicalKernelIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"oversized-ifindex", func(c *Config) { value := int64(1) << 31; c.IfIndex = int(value) }},
		{"oversized-peer", func(c *Config) { value := int64(1) << 31; c.PeerIfIndex = int(value) }},
		{"long-name", func(c *Config) { c.IfName = strings.Repeat("x", 16) }},
		{"nul-name", func(c *Config) { c.IfName = "lxc\x00other" }},
		{"slash-name", func(c *Config) { c.IfName = "lxc/other" }},
		{"malformed-mac", func(c *Config) { c.MAC = "invalid" }},
		{"eui64-mac", func(c *Config) { c.MAC = "02:00:00:00:00:00:00:01" }},
		{"noncanonical-mac", func(c *Config) { c.MAC = "02-00-00-00-00-01" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid identifier accepted")
			}
			// Early guard is part of public Open contract, before privileged calls.
			if o, err := Open(cfg, nil); err == nil {
				_ = o.Close()
				t.Fatal("Open accepted invalid config")
			}
		})
	}
}
func TestClosedObserverReturnsStableError(t *testing.T) {
	o := &Observer{}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Sample(); !errors.Is(err, ErrClosed) {
		t.Fatalf("missing stable closed error: %v", err)
	}
}
