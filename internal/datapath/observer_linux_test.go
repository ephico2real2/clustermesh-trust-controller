//go:build linux

package datapath

import "testing"

func validConfig() Config {
	return Config{Cluster: "cmtc-a", Node: "cmtc-a-worker", PodUID: "explicit-fixture-uid",
		NetNSInode: 4026531992, IfIndex: 12, IfName: "lxcfixture", MAC: "02:00:00:00:00:01",
		PeerIfIndex: 13, Direction: "ingress", CiliumLinkID: 100, CiliumProgramID: 200}
}
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"cluster", func(c *Config) { c.Cluster = "" }},
		{"node", func(c *Config) { c.Node = "" }},
		{"pod", func(c *Config) { c.PodUID = "" }},
		{"netns", func(c *Config) { c.NetNSInode = 0 }},
		{"ifindex", func(c *Config) { c.IfIndex = 0 }},
		{"ifname", func(c *Config) { c.IfName = "" }},
		{"mac", func(c *Config) { c.MAC = "" }},
		{"peer", func(c *Config) { c.PeerIfIndex = 0 }},
		{"anchor", func(c *Config) { c.CiliumLinkID = 0 }},
		{"program", func(c *Config) { c.CiliumProgramID = 0 }},
		{"direction", func(c *Config) { c.Direction = "netkit" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("incomplete config accepted")
			}
		})
	}
	for _, direction := range []string{"ingress", "egress"} {
		c := validConfig()
		c.Direction = direction
		if err := c.Validate(); err != nil {
			t.Fatalf("valid %s config rejected: %v", direction, err)
		}
	}
}
func TestCloseZeroValue(t *testing.T) {
	o := &Observer{}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Sample(); err == nil {
		t.Fatal("closed observer reported available")
	}
}
