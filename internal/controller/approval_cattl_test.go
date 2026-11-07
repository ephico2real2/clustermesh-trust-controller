package controller

import (
	"testing"
	"time"
)

// SPIRE's CA lifetime is read from server.conf exactly: SPIRE's default when ca_ttl is absent, the stated duration when
// it is on one line of its own, and unknown (no retirement) otherwise.
func TestSPIRECALifetimeFromServerConf(t *testing.T) {
	upstream := "UpstreamAuthority \"cert-manager\" {\n  plugin_data {\n    issuer_name = \"cmtc-a-spire-intermediate\"\n  }\n}\n"
	for name, c := range map[string]struct {
		conf string
		want time.Duration
	}{
		"absent":         {"server {\n  trust_domain = \"cmtc-a.mesh.example\"\n}\n" + upstream, 24 * time.Hour},
		"stated":         {"server {\n  ca_ttl = \"12h\"\n}\n" + upstream, 12 * time.Hour},
		"commented out":  {"server {\n  # ca_ttl = \"72h\"\n  // ca_ttl = \"96h\"\n}\n" + upstream, 24 * time.Hour},
		"comment after":  {"server {\n  ca_ttl = \"12h\" # SPIRE's default is 24h\n}\n" + upstream, 0},
		"stated twice":   {"server {\n  ca_ttl = \"24h\"\n  ca_ttl = \"72h\"\n}\n" + upstream, 0},
		"inline":         {"server { ca_ttl = \"72h\" }\n" + upstream, 0},
		"not a duration": {"server {\n  ca_ttl = \"two days\"\n}\n" + upstream, 0},
		"negative":       {"server {\n  ca_ttl = \"-1h\"\n}\n" + upstream, 0},
	} {
		if got := spireCALifetime(c.conf); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}
