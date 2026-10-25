//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
)

func TestFenceConfigRejectsAmbiguousKeys(t *testing.T) {
	good := validFenceJSON(t)
	for name, body := range map[string]string{
		"duplicate":       strings.TrimSuffix(good, "}") + `,"node":"n"}`,
		"caseAlias":       strings.Replace(good, `"node":`, `"Node":`, 1),
		"sameAliasTwice":  strings.TrimSuffix(good, "}") + `,"Node":"n"}`,
		"duplicateAnchor": strings.TrimSuffix(good, "}") + `,"ciliumProgramID":5}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfig(strings.NewReader(body)); err == nil {
				t.Fatal("ambiguous audited configuration accepted")
			}
		})
	}
}

func identityFixture(t *testing.T) datapath.FenceConfig {
	t.Helper()
	c, err := decodeConfig(strings.NewReader(validFenceJSON(t)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestHealthIdentityBindsDaemonAndAuditedInputs(t *testing.T) {
	c := identityFixture(t)
	id, err := makeHealthIdentity(c, []byte("elf"), "revision-a", "daemon-uid")
	if err != nil || len(id) != 64 {
		t.Fatalf("identity %q: %v", id, err)
	}
	for name, change := range map[string]func(*datapath.FenceConfig){
		"namespaceUID":   func(c *datapath.FenceConfig) { c.NamespaceUID += "-new" },
		"workloadPodUID": func(c *datapath.FenceConfig) { c.PodUID += "-new" },
		"cluster":        func(c *datapath.FenceConfig) { c.Cluster += "-new" },
		"node":           func(c *datapath.FenceConfig) { c.Node += "-new" },
		"anchor":         func(c *datapath.FenceConfig) { c.CiliumProgramID++ },
		"netns":          func(c *datapath.FenceConfig) { c.NetNSInode++ },
		"pinRoot":        func(c *datapath.FenceConfig) { c.PinRoot += "-new" },
	} {
		t.Run(name, func(t *testing.T) {
			other := c
			change(&other)
			got, e := makeHealthIdentity(other, []byte("elf"), "revision-a", "daemon-uid")
			if e != nil || got == id {
				t.Fatalf("binding unchanged: %v", e)
			}
		})
	}
	for name, args := range map[string][3]string{
		"ELF":       {"other-elf", "revision-a", "daemon-uid"},
		"source":    {"elf", "revision-b", "daemon-uid"},
		"daemonPod": {"elf", "revision-a", "different-daemon-uid"},
	} {
		t.Run(name, func(t *testing.T) {
			got, e := makeHealthIdentity(c, []byte(args[0]), args[1], args[2])
			if e != nil || got == id {
				t.Fatalf("binding unchanged: %v", e)
			}
		})
	}
	// Canonical typed JSON, not whitespace or the original key ordering, is hashed.
	raw, _ := json.MarshalIndent(c, "", " ")
	equivalent, e := decodeConfig(strings.NewReader(string(raw)))
	if e != nil {
		t.Fatal(e)
	}
	got, e := makeHealthIdentity(equivalent, []byte("elf"), "revision-a", "daemon-uid")
	if e != nil || got != id {
		t.Fatal("equivalent audited config changed identity")
	}
	for _, uid := range []string{"", "bad uid", "uid\n", strings.Repeat("x", 129)} {
		if _, e := makeHealthIdentity(c, []byte("elf"), "revision-a", uid); e == nil {
			t.Fatalf("unsafe daemon identity %q accepted", uid)
		}
	}
}
func TestHealthProbeRejectsWrongProcessAndRedirects(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		status       int
		redirect     bool
		wantOK       bool
	}{
		{"matching", "expected", 200, false, true},
		{"unverified", "expected", 503, false, false},
		{"unboundOtherServer", "", 200, false, false},
		{"previousDaemonPod", "other", 200, false, false},
		{"redirectEvenToCorrectIdentity", "expected", 302, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(healthIdentityHeader, tc.header)
				if tc.redirect && r.URL.Path != "/other" {
					w.Header().Set("Location", srv.URL+"/other")
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			for _, kind := range []string{"live", "ready"} {
				err := probeAt(srv.URL, kind, "expected")
				if (err == nil) != tc.wantOK {
					t.Fatalf("%s probe: %v", kind, err)
				}
			}
		})
	}
	if err := probeAt("http://127.0.0.1:1", "ready", ""); err == nil {
		t.Fatal("unbound probe accepted")
	}
	if err := probeAt("http://127.0.0.1:1", "invalid", "expected"); err == nil {
		t.Fatal("invalid probe accepted")
	}
}
func TestHealthHandlerIncludesBindingOnReadyAndUnready(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		r := httptest.NewRecorder()
		healthHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }), "expected").ServeHTTP(r, httptest.NewRequest("GET", "/readyz", nil))
		if r.Code != status || r.Header().Get(healthIdentityHeader) != "expected" {
			t.Fatal("binding/status lost")
		}
	}
}
