package measurement

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func status(inh, prm, eff, bnd, amb uint64) []byte {
	return fmt.Appendf(nil, "Name:\tcmtc-measure\nCapInh:\t%016x\nCapPrm:\t%016x\nCapEff:\t%016x\nCapBnd:\t%016x\n"+
		"CapAmb:\t%016x\nNoNewPrivs:\t1\n", inh, prm, eff, bnd, amb)
}

func TestLoaderCapabilitiesAreBPFAndNetAdmin(t *testing.T) {
	if LoaderCapabilities != 0x0000008000001000 {
		t.Fatalf("LoaderCapabilities %#016x, want CAP_BPF and CAP_NET_ADMIN (0x0000008000001000)", LoaderCapabilities)
	}
	if got := CapabilityNames(LoaderCapabilities); !reflect.DeepEqual(got, []string{"CAP_NET_ADMIN", "CAP_BPF"}) {
		t.Fatalf("names %v", got)
	}
}

func TestCheckCapabilitySets(t *testing.T) {
	exact := LoaderCapabilities
	ok, err := ParseCapabilitySets(status(0, exact, exact, exact, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCapabilitySets(ok, LoaderCapabilities); err != nil {
		t.Fatalf("the loader's own set is refused: %v", err)
	}
	// Docker's and containerd's default set for a root container (0x00000000a80425fb), as when the DaemonSet's
	// "drop: [ALL]" is lost.
	const runtimeDefault = 0x00000000a80425fb
	for _, c := range []struct {
		name                    string
		inh, prm, eff, bnd, amb uint64
		want                    string
	}{
		{"the runtime's default set", 0, runtimeDefault, runtimeDefault, runtimeDefault, 0, "effective capability set holds CAP_CHOWN"},
		{"CAP_PERFMON as well", 0, exact | 1<<CapPerfmon, exact | 1<<CapPerfmon, exact | 1<<CapPerfmon, 0,
			"holds CAP_PERFMON beyond CAP_NET_ADMIN,CAP_BPF"},
		{"CAP_SYS_ADMIN in the bounding set only", 0, exact, exact, exact | 1<<CapSysAdmin, 0,
			"bounding capability set holds CAP_SYS_ADMIN"},
		{"an ambient capability", 0, exact, exact, exact, 1 << CapNetAdmin, ""},
		{"an inheritable capability", 1 << 0, exact, exact, exact, 0, "inheritable capability set holds CAP_CHOWN"},
		{"no CAP_NET_ADMIN", 0, 1 << CapBPF, 1 << CapBPF, 1 << CapBPF, 0, "effective capability set lacks CAP_NET_ADMIN"},
		{"CAP_BPF permitted but not effective", 0, exact, 1 << CapNetAdmin, exact, 0, "lacks CAP_BPF"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sets, err := ParseCapabilitySets(status(c.inh, c.prm, c.eff, c.bnd, c.amb))
			if err != nil {
				t.Fatal(err)
			}
			err = CheckCapabilitySets(sets, LoaderCapabilities)
			if c.want == "" {
				// An ambient capability inside the allowed set is no extra privilege.
				if err != nil {
					t.Fatalf("CheckCapabilitySets = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckCapabilitySets = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestParseCapabilitySetsNeedsEverySet(t *testing.T) {
	if _, err := ParseCapabilitySets([]byte("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\n")); err == nil ||
		!strings.Contains(err.Error(), "no CapAmb line") {
		t.Fatalf("a status without CapAmb gave %v", err)
	}
	if _, err := ParseCapabilitySets([]byte("CapInh:\tzz\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n")); err == nil {
		t.Fatal("a capability set that is no hex number was accepted")
	}
}
