package measurement

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// The embedded object is the one scripts/measurement/build-bpf.sh compiled from the committed source: a source change
// without a rebuild fails here.
func TestObjectMatchesItsSource(t *testing.T) {
	source, err := os.ReadFile("bpf/measure.c")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(source); hex.EncodeToString(got[:]) != ObjectSourceSHA256 {
		t.Fatalf("bpf/measure.c has sha256 %x, the object was built from %s; run scripts/measurement/build-bpf.sh",
			got, ObjectSourceSHA256)
	}
	if got := sha256.Sum256(Object); hex.EncodeToString(got[:]) != ObjectSHA256 {
		t.Fatalf("the embedded object has sha256 %x, object_gen.go records %s", got, ObjectSHA256)
	}
}

// LoadSpec accepts the embedded object: CheckSpec and CheckObserveOnly pass on the object that runs.
func TestLoadSpecAcceptsTheEmbeddedObject(t *testing.T) {
	spec, err := LoadSpec()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs[ProgramEgress] == nil || spec.Programs[ProgramIngress] == nil {
		t.Fatalf("programs %v", spec.Programs)
	}
}

func TestCheckSpecRefusesAnotherLayout(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*ebpf.CollectionSpec)
		want   string
	}{
		{"a third program", func(s *ebpf.CollectionSpec) {
			s.Programs["extra"] = s.Programs[ProgramEgress].Copy()
		}, "object has 3 programs"},
		{"egress program of another type", func(s *ebpf.CollectionSpec) {
			s.Programs[ProgramEgress].Type = ebpf.SchedCLS
		}, "lacks cgroup_skb program " + ProgramEgress},
		{"egress program on the ingress hook", func(s *ebpf.CollectionSpec) {
			s.Programs[ProgramEgress].AttachType = ebpf.AttachCGroupInetIngress
		}, "lacks cgroup_skb program " + ProgramEgress},
		{"another map", func(s *ebpf.CollectionSpec) {
			s.Maps["cilium_lxc"] = s.Maps[MapNode].Copy()
		}, "unexpected map cilium_lxc"},
		{"a missing map", func(s *ebpf.CollectionSpec) { delete(s.Maps, MapDNS) }, "lacks map " + MapDNS},
		{"traffic cells of another size", func(s *ebpf.CollectionSpec) {
			s.Maps[MapTraffic].ValueSize = 8
		}, "map " + MapTraffic},
		{"a shorter node array", func(s *ebpf.CollectionSpec) {
			s.Maps[MapNode].MaxEntries = NodeCells - 1
		}, "map " + MapNode},
		{"a pinned map", func(s *ebpf.CollectionSpec) {
			s.Maps[MapPending].Pinning = ebpf.PinByName
		}, "map " + MapPending},
		{"map flags", func(s *ebpf.CollectionSpec) {
			s.Maps[MapNodeAddresses].Flags = 1
		}, "map " + MapNodeAddresses},
		{"a second variable", func(s *ebpf.CollectionSpec) {
			s.Variables["cmtc_slot"] = s.Variables[VariableBounds]
		}, "object has 2 variables"},
		{"no bounds variable", func(s *ebpf.CollectionSpec) {
			delete(s.Variables, VariableBounds)
		}, "object has 0 variables"},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec, err := LoadSpec()
			if err != nil {
				t.Fatal(err)
			}
			c.change(spec)
			if err := CheckSpec(spec); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckSpec = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// checkProgram runs CheckObserveOnly on a spec with one program of the given instructions.
func checkProgram(insns asm.Instructions) error {
	return CheckObserveOnly(&ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"p": {Name: "p", Type: ebpf.CGroupSKB, Instructions: insns}}})
}

func TestCheckObserveOnlyRefusesAnyOtherVerdict(t *testing.T) {
	pass := asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}
	if err := checkProgram(pass); err != nil {
		t.Fatalf("CheckObserveOnly refused the pass program: %v", err)
	}
	// "if r1 == 0 goto +1" jumps over "r0 = 1" to the exit, with r0 still 0.
	jumpOver := asm.JEq.Imm(asm.R1, 0, "")
	jumpOver.Offset = 1
	for _, c := range []struct {
		name  string
		insns asm.Instructions
		want  string
	}{
		{"drop", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, "does not follow r0 = 1"},
		{"verdict from a register", asm.Instructions{asm.Mov.Imm(asm.R1, 0), asm.Mov.Reg(asm.R0, asm.R1),
			asm.Return()}, "does not follow r0 = 1"},
		{"an exit reached by a jump", asm.Instructions{
			asm.Mov.Imm(asm.R0, 0), jumpOver, asm.Mov.Imm(asm.R0, 1), asm.Return(),
		}, "is a jump target"},
		{"a jump to a label", asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.JEq.Imm(asm.R1, 0, "out"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return().WithSymbol("out"),
		}, "jumps to label"},
		{"no exit", asm.Instructions{asm.Mov.Imm(asm.R0, 1)}, "no exit instruction"},
		{"a helper that changes the packet", asm.Instructions{
			asm.FnSkbStoreBytes.Call(), asm.Mov.Imm(asm.R0, 1), asm.Return(),
		}, "outside the allowlist"},
		{"a helper that redirects", asm.Instructions{
			asm.FnRedirect.Call(), asm.Mov.Imm(asm.R0, 1), asm.Return(),
		}, "outside the allowlist"},
		{"a BPF-to-BPF call", asm.Instructions{
			asm.Call.Label("f"), asm.Mov.Imm(asm.R0, 1), asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("f"), asm.Return(),
		}, "calls a function"},
		{"a helper call with a destination register", asm.Instructions{
			{OpCode: asm.Call.Op(asm.ImmSource), Dst: asm.R1, Constant: int64(asm.FnKtimeGetNs)},
			asm.Mov.Imm(asm.R0, 1), asm.Return(),
		}, "does not know"},
		{"an exit of the 32-bit jump class", asm.Instructions{
			asm.Mov.Imm(asm.R0, 0), {OpCode: asm.OpCode(asm.Jump32Class) | asm.OpCode(asm.Exit)},
			asm.Mov.Imm(asm.R0, 1), asm.Return(),
		}, "does not know"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := checkProgram(c.insns); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckObserveOnly = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// The programs write no context field. The kernel tests compare every writable __sk_buff field (mark, priority, cb,
// tstamp: net/core/filter.c, cg_skb_is_valid_access) before and after each run; this test refuses an assignment to
// skb-> or sk-> in the source before it reaches a kernel.
func TestSourceWritesNoContextField(t *testing.T) {
	source, err := os.ReadFile("bpf/measure.c")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`).ReplaceAllString(string(source), "")
	write := regexp.MustCompile(`\bsk(b)?->[a-z_0-9]+(\[[^\]]*\])?\s*(\+\+|--|[-+*/%&|^]=|<<=|>>=|=[^=])`)
	if m := write.FindString(code); m != "" {
		t.Fatalf("bpf/measure.c writes a context field: %q", m)
	}
	// The pattern finds the writes it is meant to find.
	for _, w := range []string{"skb->mark = 1;", "skb->cb[0] |= 2;", "skb->priority++;", "sk->mark=3;"} {
		if !write.MatchString(w) {
			t.Fatalf("the pattern misses %q", w)
		}
	}
	if write.MatchString("if (skb->ifindex == 1)") {
		t.Fatal("the pattern takes a comparison for a write")
	}
}
