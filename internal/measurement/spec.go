package measurement

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Object names in bpf/measure.c.
const (
	ProgramEgress    = "cmtc_measure_egress"
	ProgramIngress   = "cmtc_measure_ingress"
	MapTraffic       = "cmtc_traffic"
	MapDNS           = "cmtc_dns"
	MapNode          = "cmtc_node"
	MapPending       = "cmtc_dns_pend"
	MapNodeAddresses = "cmtc_node_addrs"
	VariableBounds   = "cmtc_bounds_ns"
	rodataSection    = ".rodata"
)

// SharedMaps are the maps that the programs of every Pod share; the loader creates each once. Each Pod's copy of the
// programs gets its own MapTraffic and MapDNS.
var SharedMaps = []string{MapNode, MapPending, MapNodeAddresses}

// Programs names each program and its attach type, in Directions order.
var Programs = [NumDirections]struct {
	Name   string
	Attach ebpf.AttachType
}{{ProgramEgress, ebpf.AttachCGroupInetEgress}, {ProgramIngress, ebpf.AttachCGroupInetIngress}}

// pendingKey mirrors struct cmtc_pending_key; nodeAddress mirrors struct cmtc_addr.
type pendingKey struct {
	Cookie    uint64
	ID        uint16
	Transport uint8
	Pad       [5]uint8
}

type nodeAddress [16]byte

// LoadSpec parses Object and checks it with CheckSpec and CheckObserveOnly.
func LoadSpec() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(Object))
	if err != nil {
		return nil, fmt.Errorf("parse the measurement object: %w", err)
	}
	if err := CheckSpec(spec); err != nil {
		return nil, err
	}
	if err := CheckObserveOnly(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

// CheckSpec refuses an object that is not the bpf/measure.c this loader was built for: its two cgroup_skb programs,
// its five unpinned maps with the layouts of contract.go, and its one read-only variable.
func CheckSpec(spec *ebpf.CollectionSpec) error {
	if len(spec.Programs) != len(Programs) {
		return fmt.Errorf("object has %d programs, want %d", len(spec.Programs), len(Programs))
	}
	for _, p := range Programs {
		ps := spec.Programs[p.Name]
		if ps == nil || ps.Type != ebpf.CGroupSKB || ps.AttachType != p.Attach {
			return fmt.Errorf("object lacks cgroup_skb program %s for %s", p.Name, p.Attach)
		}
	}
	want := map[string]struct {
		typ                    ebpf.MapType
		key, value, maxEntries uint32
	}{
		MapTraffic:       {ebpf.PerCPUArray, 4, uint32(binary.Size(Counter{})), TrafficCells},
		MapDNS:           {ebpf.PerCPUArray, 4, 8, PodDNSCells},
		MapNode:          {ebpf.PerCPUArray, 4, 8, NodeCells},
		MapPending:       {ebpf.LRUHash, uint32(binary.Size(pendingKey{})), 8, MaxPending},
		MapNodeAddresses: {ebpf.Hash, uint32(binary.Size(nodeAddress{})), 4, MaxNodeAddresses},
	}
	for name, ms := range spec.Maps {
		if name == rodataSection {
			continue
		}
		w, ok := want[name]
		if !ok {
			return fmt.Errorf("object has unexpected map %s", name)
		}
		if ms.Type != w.typ || ms.KeySize != w.key || ms.ValueSize != w.value || ms.MaxEntries != w.maxEntries ||
			ms.Flags != 0 || ms.Pinning != ebpf.PinNone {
			return fmt.Errorf("map %s is %s key %d value %d entries %d flags %d pinning %d; the loader expects %s key %d "+
				"value %d entries %d, no flags, unpinned", name, ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags,
				ms.Pinning, w.typ, w.key, w.value, w.maxEntries)
		}
	}
	for name := range want {
		if spec.Maps[name] == nil {
			return fmt.Errorf("object lacks map %s", name)
		}
	}
	if len(spec.Variables) != 1 {
		return fmt.Errorf("object has %d variables, want only %s", len(spec.Variables), VariableBounds)
	}
	v := spec.Variables[VariableBounds]
	if v == nil || v.Size() != 8*NumBounds || !v.Constant() || v.SectionName != rodataSection {
		return fmt.Errorf("object lacks read-only variable %s of %d bytes", VariableBounds, 8*NumBounds)
	}
	return nil
}

// allowedHelpers are the only helpers the programs may call: access to their own maps, the clock, packet reads and
// the socket cookie. None of them writes a packet, a socket or a syscall result.
var allowedHelpers = map[asm.BuiltinFunc]bool{
	asm.FnMapLookupElem: true, asm.FnMapUpdateElem: true, asm.FnMapDeleteElem: true,
	asm.FnKtimeGetNs: true, asm.FnSkbLoadBytes: true, asm.FnGetSocketCookie: true,
}

// CheckObserveOnly is the static check of ADR-005 on the compiled programs:
//   - every helper call is in allowedHelpers, and there is no BPF-to-BPF call, kfunc call, function pointer, or
//     call or jump of a form the check does not know;
//   - every exit follows "r0 = 1" (the cgroup_skb pass value) and is not a jump target, so no path reaches an exit
//     with another value in r0.
//
// Context writes are checked by the kernel tests, which compare every writable __sk_buff field before and after
// each run, and by TestSourceWritesNoContextField.
func CheckObserveOnly(spec *ebpf.CollectionSpec) error {
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := checkInstructions(spec.Programs[name].Instructions); err != nil {
			return fmt.Errorf("program %s: %w", name, err)
		}
	}
	return nil
}

func checkInstructions(insns asm.Instructions) error {
	// Jump targets and exits are compared as raw instruction offsets, because a 64-bit immediate load takes two.
	targets := map[asm.RawInstructionOffset]bool{}
	type exit struct {
		index int
		at    asm.RawInstructionOffset
	}
	var exits []exit
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		op := ins.OpCode.JumpOp()
		switch {
		case ins.IsFunctionCall(), ins.IsKfuncCall(), ins.IsLoadOfFunctionPointer():
			return fmt.Errorf("instruction %d calls a function: %v", iter.Index, *ins)
		case ins.IsBuiltinCall():
			if fn := asm.BuiltinFunc(ins.Constant); !allowedHelpers[fn] {
				return fmt.Errorf("instruction %d calls helper %s outside the allowlist", iter.Index, fn)
			}
		case op == asm.Exit:
			exits = append(exits, exit{iter.Index, iter.Offset})
		case op == asm.Call, op == asm.InvalidJumpOp && ins.OpCode.Class().IsJump():
			// A call of another form, or an exit or a call of the 32-bit jump class. The kernel refuses both; the check
			// refuses what it cannot classify instead of relying on that.
			return fmt.Errorf("instruction %d is a call or jump the check does not know: %v", iter.Index, *ins)
		case ins.OpCode.Class().IsJump():
			if ins.Reference() != "" {
				// A jump to a label has no offset until the program is assembled. The ELF loader gives every jump of
				// the object its offset, so a label means a program this check cannot follow.
				return fmt.Errorf("instruction %d jumps to label %q, not to an offset", iter.Index, ins.Reference())
			}
			offset := int64(ins.Offset)
			if op == asm.Ja && ins.OpCode.Class() == asm.Jump32Class {
				offset = ins.Constant // gotol: a 32-bit offset in the immediate
			}
			targets[asm.RawInstructionOffset(int64(iter.Offset)+1+offset)] = true
		}
	}
	if len(exits) == 0 {
		return fmt.Errorf("no exit instruction")
	}
	for _, e := range exits {
		if targets[e.at] {
			return fmt.Errorf("exit at instruction %d is a jump target, so r0 is not known there", e.index)
		}
		if e.index == 0 || !isMovR0One(insns[e.index-1]) {
			return fmt.Errorf("exit at instruction %d does not follow r0 = 1", e.index)
		}
	}
	return nil
}

func isMovR0One(ins asm.Instruction) bool {
	return ins.OpCode.Class().IsALU() && ins.OpCode.ALUOp() == asm.Mov && ins.OpCode.Source() == asm.ImmSource &&
		ins.Dst == asm.R0 && ins.Constant == 1
}
