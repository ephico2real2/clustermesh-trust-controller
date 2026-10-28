//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Cilium regenerates an endpoint by replacing the program of its retained
// TCX link in place (BPF_LINK_UPDATE): the link ID and position stay, the
// program ID changes. These tests model that with the fixture's own link.

func passProgram(t *testing.T, name string, at ebpf.AttachType) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, AttachType: at,
		License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func loadedProgramID(t *testing.T, p *ebpf.Program) uint32 {
	t.Helper()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel program ID unavailable")
	}
	return uint32(id)
}

func requireChain(t *testing.T, c Config, want []attachment) {
	t.Helper()
	_, got, err := query(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("chain=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain=%v, want %v", got, want)
		}
	}
}

func TestPrivilegedFollowsCiliumInPlaceProgramUpdate(t *testing.T) {
	elf := requirePrivileged(t)
	for _, direction := range []string{"ingress", "egress"} {
		t.Run(direction, func(t *testing.T) {
			f := directionalFixture(t, direction)
			at, err := f.cfg.attachType()
			if err != nil {
				t.Fatal(err)
			}
			info, err := f.prog.Info()
			if err != nil {
				t.Fatal(err)
			}
			o, err := Open(f.cfg, elf)
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			own := o.expected[0]
			before, err := o.Sample()
			if err != nil {
				t.Fatal(err)
			}

			// Same name, new program on the same link: Cilium's regeneration.
			regenerated := passProgram(t, info.Name, at)
			if err := f.policy.Update(regenerated); err != nil {
				t.Fatalf("in-place TCX link update: %v", err)
			}
			requireChain(t, f.cfg, []attachment{own, {loadedProgramID(t, regenerated), f.cfg.CiliumLinkID}})
			if _, err := o.Sample(); err != nil {
				t.Fatalf("observer stopped on Cilium's in-place update of its frozen link: %v", err)
			}
			if want := (attachment{loadedProgramID(t, regenerated), f.cfg.CiliumLinkID}); o.expected[1] != want {
				t.Fatalf("expected anchor %v, want %v", o.expected[1], want)
			}

			// Counting continues across the update: the observer program is unchanged.
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			from, to := f.peer, f.dev
			if direction == "egress" {
				from, to = f.dev, f.peer
			}
			packet := make([]byte, 64)
			copy(packet[:6], to.Attrs().HardwareAddr)
			copy(packet[6:12], from.Attrs().HardwareAddr)
			packet[12], packet[13] = 0x88, 0xb5
			const sent = 20
			for range sent {
				if err := unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: from.Attrs().Index, Halen: 6}); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				after, err := o.Sample()
				if err != nil {
					t.Fatal(err)
				}
				if after.Packets-before.Packets >= sent && after.Bytes-before.Bytes >= sent*uint64(len(packet)) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("counting stopped after the update: before=%+v after=%+v", before, after)
				}
				time.Sleep(10 * time.Millisecond)
			}

			// A program with another name on the same link is not followed.
			foreign := passProgram(t, "fixture_other", at)
			if err := f.policy.Update(foreign); err != nil {
				t.Fatal(err)
			}
			if _, err := o.Sample(); err == nil {
				t.Fatal("observer followed a replacement program with another name")
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			// Close removes only the observer's own link.
			requireChain(t, f.cfg, []attachment{{loadedProgramID(t, foreign), f.cfg.CiliumLinkID}})
		})
	}
}

func TestPrivilegedReopenAcceptsOnlyTheDirectionsCiliumEndpointProgram(t *testing.T) {
	elf := requirePrivileged(t)
	for _, tc := range []struct{ direction, endpoint, other string }{
		{"ingress", "cil_from_container", "cil_to_container"},
		{"egress", "cil_to_container", "cil_from_container"},
	} {
		t.Run(tc.direction, func(t *testing.T) {
			f := directionalFixture(t, tc.direction)
			at, err := f.cfg.attachType()
			if err != nil {
				t.Fatal(err)
			}
			// The configuration keeps the qualified program ID; Cilium has
			// since regenerated the endpoint on the same link.
			stale := f.cfg

			for _, name := range []string{"cil_fixture_x", tc.other} {
				wrong := passProgram(t, name, at)
				if err := f.policy.Update(wrong); err != nil {
					t.Fatal(err)
				}
				if o, err := Open(stale, elf); err == nil {
					_ = o.Close()
					t.Fatalf("stale program ID accepted for %q on a %s link", name, tc.direction)
				}
				requireChain(t, stale, []attachment{{loadedProgramID(t, wrong), stale.CiliumLinkID}})
			}

			endpoint := passProgram(t, tc.endpoint, at)
			if err := f.policy.Update(endpoint); err != nil {
				t.Fatal(err)
			}
			o, err := Open(stale, elf)
			if err != nil {
				t.Fatalf("restart after Cilium regenerated the frozen link: %v", err)
			}
			if want := (attachment{loadedProgramID(t, endpoint), stale.CiliumLinkID}); o.expected[1] != want {
				t.Fatalf("expected anchor %v, want %v", o.expected[1], want)
			}
			if _, err := o.Sample(); err != nil {
				t.Fatal(err)
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			requireChain(t, stale, []attachment{{loadedProgramID(t, endpoint), stale.CiliumLinkID}})

			// The link stays the authority: a second link that runs a program
			// with the endpoint name, but is not first in the chain, is refused.
			impostor := passProgram(t, tc.endpoint, at)
			extra, err := link.AttachTCX(link.TCXOptions{Interface: stale.IfIndex, Program: impostor,
				Attach: at, Anchor: link.Tail()})
			if err != nil {
				t.Fatal(err)
			}
			defer extra.Close()
			ei, err := extra.Info()
			if err != nil {
				t.Fatal(err)
			}
			wrongLink := stale
			wrongLink.CiliumLinkID = uint32(ei.ID)
			if again, err := Open(wrongLink, elf); err == nil {
				_ = again.Close()
				t.Fatal("a link that is not first in the chain accepted as the Cilium anchor")
			}
			requireChain(t, stale, []attachment{{loadedProgramID(t, endpoint), stale.CiliumLinkID},
				{loadedProgramID(t, impostor), uint32(ei.ID)}})
		})
	}
}
