//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// These tests share the real disposable fixture/ELF/UDP helpers from
// fence_kernel_privileged_test.go. They define no second TestMain. A failed
// private transaction is NEVER cleaned through the production adoption API.
// The owned test veth is deleted and the fixture's private bpffs is unmounted.
func fenceNames(t *testing.T, f *Fence) []string {
	t.Helper()
	entries, err := os.ReadDir(f.fs.path("."))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name()
	}
	return out
}
func TestPrivilegedFenceTransactionFailurePreservesPinsAndDeny(t *testing.T) {
	elf := requireFenceELF(t)
	for _, dir := range []string{"ingress", "egress"} {
		for _, point := range []string{"pinned-accounted", "pinned-program", "pinned-identity", "attached-unpinned", "pinned-link", "committed"} {
			t.Run(dir+"/"+point, func(t *testing.T) {
				fx, seen := installFenceFollower(t, directionalFixture(t, dir))
				cfg := fixtureFenceConfig(t, fx, privateFenceRoot(t))
				wire := newUDPWire(t, fx)
				wire.mustDeliver(t)
				_, before, err := fenceQuery(cfg)
				if err != nil {
					t.Fatal(err)
				}
				injected := errors.New("injected transaction boundary failure")
				f, err := installFence(cfg, elf, func(stage string) error {
					if stage == point {
						return injected
					}
					return nil
				})
				if !errors.Is(err, injected) {
					t.Fatalf("fault did not execute at%s: %v", point, err)
				}
				// Deleting this fixture veth before releasing any unpinned partial link
				// preserves the implementation's ownership rule, including on Fatal.
				t.Cleanup(func() {
					_ = netlink.LinkDel(fx.dev)
					if f != nil {
						if err := f.ReleaseProcess(); err != nil {
							t.Errorf("release after owned device deletion: %v", err)
						}
					}
				})
				attached := point == "attached-unpinned" || point == "pinned-link" || point == "committed"
				if !attached {
					if f != nil {
						t.Fatal("pre-attach failure leaked process handles")
					}
					_, chain, err := fenceQuery(cfg)
					if err != nil || !reflect.DeepEqual(chain, before) {
						t.Fatalf("pre-attach failure changed native chain: %v %+v", err, chain)
					}
					wire.mustDeliver(t)
					if candidate, err := AdoptFence(cfg, elf); err == nil {
						candidate.ReleaseProcess()
						t.Fatal("incomplete pre-attach transaction adopted")
					}
					if candidate, err := InstallFence(cfg, elf); !errors.Is(err, ErrFenceIncomplete) {
						if candidate != nil {
							candidate.ReleaseProcess()
						}
						t.Fatalf("incomplete transaction overwritten: %v", err)
					}
					return
				}
				if f == nil {
					t.Fatal("post-attach error discarded owning FD")
				}
				denyCounter, cloneErr := f.counters.Clone()
				if cloneErr != nil {
					t.Fatal(cloneErr)
				}
				defer denyCounter.Close()
				names := fenceNames(t, f)
				_, chainBefore, err := fenceQuery(cfg)
				if err != nil {
					t.Fatal(err)
				}
				wire.mustDrop(t, denyCounter, seen)
				if candidate, err := AdoptFence(cfg, elf); !errors.Is(err, ErrFenceBusy) {
					if candidate != nil {
						candidate.ReleaseProcess()
					}
					t.Fatalf("live installer lock not exclusive: %v", err)
				}
				if err = RetireDefunctFence(cfg, elf); !errors.Is(err, ErrFenceBusy) {
					t.Fatalf("retirer bypassed process ownership lock: %v", err)
				}
				if !reflect.DeepEqual(fenceNames(t, f), names) {
					t.Fatal("failed concurrent operations changed pins")
				}
				_, after, err := fenceQuery(cfg)
				if err != nil || !reflect.DeepEqual(after, chainBefore) {
					t.Fatalf("failed operation changed deny chain: %v", err)
				}
				wire.mustDrop(t, denyCounter, seen)
				if point == "attached-unpinned" {
					if err = f.ReleaseProcess(); !errors.Is(err, ErrFenceUnpinnedLive) {
						t.Fatalf("closed only live unpinned owning FD: %v", err)
					}
					wire.mustDrop(t, denyCounter, seen)
					return
				}
				if err = f.ReleaseProcess(); err != nil {
					t.Fatal(err)
				}
				wire.mustDrop(t, denyCounter, seen)
				recovered, err := AdoptFence(cfg, elf)
				if point == "committed" {
					if err != nil {
						t.Fatalf("last boundary fault lost committed recovery: %v", err)
					}
					defer recovered.ReleaseProcess()
					if _, err = recovered.Account(); err != nil {
						t.Fatal(err)
					}
				} else {
					if err == nil {
						recovered.ReleaseProcess()
						t.Fatal("missing commit adopted")
					}
					if err = RetireDefunctFence(cfg, elf); err == nil {
						t.Fatal("incomplete live transaction retired")
					}
				}
				wire.mustDrop(t, denyCounter, seen)
			})
		}
	}
}
func replaceFrozenFenceMetadata(t *testing.T, f *Fence, name string, identity bool) {
	t.Helper()
	var value any
	size := 0
	if identity {
		id := f.id
		id.ConfigHash[0] ^= 0xff
		value = id
		size = binary.Size(id)
	} else {
		commit := f.commit
		commit.LinkID++
		value = commit
		size = binary.Size(commit)
	}
	replacement, err := ebpf.NewMap(&ebpf.MapSpec{Name: "cmtc_bad_meta", Type: ebpf.Array, KeySize: 4, ValueSize: uint32(size), MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	// Self-ID is deliberately made internally consistent: adoption must still
	// reject immutable ownership/commit fields, rather than just a stale map ID.
	rid, err := fenceMapID(replacement)
	if err != nil {
		t.Fatal(err)
	}
	switch v := value.(type) {
	case fenceIdentity:
		v.SelfID = rid
		value = v
	case fenceCommit:
		v.SelfID = rid
		value = v
	}
	if err = replacement.Update(uint32(0), value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err = replacement.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(f.fs.path(name)); err != nil {
		t.Fatal(err)
	}
	if err = f.fs.securePin(name, replacement.Pin); err != nil {
		t.Fatal(err)
	}
}
func TestPrivilegedFenceAdoptionAndAccountRejectTamperingWithoutDetach(t *testing.T) {
	elf := requireFenceELF(t)
	for _, which := range []string{"identity", "commit", "extra-pin", "namespace-reuse", "pod-reuse", "interface-reuse", "anchor-reuse"} {
		t.Run(which, func(t *testing.T) {
			fx, seen := installFenceFollower(t, directionalFixture(t, "ingress"))
			cfg := fixtureFenceConfig(t, fx, privateFenceRoot(t))
			wire := newUDPWire(t, fx)
			wire.mustDeliver(t)
			f, err := InstallFence(cfg, elf)
			if err != nil {
				t.Fatal(err)
			}
			denyCounter, cloneErr := f.counters.Clone()
			if cloneErr != nil {
				t.Fatal(cloneErr)
			}
			defer denyCounter.Close()
			t.Cleanup(func() {
				_ = netlink.LinkDel(fx.dev)
				if err := f.ReleaseProcess(); err != nil {
					t.Errorf("release:%v", err)
				}
			})
			_, before, err := fenceQuery(cfg)
			if err != nil {
				t.Fatal(err)
			}
			next := cfg
			switch which {
			case "identity":
				replaceFrozenFenceMetadata(t, f, "identity", true)
			case "commit":
				replaceFrozenFenceMetadata(t, f, "commit", false)
			case "extra-pin":
				clone, cloneErr := f.counters.Clone()
				if cloneErr != nil {
					t.Fatal(cloneErr)
				}
				defer clone.Close()
				if err = f.fs.securePin("foreign", clone.Pin); err != nil {
					t.Fatal(err)
				}
			case "namespace-reuse":
				next.NamespaceUID += "-new"
			case "pod-reuse":
				next.PodUID += "-new"
			case "interface-reuse":
				next.MAC = "02:00:00:00:00:ff"
			case "anchor-reuse":
				next.CiliumProgramID++
			}
			if which == "identity" || which == "commit" || which == "extra-pin" {
				if _, err = f.Account(); err == nil {
					t.Fatal("held old FDs hid pin replacement")
				}
			}
			if err = f.ReleaseProcess(); err != nil {
				t.Fatal(err)
			}
			namesBefore, err := os.ReadDir(cfg.PinRoot + "/" + cfg.key())
			if err != nil {
				t.Fatal(err)
			}
			candidate, adoptErr := AdoptFence(next, elf)
			if adoptErr == nil {
				candidate.ReleaseProcess()
				t.Fatal("tampered or reused workload adopted")
			}
			if err = RetireDefunctFence(next, elf); err == nil {
				t.Fatal("reused or corrupted live fence retired")
			}
			namesAfter, err := os.ReadDir(cfg.PinRoot + "/" + cfg.key())
			if err != nil {
				t.Fatal(err)
			}
			if len(namesBefore) != len(namesAfter) {
				t.Fatal("failed adoption removed pin entries")
			}
			for i := range namesBefore {
				if namesBefore[i].Name() != namesAfter[i].Name() {
					t.Fatal("failed adoption renamed pin entries")
				}
			}
			_, after, err := fenceQuery(cfg)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("failed adoption altered live chain: %v", err)
			}
			wire.mustDrop(t, denyCounter, seen)
		})
	}
}
func TestPrivilegedFenceDoesNotProlongForeignAnchorFD(t *testing.T) {
	elf := requireFenceELF(t)
	fx, _ := installFenceFollower(t, directionalFixture(t, "ingress"))
	cfg := fixtureFenceConfig(t, fx, privateFenceRoot(t))
	f, err := InstallFence(cfg, elf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netlink.LinkDel(fx.dev)
		if err := f.ReleaseProcess(); err != nil {
			t.Errorf("release:%v", err)
		}
	})
	if err = fx.policy.Close(); err != nil {
		t.Fatal(err)
	}
	_, chain, err := fenceQuery(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range chain {
		if entry.Link == cfg.CiliumLinkID {
			t.Fatal("prototype retained foreign unpinned TCX anchor FD")
		}
	}
	if len(chain) != 1 || chain[0].Link != f.commit.LinkID {
		t.Fatalf("own deny lost with foreign reference: %+v", chain)
	}
	if _, err = f.Account(); err == nil {
		t.Fatal("missing anchor incorrectly remained ready")
	}
}
