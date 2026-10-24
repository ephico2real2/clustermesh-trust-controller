# Cursor persistent fence implementation proposal

Model: Grok 4.7 Extra High. Still subject to primary source review and local qualification.

The next slice is a first-packet fence, so I’m reading the restore path, the observer, and the CNI intent admission before proposing any kernel change.The persistent deny slice is a separate, pinned TCX program. It is not the observer, and it is not a Cilium policy change. The native endpoint programs already survive an agent restart, and they do not read a new guard map, so this slice does not claim to close that window.

# Persistent first-packet fence

Status: proposal only. Not applied, not compiled, and not run. The ClusterMesh guard stays closed. Nothing here is Protected, mTLS, or a packet fence on `cmtc-a` or `cmtc-b`.

## Source-backed facts

The observer at CMTC `b193510f206a8655a3f9c240728b71b0427a5b31` is `TCX_NEXT` only. `internal/datapath/bpf/observer.c` counts packets and bytes, then returns. `Open` in `internal/datapath/observer_linux.go` holds the foreign Cilium link only for the attach, then closes that FD. Its own link is process-owned. SIGKILL removes it. That is correct for observation and is not a fail-closed fence. The unprivileged Observe DaemonSet is a different workload from the experimental privileged observer DaemonSet. This proposal does not change either one.

Cilium `8b01a7c95440f6db398a87bdac2136d36711d23f` pins endpoint TCX links and then closes the process FD. `attachTCX` in `pkg/datapath/loader/tcx.go` comments that closing a pinned link does not detach it. `attachSKBProgram` uses that path for `cil_from_container` on ingress and `cil_to_container` on egress (`pkg/datapath/loader/endpoint.go`). Netkit devices take the netkit loader instead. Legacy TC remains the fallback when TCX returns `link.ErrNotSupported`. Those attached programs do not consult a CMTC map. Restarting the agent does not remove them.

`daemon/cmd/endpoint_restore.go` does not stop those programs:

- `OnStart` reads endpoint state, logs a read error, and still returns nil. It then calls `RestorationNotify` with no error return, before Kubernetes sync.
- `RestoreOldEndpoints` validates a Pod by namespace, name, and node name in `getPodForEndpoint`. It does not compare `pod.UID` with `ep.K8sUID`.
- The on-disk endpoint record has `K8sNamespace`, `K8sPodName`, and `K8sUID`. It has no namespace UID field (`pkg/endpoint/restore.go`).
- `regenerateRestoredEndpoints` inserts endpoints into the manager before regeneration. Regeneration runs later. `InitRestore` closes `endpointRestoreComplete` after starting that work, not after it succeeds.
- `handleRestoredEndpointsRegeneration` logs a regeneration error at debug level and still closes `endpointRegenerateComplete`.

`pkg/ztunnel/admission/required_recorder.go` states that the recorder persists intent and does not install a kernel fence. `gate.once` in `pkg/ztunnel/admission/cell.go` commits that journal and enrolls the sandbox before `WaitForEndpoint` returns. CNI success is therefore not evidence that a program which can drop is attached. The endpoint loader itself says an unclean death after the policy-map insert and before attachment leaves partial connectivity (`endpoint.go`).

Ztunnel `1db4fb296beb4ca4c6c12762c61d1730dc38ceab` is the qualified issuer helper only. It is not wired to live TLS, CRL, SPIRE, policy, or pools. The earlier full integration proposal stays unaccepted. This document does not change it. Native policy AND semantics, authoritative withdrawal, and socket cancellation remain requirements for that separate slice.

The deployed labs are still Observe. The agent is the `8b01a7c` overlay on baseline BPF/CNI. The proxy image is imported and version-tested, not an active DaemonSet. There is no node encryption.

## Unknowns

The namespace-UID patch in `/private/tmp/cmtc-cilium-namespace-uid` was not applied here and was not treated as authorization. Whether a deleted host veth’s TCX link always becomes `ENOLINK` before its ifindex is reused was not executed. `BPF_PROG_TEST_RUN` for this ELF supplies ifindex 0; the wire tests are what carry the real device index. Traffic that never crosses the selected host veth is outside this attachment.

## Why a map or a journal cannot close the current window

A userspace flag, a restore callback error, the Required journal, and a new BPF map share one limit: `cil_from_container` and `cil_to_container` do not read them. Packets keep taking the pinned program’s existing path. The window closes only when a program that is actually attached returns drop, or when that attachment is replaced by a new program ID that fails closed. An agent restart is not that replacement.

## Two shapes

The lab shape below is a separate opt-in CMTC process. It pins its own TCX program immediately before the audited Cilium link and returns `TC_ACT_SHOT` (2) unless a test writer arms a lease. `TCX_NEXT` (-1) is the only pass, so the following program still runs. Production code never arms a lease. `Adopt` rewrites any lease back to deny. There is no grant flag, label, ACK, or certificate string.

That shape is temporary. It is a second hook in front of Cilium, not a second connection tracker, NAT, or policy engine. It does not look at ports. It must be removed after, and only after, the native program ID on that veth is a build that reads the guard.

The native shape is not coded. It belongs in `cil_from_container` and `cil_to_container`, loaded by the existing endpoint loader and pinned with `attachTCX`. The new instructions must fail closed on a missing, malformed, expired, or non-matching guard record before policy tail calls. Rollout is per link: read back the program ID from the TCX query and do not treat the node as covered while any enrolled veth still shows the old ID. CNI `WaitForEndpoint` must wait for that ID check. It must not return when the journal commit finishes. Restore must not report completion because a log line was written. Health and ingress endpoints, `cilium_host`, `cilium_net`, and the encryption/overlay devices stay out of the workload hook. Legacy TC and netkit stay unsupported until their own attach paths are changed; this slice refuses them instead of falling back.

Retire the lab hook only after that native ID check passes. Removing it earlier reopens the old program.

## Smallest slice

New files only. The observer C, loader, and unprivileged Observe DaemonSet stay as they are.

| Path | Role |
|---|---|
| `internal/datapath/bpf/fence.c` | Deny-by-default TCX program. |
| `internal/datapath/fence_linux.go` | Pin, adopt, retire. No grant API. |
| `internal/datapath/fence_linux_test.go` | Config and map-value checks. Not a kernel fence. |
| `internal/datapath/fence_privileged_linux_test.go` | Verifier, both directions, crash, reuse, follower. |
| `cmd/cmtc-bpf-fence/main.go` | Hold, adopt, or retire. No allow flag. |
| `config/experimental/datapath-fence.yaml` | Opt-in manifest. Not referenced by default provisioning and not applied. |

`Install` writes the deny record before attach. The pass path exists so a test can prove the program reads the map and then returns `TCX_NEXT`. A program that ignored the map and always dropped would fail that test. `Adopt` deletes a pass record on the next start, so a killed test process cannot leave a grant for the daemon.

### `internal/datapath/bpf/fence.c`

```c
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Deny unless binding and decision agree. No port match and no packet rewrite.
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
};
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define TC_ACT_SHOT 2
#define TCX_NEXT (-1)
struct binding { __u32 ifindex; __u32 pad; __u64 generation; };
struct decision { __u32 verdict; __u32 pad; __u64 expires_ns; __u64 generation; };
struct counters { __u64 packets; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct binding);
} binding SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct decision);
} guard SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct counters);
} accounted SEC(".maps");
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)5;
static void account(struct __sk_buff *skb, __u32 key)
{
    struct counters *c = bpf_map_lookup_elem(&accounted, &key);
    if (c) {
        __sync_fetch_and_add(&c->packets, 1);
        __sync_fetch_and_add(&c->bytes, skb->len);
    }
}
SEC("tcx/ingress")
int cmtc_fence(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct binding *b = bpf_map_lookup_elem(&binding, &key);
    struct decision *d = bpf_map_lookup_elem(&guard, &key);
    __u64 now = bpf_ktime_get_ns();
    if (b && d && b->generation != 0 && b->generation == d->generation &&
        b->ifindex == skb->ifindex && d->verdict == 1 && d->expires_ns != 0 &&
        now < d->expires_ns) {
        account(skb, 1);
        return TCX_NEXT;
    }
    account(skb, 0);
    return TC_ACT_SHOT;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

### `internal/datapath/fence_linux.go`

```go
//go:build linux

package datapath

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const bpfFilesystemMagic int64 = 0xcafe4a11

var (
	ErrClosed      = errors.New("fence is closed")
	ErrNotInstalled = errors.New("fence pin is not installed")
	ErrIncarnation = errors.New("fence incarnation does not match the device")
	ErrReserved    = errors.New("platform, host, health, or control device")
)

type FenceConfig struct {
	Cluster         string `json:"cluster"`
	Node            string `json:"node"`
	PodUID          string `json:"podUID"`
	NetNSInode      uint64 `json:"netNSInode"`
	IfIndex         int    `json:"ifIndex"`
	IfName          string `json:"ifName"`
	MAC             string `json:"mac"`
	PeerIfIndex     int    `json:"peerIfIndex"`
	Direction       string `json:"direction"`
	CiliumLinkID    uint32 `json:"ciliumLinkID"`
	CiliumProgramID uint32 `json:"ciliumProgramID"`
	PinRoot         string `json:"pinRoot"`
}

type Binding struct {
	Ifindex    uint32
	Pad        uint32
	Generation uint64
}

type Decision struct {
	Verdict    uint32
	Pad        uint32
	ExpiresNs  uint64
	Generation uint64
}

type FenceCount struct {
	DroppedPackets uint64
	DroppedBytes   uint64
	PassedPackets  uint64
	PassedBytes    uint64
}

type pinIdentity struct {
	FenceConfig
	Generation uint64 `json:"generation"`
}

type Fence struct {
	mu         sync.Mutex
	cfg        FenceConfig
	dir        string
	ns         *os.File
	nl         *netlink.Handle
	coll       *ebpf.Collection
	link       link.Link
	generation uint64
	expected   []attachment
	cpus       int
	released   bool
	retired    bool
}

func (c FenceConfig) attachType() (ebpf.AttachType, error) {
	switch c.Direction {
	case "ingress":
		return ebpf.AttachTCXIngress, nil
	case "egress":
		return ebpf.AttachTCXEgress, nil
	default:
		return 0, errors.New("direction must be ingress or egress")
	}
}

func ReservedDevice(name string) bool {
	switch name {
	case "cilium_host", "cilium_net", "cilium_vxlan", "cilium_geneve", "cilium_wg0":
		return true
	}
	return strings.HasPrefix(name, "cilium_")
}

func (c FenceConfig) Validate() error {
	if c.Cluster == "" || c.Node == "" || c.PodUID == "" || c.NetNSInode == 0 ||
		c.IfIndex <= 0 || c.IfName == "" || c.MAC == "" || c.PeerIfIndex <= 0 ||
		c.CiliumLinkID == 0 || c.CiliumProgramID == 0 || c.PinRoot == "" {
		return errors.New("cluster, node, Pod UID, namespace, device, Cilium anchor, and pin root are required")
	}
	if strings.Contains(c.PodUID, "/") || strings.Contains(c.PodUID, "..") || len(c.PodUID) > 128 {
		return errors.New("Pod UID cannot shape a path")
	}
	if len(c.IfName) >= unix.IFNAMSIZ || strings.ContainsAny(c.IfName, "/\x00") || ReservedDevice(c.IfName) {
		return ErrReserved
	}
	mac, err := net.ParseMAC(c.MAC)
	if err != nil || len(mac) != 6 || mac.String() != c.MAC {
		return errors.New("canonical six-byte MAC required")
	}
	if _, err = c.attachType(); err != nil {
		return err
	}
	clean := filepath.Clean(c.PinRoot)
	if !filepath.IsAbs(clean) || clean == "/sys/fs/bpf" || strings.HasPrefix(clean, "/sys/fs/bpf/cilium") {
		return errors.New("pin root must be a private BPF filesystem outside Cilium's pin tree")
	}
	return nil
}

func (c FenceConfig) pinDir() (string, error) {
	sum := sha256.Sum256([]byte(c.PodUID + "\x00" + c.Direction))
	return filepath.Join(filepath.Clean(c.PinRoot), hex.EncodeToString(sum[:8])), nil
}

func requireBPFFilesystem(root string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(root, &st); err != nil {
		return err
	}
	if int64(st.Type) != bpfFilesystemMagic {
		return errors.New("pin root is not a BPF filesystem")
	}
	return nil
}

func (f *Fence) checkNamespace() error {
	cur, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer cur.Close()
	got, err := inode(cur)
	if err != nil {
		return err
	}
	if got != f.cfg.NetNSInode {
		return fmt.Errorf("network namespace mismatch: got %d", got)
	}
	held, err := inode(f.ns)
	if err != nil {
		return err
	}
	if held != got {
		return errors.New("held namespace changed")
	}
	return nil
}

func (f *Fence) checkDevice() error {
	if err := f.checkNamespace(); err != nil {
		return err
	}
	dev, err := f.nl.LinkByIndex(f.cfg.IfIndex)
	if err != nil {
		return err
	}
	a := dev.Attrs()
	if dev.Type() != "veth" || a.Name != f.cfg.IfName || a.HardwareAddr.String() != f.cfg.MAC ||
		a.ParentIndex != f.cfg.PeerIfIndex || ReservedDevice(a.Name) {
		return ErrIncarnation
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		fs, err := f.nl.FilterList(dev, parent)
		if err != nil {
			return fmt.Errorf("legacy TC inspection: %w", err)
		}
		if len(fs) != 0 {
			return errors.New("legacy TC filters present; no fallback")
		}
	}
	return nil
}

func monotonic() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func (f *Fence) writeMaps(binding Binding, decision Decision) error {
	if err := f.coll.Maps["binding"].Update(uint32(0), binding, ebpf.UpdateAny); err != nil {
		return err
	}
	return f.coll.Maps["guard"].Update(uint32(0), decision, ebpf.UpdateAny)
}

func (f *Fence) persistIdentity() error {
	body, err := json.Marshal(pinIdentity{FenceConfig: f.cfg, Generation: f.generation})
	if err != nil {
		return err
	}
	path := filepath.Join(f.dir, "identity.json")
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(f.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Install(c FenceConfig, elf []byte) (_ *Fence, retErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := requireBPFFilesystem(c.PinRoot); err != nil {
		return nil, err
	}
	dir, err := c.pinDir()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, "link")); err == nil {
		return nil, errors.New("fence pin already exists; adopt or retire it")
	}
	f := &Fence{cfg: c, dir: dir}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, f.Retire())
		}
	}()
	f.ns, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	f.nl, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = f.nl.SetSocketTimeout(2 * time.Second); err != nil {
		return nil, err
	}
	if err = f.checkDevice(); err != nil {
		return nil, err
	}
	anchor, err := link.NewFromID(link.ID(c.CiliumLinkID))
	if err != nil {
		return nil, err
	}
	defer anchor.Close()
	info, err := anchor.Info()
	if err != nil {
		return nil, err
	}
	at, _ := c.attachType()
	tx := info.TCX()
	if tx == nil || tx.Ifindex != uint32(c.IfIndex) || uint32(tx.AttachType) != uint32(at) ||
		uint32(info.Program) != c.CiliumProgramID {
		return nil, errors.New("Cilium anchor does not match device, direction, and program")
	}
	prog, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return nil, err
	}
	pi, infoErr := prog.Info()
	_ = prog.Close()
	if infoErr != nil {
		return nil, infoErr
	}
	if !strings.HasPrefix(pi.Name, "cil_") {
		return nil, errors.New("anchor name is not a Cilium entry program")
	}
	q, before, err := query(Config{IfIndex: c.IfIndex, Direction: c.Direction})
	if err != nil {
		return nil, err
	}
	if len(before) == 0 || before[0] != (attachment{c.CiliumProgramID, c.CiliumLinkID}) {
		return nil, errors.New("Cilium link is not first in the TCX chain")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, err
	}
	ps := spec.Programs["cmtc_fence"]
	if ps == nil || spec.Maps["binding"] == nil || spec.Maps["guard"] == nil || spec.Maps["accounted"] == nil {
		return nil, errors.New("fence ELF is missing its program or maps")
	}
	ps.AttachType = at
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("verifier rejected fence: %w", err)
	}
	f.generation = 1
	if err = f.writeMaps(Binding{Ifindex: uint32(c.IfIndex), Generation: f.generation}, Decision{}); err != nil {
		return nil, err
	}
	owned := f.coll.Programs["cmtc_fence"]
	f.link, err = link.AttachTCX(link.TCXOptions{
		Interface: c.IfIndex, Program: owned, Attach: at,
		Anchor: link.BeforeLink(anchor), ExpectedRevision: q.Revision,
	})
	if err != nil {
		return nil, fmt.Errorf("attach before exact Cilium link: %w", err)
	}
	if err = f.coll.Maps["binding"].Pin(filepath.Join(dir, "binding")); err != nil {
		return nil, err
	}
	if err = f.coll.Maps["guard"].Pin(filepath.Join(dir, "guard")); err != nil {
		return nil, err
	}
	if err = f.coll.Maps["accounted"].Pin(filepath.Join(dir, "accounted")); err != nil {
		return nil, err
	}
	if err = f.link.Pin(filepath.Join(dir, "link")); err != nil {
		return nil, err
	}
	if err = f.persistIdentity(); err != nil {
		return nil, err
	}
	li, err := f.link.Info()
	if err != nil {
		return nil, err
	}
	f.expected = append([]attachment{{uint32(li.Program), uint32(li.ID)}}, before...)
	f.cpus, err = ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if err = f.verify(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Fence) verify() error {
	if f.retired {
		return ErrClosed
	}
	if f.released {
		return nil
	}
	if err := f.checkDevice(); err != nil {
		return err
	}
	_, now, err := query(Config{IfIndex: f.cfg.IfIndex, Direction: f.cfg.Direction})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(f.expected, now) {
		return errors.New("TCX chain changed")
	}
	return nil
}

func (f *Fence) Account() (FenceCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.verify(); err != nil {
		return FenceCount{}, err
	}
	return readAccount(f.coll.Maps["accounted"], f.cpus)
}

func readAccount(m *ebpf.Map, cpus int) (FenceCount, error) {
	var out FenceCount
	for key, dst := range map[uint32]*struct{ p, b *uint64 }{
		0: {&out.DroppedPackets, &out.DroppedBytes},
		1: {&out.PassedPackets, &out.PassedBytes},
	} {
		values := make([]struct{ Packets, Bytes uint64 }, cpus)
		if err := m.Lookup(key, &values); err != nil {
			return FenceCount{}, err
		}
		for _, v := range values {
			*dst.p += v.Packets
			*dst.b += v.Bytes
		}
	}
	return out, nil
}

// setLease is reachable only by tests in this package. Install and Adopt write a zero decision.
func (f *Fence) setLease(verdict uint32, expiresNs uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.verify(); err != nil {
		return err
	}
	return f.writeMaps(Binding{Ifindex: uint32(f.cfg.IfIndex), Generation: f.generation},
		Decision{Verdict: verdict, ExpiresNs: expiresNs, Generation: f.generation})
}

func (f *Fence) ReleaseProcess() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = true
	var err error
	if f.link != nil {
		err = f.link.Close()
		f.link = nil
	}
	if f.coll != nil {
		f.coll.Close()
		f.coll = nil
	}
	if f.nl != nil {
		f.nl.Close()
		f.nl = nil
	}
	if f.ns != nil {
		err = errors.Join(err, f.ns.Close())
		f.ns = nil
	}
	return err
}

func loadIdentity(dir string) (pinIdentity, error) {
	body, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return pinIdentity{}, err
	}
	var id pinIdentity
	if err := json.Unmarshal(body, &id); err != nil {
		return pinIdentity{}, err
	}
	return id, nil
}

func Adopt(c FenceConfig) (*Fence, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	dir, err := c.pinDir()
	if err != nil {
		return nil, err
	}
	id, err := loadIdentity(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, err
	}
	if id.PodUID != c.PodUID || id.Direction != c.Direction || id.NetNSInode != c.NetNSInode ||
		id.IfIndex != c.IfIndex || id.IfName != c.IfName || id.MAC != c.MAC ||
		id.PeerIfIndex != c.PeerIfIndex || id.Generation == 0 {
		_ = retireDir(dir)
		return nil, ErrIncarnation
	}
	f := &Fence{cfg: c, dir: dir, generation: id.Generation}
	f.ns, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	f.nl, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = f.checkDevice(); err != nil {
		_ = f.Retire()
		return nil, ErrIncarnation
	}
	f.link, err = link.LoadPinnedLink(filepath.Join(dir, "link"), nil)
	if err != nil {
		_ = f.Retire()
		return nil, err
	}
	info, err := f.link.Info()
	if err != nil {
		_ = f.Retire()
		return nil, err
	}
	tx := info.TCX()
	at, _ := c.attachType()
	if tx == nil || tx.Ifindex != uint32(c.IfIndex) || uint32(tx.AttachType) != uint32(at) {
		_ = f.Retire()
		return nil, ErrIncarnation
	}
	f.coll, err = ebpf.NewCollectionWithOptions(&ebpf.CollectionSpec{}, ebpf.CollectionOptions{})
	if f.coll != nil {
		f.coll.Close()
	}
	guard, err := ebpf.LoadPinnedMap(filepath.Join(dir, "guard"), nil)
	if err != nil {
		_ = f.Retire()
		return nil, err
	}
	binding, err := ebpf.LoadPinnedMap(filepath.Join(dir, "binding"), nil)
	if err != nil {
		_ = guard.Close()
		_ = f.Retire()
		return nil, err
	}
	accounted, err := ebpf.LoadPinnedMap(filepath.Join(dir, "accounted"), nil)
	if err != nil {
		_ = binding.Close()
		_ = guard.Close()
		_ = f.Retire()
		return nil, err
	}
	f.coll = &ebpf.Collection{Maps: map[string]*ebpf.Map{
		"guard": guard, "binding": binding, "accounted": accounted,
	}}
	if err = f.writeMaps(Binding{Ifindex: uint32(c.IfIndex), Generation: f.generation}, Decision{}); err != nil {
		_ = f.Retire()
		return nil, err
	}
	f.cpus, err = ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	return f, nil
}

func retireDir(dir string) error {
	var err error
	if pinned, loadErr := link.LoadPinnedLink(filepath.Join(dir, "link"), nil); loadErr == nil {
		err = pinned.Unpin()
		err = errors.Join(err, pinned.Close())
	}
	for _, name := range []string{"link", "guard", "binding", "accounted", "identity.json"} {
		err = errors.Join(err, os.Remove(filepath.Join(dir, name)))
	}
	err = errors.Join(err, os.Remove(dir))
	return err
}

func (f *Fence) Retire() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired {
		return nil
	}
	f.retired = true
	err := f.ReleaseProcess()
	if f.dir != "" {
		err = errors.Join(err, retireDir(f.dir))
	}
	return err
}
```

`Adopt` as written constructs a collection incorrectly. Use this body from the `guard, err :=` line through the successful return instead. It keeps the three pinned maps without `NewCollectionWithOptions`:

```go
	guard, err := ebpf.LoadPinnedMap(filepath.Join(dir, "guard"), nil)
	if err != nil {
		_ = f.Retire()
		return nil, err
	}
	binding, err := ebpf.LoadPinnedMap(filepath.Join(dir, "binding"), nil)
	if err != nil {
		_ = guard.Close()
		_ = f.Retire()
		return nil, err
	}
	accounted, err := ebpf.LoadPinnedMap(filepath.Join(dir, "accounted"), nil)
	if err != nil {
		_ = binding.Close()
		_ = guard.Close()
		_ = f.Retire()
		return nil, err
	}
	f.coll = &ebpf.Collection{Maps: map[string]*ebpf.Map{
		"guard": guard, "binding": binding, "accounted": accounted,
	}}
	if err = f.writeMaps(Binding{Ifindex: uint32(c.IfIndex), Generation: f.generation}, Decision{}); err != nil {
		_ = f.Retire()
		return nil, err
	}
	f.cpus, err = ebpf.PossibleCPU()
	if err != nil {
		_ = f.Retire()
		return nil, err
	}
	return f, nil
```

`Retire` calls `ReleaseProcess` while holding `f.mu`, and `ReleaseProcess` also locks it. That deadlocks. `Retire` must close the FDs inline and then call `retireDir`. Replace `Retire` with:

```go
func (f *Fence) Retire() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired {
		return nil
	}
	f.retired = true
	f.released = true
	var err error
	if f.link != nil {
		err = f.link.Close()
		f.link = nil
	}
	if f.coll != nil {
		f.coll.Close()
		f.coll = nil
	}
	if f.nl != nil {
		f.nl.Close()
		f.nl = nil
	}
	if f.ns != nil {
		err = errors.Join(err, f.ns.Close())
		f.ns = nil
	}
	if f.dir != "" {
		err = errors.Join(err, retireDir(f.dir))
	}
	return err
}
```

`query` in `Install` passes a partial `Config`. That function is the observer helper and requires the full observer config for `attachType`, but `query` itself only reads `IfIndex` and `Direction`. That coupling is accidental. Add this private helper to `fence_linux.go` and call it instead of `query`:

```go
func queryFence(index int, direction string) (*link.QueryResult, []attachment, error) {
	c := Config{IfIndex: index, Direction: direction, Cluster: "x", Node: "x", PodUID: "x",
		NetNSInode: 1, IfName: "x", MAC: "02:00:00:00:00:01", PeerIfIndex: 1,
		CiliumLinkID: 1, CiliumProgramID: 1}
	return query(c)
}
```

The dummy fields are only enough for `attachType`. `query` does not validate them. This still uses the observer’s chain reader, which is the same TCX query the observer already qualifies. It does not attach the observer.

### `internal/datapath/fence_linux_test.go`

```go
//go:build linux

package datapath

import "testing"

func TestFenceRejectsPlatformDevicesAndCiliumPins(t *testing.T) {
	base := FenceConfig{Cluster: "c", Node: "n", PodUID: "pod-1", NetNSInode: 1,
		IfIndex: 2, IfName: "cfh1", MAC: "02:00:00:00:00:01", PeerIfIndex: 3,
		Direction: "ingress", CiliumLinkID: 4, CiliumProgramID: 5, PinRoot: "/run/cmtc-fence"}
	for _, name := range []string{"cilium_host", "cilium_net", "cilium_health"} {
		c := base
		c.IfName = name
		if err := c.Validate(); err != ErrReserved {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, root := range []string{"/sys/fs/bpf", "/sys/fs/bpf/cilium/links", "relative"} {
		c := base
		c.PinRoot = root
		if err := c.Validate(); err == nil {
			t.Fatal(root)
		}
	}
	if Decision{} != (Decision{}) || (Decision{}).Verdict != 0 || (Decision{}).ExpiresNs != 0 {
		t.Fatal("zero decision must be deny")
	}
}
```

These checks do not establish a kernel fence.

### `internal/datapath/fence_privileged_linux_test.go`

```go
//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if os.Getenv("CMTC_FENCE_CHILD") == "1" {
		var c FenceConfig
		if err := json.Unmarshal([]byte(os.Getenv("CMTC_FENCE_CONFIG")), &c); err != nil {
			os.Exit(2)
		}
		elf, err := os.ReadFile(os.Getenv("CMTC_BPF_ELF"))
		if err != nil {
			os.Exit(2)
		}
		f, err := Install(c, elf)
		if err != nil {
			os.Exit(3)
		}
		if err := f.ReleaseProcess(); err != nil {
			os.Exit(4)
		}
		select {}
	}
	os.Exit(m.Run())
}

func mountPrivateBPF(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CMTC_BPF_TEST_PRIVATE_NETNS") != "1" {
		t.Fatal("root in a private container network namespace is required")
	}
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	return dir
}

func follower(t *testing.T, attach ebpf.AttachType) (*ebpf.Map, *ebpf.Program, link.Link, int) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, Name: "cil_seen", KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cil_fixture", Type: ebpf.SchedCLS, AttachType: attach,
		License: "GPL", Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()), asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -4),
			asm.StoreImm(asm.R2, 0, 0, asm.Word), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"), asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("out"), asm.Return(),
		}})
	if err != nil {
		t.Fatalf("follower verifier: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return m, prog, nil, 0
}

func TestPrivilegedFenceDenyPassCrashAndReuse(t *testing.T) {
	elf := requirePrivileged(t)
	root := mountPrivateBPF(t)
	for _, direction := range []string{"ingress", "egress"} {
		f := newFixture(t)
		f.cfg.Direction = direction
		f.cfg.PinRoot = root
		at, err := f.cfg.attachType()
		if err != nil {
			t.Fatal(err)
		}
		seen, prog, _, _ := follower(t, at)
		fl, err := link.AttachTCX(link.TCXOptions{Interface: f.cfg.IfIndex, Program: prog, Attach: at, Anchor: link.Tail()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fl.Close() })
		info, err := fl.Info()
		if err != nil {
			t.Fatal(err)
		}
		f.cfg.CiliumLinkID = uint32(info.ID)
		f.cfg.CiliumProgramID = uint32(info.Program)
		fence, err := Install(f.cfg, elf)
		if err != nil {
			t.Fatal(err)
		}
		send := f.peer.Attrs().Index
		if direction == "egress" {
			send = f.cfg.IfIndex
		}
		before, err := fence.Account()
		if err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 64)
		packet[12], packet[13] = 0x88, 0xb5
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		after, err := fence.Account()
		if err != nil || after.DroppedPackets <= before.DroppedPackets || after.PassedPackets != before.PassedPackets {
			t.Fatalf("deny did not account a drop: before=%+v after=%+v err=%v", before, after, err)
		}
		var seenCount uint64
		if err = seen.Lookup(uint32(0), &seenCount); err != nil || seenCount != 0 {
			t.Fatalf("follower saw a denied packet: %d %v", seenCount, err)
		}
		now, err := monotonic()
		if err != nil {
			t.Fatal(err)
		}
		if err = fence.setLease(1, now+uint64(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		passed, err := fence.Account()
		if err != nil || passed.PassedPackets <= after.PassedPackets {
			t.Fatalf("lease did not pass: %+v %v", passed, err)
		}
		if err = seen.Lookup(uint32(0), &seenCount); err != nil || seenCount == 0 {
			t.Fatalf("following program did not run on TCX_NEXT: %d %v", seenCount, err)
		}
		if err = fence.setLease(1, 1); err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		expired, err := fence.Account()
		if err != nil || expired.DroppedPackets <= passed.DroppedPackets || expired.PassedPackets != passed.PassedPackets {
			t.Fatalf("expired lease still passed: %+v %+v %v", passed, expired, err)
		}
		if err = fence.setLease(9, now+uint64(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		malformed, err := fence.Account()
		if err != nil || malformed.PassedPackets != expired.PassedPackets {
			t.Fatalf("malformed verdict passed: %+v", malformed)
		}
		_ = unix.Close(fd)
		if err = fence.ReleaseProcess(); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(f.cfg)
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), "CMTC_FENCE_CHILD=1", "CMTC_FENCE_CONFIG="+string(body))
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if err = child.Process.Signal(os.Kill); err != nil {
			t.Fatal(err)
		}
		_, _ = child.Process.Wait()
		_, chain, err := queryFence(f.cfg.IfIndex, direction)
		if err != nil || len(chain) == 0 {
			t.Fatalf("pinned program disappeared on process death: %v %v", chain, err)
		}
		adopted, err := Adopt(f.cfg)
		if err != nil {
			t.Fatal(err)
		}
		cleared, err := adopted.Account()
		if err != nil {
			t.Fatal(err)
		}
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send, Halen: 6}); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		deniedAgain, err := adopted.Account()
		if err != nil || deniedAgain.PassedPackets != cleared.PassedPackets {
			t.Fatalf("adopt preserved a pass: %+v %+v", cleared, deniedAgain)
		}
		old := f.cfg
		if err = netlink.LinkSetHardwareAddr(f.dev, []byte{0x02, 0, 0, 0, 0, 0x22}); err != nil {
			t.Fatal(err)
		}
		if _, err = Adopt(old); err != ErrIncarnation {
			t.Fatalf("changed MAC adopted: %v", err)
		}
		_, chain, err = queryFence(old.IfIndex, direction)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range chain {
			prog, openErr := ebpf.NewProgramFromID(ebpf.ProgramID(item.Program))
			if openErr != nil {
				continue
			}
			pi, _ := prog.Info()
			_ = prog.Close()
			if pi != nil && pi.Name == "cmtc_fence" {
				t.Fatal("mismatched incarnation kept the fence program")
			}
		}
	}
}
```

`newFixture` currently forces ingress and its own Cilium fixture. The test above overwrites direction and replaces the anchor with `cil_fixture`. `newFixture` still creates the veth and namespace inode. Its original policy link must be closed before attaching the follower, or the chain will not have the follower first. Add this immediately after `f := newFixture(t)`:

```go
		if err := f.policy.Close(); err != nil {
			t.Fatal(err)
		}
```

The child process also calls `Install` on a pin that the parent already created. That is only a crash vehicle: start it after `ReleaseProcess`, and change the child to `Adopt`, not `Install`. Use this child branch in `TestMain`:

```go
		f, err := Adopt(c)
		if err != nil {
			os.Exit(3)
		}
		if err := f.ReleaseProcess(); err != nil {
			os.Exit(4)
		}
		select {}
```

The parent’s `Install` creates the pin. The child adopts it, drops its FDs, and is killed. The parent then checks that the TCX query still contains the link. `Adopt` in the parent after the kill rewrites the decision to deny.

`Account` after `ReleaseProcess` is not valid on the old object because `verify` returns nil when `released` is set but the collection is closed. The parent must `Adopt` before calling `Account` for the post-kill packet. Move the post-kill packet send to after that `Adopt`. The chain query between kill and `Adopt` is the persistence assertion.

One privileged test cannot also prove a fresh verifier load without attachment. Add this beside it:

```go
func TestPrivilegedVerifierDefaultIsShot(t *testing.T) {
	elf := requirePrivileged(t)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("verifier rejected fence: %v", err)
	}
	defer coll.Close()
	packet := make([]byte, 64)
	packet[12], packet[13] = 0x08, 0x00
	action, out, err := coll.Programs["cmtc_fence"].Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	if action != 2 || !bytes.Equal(packet, out) {
		t.Fatalf("default action=%d, want TC_ACT_SHOT without rewrite", action)
	}
	other := make([]byte, 64)
	other[12], other[13] = 0x86, 0xdd
	action, _, err = coll.Programs["cmtc_fence"].Test(other)
	if err != nil || action != 2 {
		t.Fatalf("different ethertype action=%d err=%v", action, err)
	}
}
```

Add `"bytes"` to the privileged file imports. The two ethertypes are the stand-in for “no application port list”: both are shot, and neither packet is rewritten.

Reserved-name and legacy-filter cases belong in the same privileged file and follow the observer’s existing pattern: build a veth named `cilium_host` only inside the private namespace, expect `Install` to return `ErrReserved`, and leave the chain unchanged. A `clsact` plus one owned BPF filter must make `Install` fail and leave both the TCX chain and that filter in place. A `dummy` device must fail `ErrIncarnation` because its type is not `veth`. Those three are required copies of the observer’s refusal tests; they are not new behavior beyond the checks in `checkDevice` and `Validate`.

### `cmd/cmtc-bpf-fence/main.go`

```go
//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	ctrl "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	ctrl.SetLogger(zap.New())
	configPath := flag.String("config", "", "immutable fence config")
	elfPath := flag.String("elf", "", "compiled fence ELF")
	retire := flag.Bool("retire", false, "detach this incarnation and remove its private pins")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "config is required")
		os.Exit(2)
	}
	body, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var cfg datapath.FenceConfig
	if err = json.Unmarshal(body, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *retire {
		f, adoptErr := datapath.Adopt(cfg)
		if adoptErr != nil && !errors.Is(adoptErr, datapath.ErrNotInstalled) {
			fmt.Fprintln(os.Stderr, adoptErr)
			os.Exit(1)
		}
		if f != nil {
			if err = f.Retire(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	f, err := datapath.Adopt(cfg)
	if errors.Is(err, datapath.ErrNotInstalled) {
		elf, readErr := os.ReadFile(*elfPath)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, readErr)
			os.Exit(1)
		}
		f, err = datapath.Install(cfg, elf)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.ReleaseProcess()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
}
```

SIGTERM closes process FDs and leaves the pin. It does not retire. `--retire` is the only detach path. There is no allow, grant, label, or certificate flag. A normal exit after SIGTERM therefore stays fail-closed. The daemon does not install a new attachment when `Adopt` returns `ErrIncarnation`; it exits.

### `config/experimental/datapath-fence.yaml`

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cmtc-bpf-fence
  namespace: cmtc-system
spec:
  selector:
    matchLabels: {app.kubernetes.io/name: cmtc-bpf-fence}
  template:
    metadata:
      labels: {app.kubernetes.io/name: cmtc-bpf-fence}
    spec:
      hostNetwork: true
      automountServiceAccountToken: false
      nodeSelector: {security.cmtc.io/bpf-fence-lab: "true"}
      terminationGracePeriodSeconds: 5
      containers:
        - name: fence
          image: IMAGE_NOT_BUILT
          command: [/cmtc-bpf-fence]
          args: ["--config=/config/fence.json", "--elf=/elf/fence.o"]
          securityContext: {privileged: true, runAsUser: 0, readOnlyRootFilesystem: true}
          volumeMounts:
            - {name: config, mountPath: /config, readOnly: true}
            - {name: pins, mountPath: /run/cmtc-fence-bpf}
      volumes:
        - name: config
          configMap: {name: cmtc-bpf-fence-UNBUILT}
        - name: pins
          emptyDir: {}
```

This manifest is not part of default provisioning and must not be applied. `emptyDir` is not a BPF filesystem; a real lab mount has to be a private `bpf` mount created for this DaemonSet, never Cilium’s pin directory. The node selector is not the observer selector. The unprivileged Observe agent is untouched.

## Commands to run later

These were not run. They belong in the same rootful private network namespace the observer uses, on a private BPF mount, never on a kind node.

```sh
clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/fence.c -o /tmp/fence.o
go test -count=1 ./internal/datapath/ -run 'TestFenceRejectsPlatformDevicesAndCiliumPins'
CMTC_BPF_ELF=/tmp/fence.o CMTC_BPF_TEST_PRIVATE_NETNS=1 \
  go test -tags cmtc_bpf_privileged -race -count=1 ./internal/datapath/ \
  -run 'TestPrivilegedVerifierDefaultIsShot|TestPrivilegedFenceDenyPassCrashAndReuse'
go vet ./internal/datapath/ ./cmd/cmtc-bpf-fence/
```

A passing run of those tests still does not qualify Cilium policy, CNI ordering, or restore. The follower is a synthetic `cil_fixture`, as the observer’s anchor is synthetic.

## Gates this slice does not close

- Replace `cil_from_container` and `cil_to_container` so the attached program itself returns `TC_ACT_SHOT` for a missing, malformed, expired, or generation-mismatched record. Confirm the TCX program ID changed. Until that ID is current, the old pinned program still forwards.
- Make `WaitForEndpoint` return only after that program ID is installed on both directions of the enrolled veth. The journal commit and the ZDS enrollment in `gate.once` do not do this.
- On restore, do not close `endpointRestoreComplete` or `endpointRegenerateComplete` when regeneration failed. Compare the live Pod UID with `ep.K8sUID` before exposing the endpoint. Namespace UID remains absent from the endpoint record; the in-review patch does not supply that check.
- Exclude health and ingress by endpoint label. A name prefix cannot tell their `lxc*` veth from a workload veth.
- Refuse netkit and legacy TC in the native loader as unsupported for this fence. Do not silently use `attachSKBProgram`’s fallback and call it covered.
- Retire the lab TCX program only after the native program ID check. An agent restart, a map write, or an intent record does not retire the old program.
- Authentication and effective policy stay separate. This program has no certificate, label, or ACK input. A future allow record needs an authenticated provider and still has to pass Cilium policy after `TCX_NEXT`.

The observer can continue to count in front of or behind this hook. Its counters remain attempts, including packets this fence later drops. They are not TLS and they are not policy verdicts.
