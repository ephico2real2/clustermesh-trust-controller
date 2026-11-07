//go:build linux

package datapath

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var ErrClosed = errors.New("observer is closed")

type Config struct {
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
}

type Count struct {
	Packets uint64
	Bytes   uint64
}
type attachment struct {
	Program uint32
	Link    uint32
}

type Observer struct {
	mu       sync.Mutex
	cfg      Config
	ns       *os.File
	nl       *netlink.Handle
	anchor   link.Link
	owned    link.Link
	coll     *ebpf.Collection
	counters *ebpf.Map
	expected []attachment
	cpus     int
	closed   bool
	// anchorName is the name of the program Cilium's link ran at Open. A
	// replacement program on the same link must carry the same name.
	anchorName string
	// followed counts Cilium's in-place program replacements on its link.
	followed uint64
}

// ciliumEndpointProgram returns the name Cilium gives its endpoint program
// for a direction, in full and cut to the kernel's 15-byte object name.
// ProgramInfo reports the full name only when the program carries BTF.
func ciliumEndpointProgram(direction string) (full, truncated string) {
	full = "cil_from_container"
	if direction == "egress" {
		full = "cil_to_container"
	}
	truncated = full
	if len(truncated) > 15 {
		truncated = truncated[:15]
	}
	return full, truncated
}

// programIdentity returns the name and type of a loaded program. The name is
// a sanity check, not proof of ownership.
func programIdentity(id ebpf.ProgramID) (string, ebpf.ProgramType, error) {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", ebpf.UnspecifiedProgram, err
	}
	pi, err := p.Info()
	_ = p.Close()
	if err != nil {
		return "", ebpf.UnspecifiedProgram, err
	}
	return pi.Name, pi.Type, nil
}

func (c Config) attachType() (ebpf.AttachType, error) {
	switch c.Direction {
	case "ingress":
		return ebpf.AttachTCXIngress, nil
	case "egress":
		return ebpf.AttachTCXEgress, nil
	default:
		return 0, errors.New("direction must be ingress or egress")
	}
}

func (c Config) Validate() error {
	if c.Cluster == "" || c.Node == "" || c.PodUID == "" ||
		c.NetNSInode == 0 || c.IfIndex <= 0 || c.IfName == "" ||
		c.MAC == "" || c.PeerIfIndex <= 0 || c.CiliumLinkID == 0 ||
		c.CiliumProgramID == 0 {
		return errors.New("explicit cluster/node/Pod UID and full interface/anchor incarnation required")
	}
	if c.IfIndex > (1<<31)-1 || c.PeerIfIndex > (1<<31)-1 {
		return errors.New("interface indices must fit positive Linux signed32 index")
	}
	if len(c.IfName) >= unix.IFNAMSIZ || strings.ContainsAny(c.IfName, "/\x00") {
		return errors.New("invalid interface name")
	}
	mac, err := net.ParseMAC(c.MAC)
	if err != nil || len(mac) != 6 || mac.String() != c.MAC {
		return errors.New("canonical six-byte interface MAC required")
	}
	_, err = c.attachType()
	return err
}

func inode(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// Verify current thread namespace, not process leader's namespace. This binary
// must never call setns; hostNetwork selects the host namespace at exec time.
func (o *Observer) checkNamespace() error {
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := inode(f)
	if err != nil {
		return err
	}
	if got != o.cfg.NetNSInode {
		return fmt.Errorf("network namespace mismatch: got %d", got)
	}
	held, err := inode(o.ns)
	if err != nil {
		return err
	}
	if held != got {
		return errors.New("held namespace changed")
	}
	return nil
}

func (o *Observer) checkDevice() error {
	if err := o.checkNamespace(); err != nil {
		return err
	}
	dev, err := o.nl.LinkByIndex(o.cfg.IfIndex)
	if err != nil {
		return err
	}
	a := dev.Attrs()
	if dev.Type() != "veth" {
		return fmt.Errorf("only explicit host veth supported, got %s", dev.Type())
	}
	if a.Name != o.cfg.IfName || a.HardwareAddr.String() != o.cfg.MAC ||
		a.ParentIndex != o.cfg.PeerIfIndex {
		return errors.New("interface incarnation attributes changed")
	}
	// No legacy fallback, and do not mix with legacy filters in either direction.
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		fs, err := o.nl.FilterList(dev, parent)
		if err != nil {
			return fmt.Errorf("legacy TC inspection: %w", err)
		}
		if len(fs) != 0 {
			return errors.New("legacy TC filters present; refusing observer")
		}
	}
	return nil
}

func query(c Config) (*link.QueryResult, []attachment, error) {
	at, err := c.attachType()
	if err != nil {
		return nil, nil, err
	}
	q, err := link.QueryPrograms(link.QueryOptions{Target: c.IfIndex, Attach: at})
	if err != nil {
		return nil, nil, fmt.Errorf("TCX required, no fallback: %w", err)
	}
	if q.Revision == 0 {
		return nil, nil, errors.New("TCX revision/link identity unavailable")
	}
	ids := make([]attachment, 0, len(q.Programs))
	for _, p := range q.Programs {
		id, ok := p.LinkID()
		if !ok {
			return nil, nil, errors.New("TCX attachment lacks kernel link identity")
		}
		ids = append(ids, attachment{uint32(p.ID), uint32(id)})
	}
	return q, ids, nil
}

func Open(c Config, elf []byte) (_ *Observer, retErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	o := &Observer{cfg: c}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, o.Close())
		}
	}()
	var err error
	o.ns, err = os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	if err := o.checkNamespace(); err != nil {
		return nil, err
	}
	o.nl, err = netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	// Bound socket receive inactivity; freshness still expires independently
	// because multiple dump receives are not a whole-Sample deadline.
	if err := o.nl.SetSocketTimeout(2 * time.Second); err != nil {
		return nil, fmt.Errorf("set netlink socket timeout: %w", err)
	}
	if err := o.checkDevice(); err != nil {
		return nil, err
	}
	// Opening the exact old link prevents its numeric ID being reused. Never
	// discover a replacement anchor if this one becomes defunct.
	o.anchor, err = link.NewFromID(link.ID(c.CiliumLinkID))
	if err != nil {
		return nil, err
	}
	ai, err := o.anchor.Info()
	if err != nil {
		return nil, err
	}
	at, _ := c.attachType()
	ti := ai.TCX()
	if ti == nil || ti.Ifindex != uint32(c.IfIndex) || uint32(ti.AttachType) != uint32(at) {
		return nil, errors.New("configured Cilium anchor does not match device/direction")
	}
	name, typ, err := programIdentity(ai.Program)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(name, "cil_") || typ != ebpf.SchedCLS {
		return nil, errors.New("anchor is not a Cilium program")
	}
	// Program name is an ownership sanity check, NOT cryptographic proof.
	// Admission/config is restricted to audited owned disposable Pods.
	// Cilium replaces the program of its retained endpoint link in place on
	// every datapath regeneration (agent restart, ztunnel quarantine release),
	// so the configured program ID goes stale while the link stays. The link
	// ID is the incarnation authority. Another program is accepted only when it
	// is the direction's Cilium endpoint program.
	if uint32(ai.Program) != c.CiliumProgramID {
		full, truncated := ciliumEndpointProgram(c.Direction)
		if name != full && name != truncated {
			return nil, errors.New("configured Cilium anchor does not match program")
		}
	}
	o.anchorName = name
	q, before, err := query(c)
	if err != nil {
		return nil, err
	}
	if len(before) == 0 || before[0] != (attachment{uint32(ai.Program), c.CiliumLinkID}) {
		return nil, errors.New("configured Cilium link must be first in baseline TCX chain")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, err
	}
	ps := spec.Programs["cmtc_observe"]
	if ps == nil {
		return nil, errors.New("observer program missing from ELF")
	}
	ps.AttachType = at
	o.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load observer: %w", err)
	}
	o.counters = o.coll.Maps["observed"]
	if o.counters == nil {
		return nil, errors.New("observer counter map missing")
	}
	prog := o.coll.Programs["cmtc_observe"]
	o.owned, err = link.AttachTCX(link.TCXOptions{
		Interface: c.IfIndex, Program: prog, Attach: at,
		Anchor: link.BeforeLink(o.anchor), ExpectedRevision: q.Revision,
	})
	if err != nil {
		return nil, fmt.Errorf("attach against exact baseline: %w", err)
	}
	oi, err := o.owned.Info()
	if err != nil {
		return nil, err
	}
	o.expected = append([]attachment{{uint32(oi.Program), uint32(oi.ID)}}, before...)
	// The exact foreign FD fences the attach transaction, but must not keep
	// Cilium's link alive after Cilium intentionally closes/unpins it. Our own
	// retained link FD now binds this observer to the original device; its ID
	// cannot be reused while held, so a replacement device cannot pass verify.
	anchor := o.anchor
	o.anchor = nil
	if err := anchor.Close(); err != nil {
		return nil, fmt.Errorf("release temporary foreign anchor reference: %w", err)
	}
	o.cpus, err = ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if err := o.verify(); err != nil {
		return nil, err
	}
	return o, nil
}

// verify checks the frozen interface and the complete TCX chain. It follows
// one change only: Cilium replacing the program of its own link in place.
// BPF_LINK_UPDATE keeps the link ID and its position, so this observer still
// runs immediately before the same Cilium link. The new program must have the
// name recorded at Open and be a SchedCLS program. Every other change stops.
func (o *Observer) verify() error {
	if o.closed {
		return ErrClosed
	}
	if err := o.checkDevice(); err != nil {
		return err
	}
	_, now, err := query(o.cfg)
	if err != nil {
		return err
	}
	if len(now) != len(o.expected) || now[0] != o.expected[0] || now[1].Link != o.expected[1].Link ||
		!slices.Equal(now[2:], o.expected[2:]) {
		return errors.New("TCX chain changed; stop and explicitly requalify")
	}
	if now[1].Program == o.expected[1].Program {
		return nil
	}
	name, typ, err := programIdentity(ebpf.ProgramID(now[1].Program))
	if err != nil {
		return fmt.Errorf("inspect replacement program %d on Cilium link %d: %w", now[1].Program, now[1].Link, err)
	}
	if name != o.anchorName || typ != ebpf.SchedCLS {
		return fmt.Errorf("replacement program on Cilium link %d is %q (%s), not %q; stop and explicitly requalify",
			now[1].Link, name, typ, o.anchorName)
	}
	o.expected[1].Program = now[1].Program
	o.followed++
	return nil
}

// Anchor returns the program ID that Cilium's link runs now and how many
// in-place replacements this observer has followed.
func (o *Observer) Anchor() (programID uint32, followed uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.expected) < 2 {
		return 0, o.followed
	}
	return o.expected[1].Program, o.followed
}

// Sample returns only kernel packet/byte counts. It is never a policy or
// workload security assertion. On error caller must clear readiness and Close.
func (o *Observer) Sample() (Count, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.verify(); err != nil {
		return Count{}, err
	}
	values := make([]Count, o.cpus)
	if err := o.counters.Lookup(uint32(0), &values); err != nil {
		return Count{}, err
	}
	var total Count
	for _, c := range values {
		total.Packets += c.Packets
		total.Bytes += c.Bytes
	}
	return total, nil
}

func (o *Observer) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	var errs []error
	if o.owned != nil {
		errs = append(errs, o.owned.Close())
	}
	// Never Unpin, update or close-through another owner's path.
	if o.coll != nil {
		o.coll.Close()
	}
	if o.anchor != nil {
		errs = append(errs, o.anchor.Close())
	}
	if o.nl != nil {
		errs = append(errs, o.nl.Close())
	}
	if o.ns != nil {
		errs = append(errs, o.ns.Close())
	}
	return errors.Join(errs...)
}
