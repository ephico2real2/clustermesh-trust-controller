//go:build linux

// Proposal only. Qualified observer is unchanged. This loader guarantees only
// a COMMITTED pinned deny attachment; attach->pin is not an atomic syscall.
package datapath

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

var (
	ErrFenceClosed       = errors.New("fence process handles are closed")
	ErrFenceNotInstalled = errors.New("fence directory is absent")
	ErrFenceIncomplete   = errors.New("fence pin transaction is incomplete; preserve pins")
	ErrFenceBusy         = errors.New("fence has another process owner")
	ErrFenceLive         = errors.New("live fence cannot be retired or unpinned")
	ErrFenceIncarnation  = errors.New("fence incarnation differs from immutable configuration")
	ErrFenceUnsafe       = errors.New("unsafe fence filesystem ownership or path")
	ErrFenceReserved     = errors.New("platform device is excluded from fence prototype")
	ErrFenceUnpinnedLive = errors.New("uncommitted live link is process-owned; persistence is unqualified")
)

const fenceBPFMagic = 0xcafe4a11
const fenceIdentityMagic uint64 = 0x434d544346494431
const fenceCommitMagic uint64 = 0x434d544346434d31
const fenceSchema uint32 = 1

var fencePinNames = []string{"program", "accounted", "identity", "link", "commit"}

type FenceConfig struct {
	Cluster         string `json:"cluster"`
	Node            string `json:"node"`
	NamespaceUID    string `json:"namespaceUID"`
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
	LockRoot        string `json:"lockRoot"`
}
type FenceCount struct{ DroppedPackets, DroppedBytes uint64 }
type fenceAttachment struct{ Program, Link uint32 }
type fenceIdentity struct {
	Magic                                   uint64
	Schema, Reserved                        uint32
	ConfigHash, ELFHash, BaselineHash       [32]byte
	Epoch                                   [16]byte
	Tag                                     [8]byte
	ProgramID, CounterID, SelfID, Reserved2 uint32
}
type fenceCommit struct {
	Magic                                 uint64
	Schema, Reserved                      uint32
	IdentityID, LinkID, SelfID, Reserved2 uint32
	Epoch                                 [16]byte
}
type fenceFS struct {
	root, locks, dir, owner  *os.File
	rootPath, lockPath, name string
}
type Fence struct {
	mu                               sync.Mutex
	cfg                              FenceConfig
	fs                               *fenceFS
	ns                               *os.File
	nl                               *netlink.Handle
	program                          *ebpf.Program
	counters, identityMap, commitMap *ebpf.Map
	own                              link.Link
	id                               fenceIdentity
	commit                           fenceCommit
	expected                         []fenceAttachment
	cpus                             int
	pinned, committed, closed        bool
	// Test-only fault injection is supplied via private installFence. Never a grant.
	checkpoint func(string) error
}

func (c FenceConfig) attachType() (ebpf.AttachType, error) {
	switch c.Direction {
	case "ingress":
		return ebpf.AttachTCXIngress, nil
	case "egress":
		return ebpf.AttachTCXEgress, nil
	}
	return 0, fmt.Errorf("%w: unknown direction", ErrFenceIncarnation)
}
func fenceReservedDevice(name string) bool {
	return name == "lo" || strings.HasPrefix(name, "cilium_") || strings.HasPrefix(name, "kube-")
}
func (c FenceConfig) Validate() error {
	for _, s := range []string{c.Cluster, c.Node, c.NamespaceUID, c.PodUID} {
		if s == "" || strings.TrimSpace(s) != s || len(s) > 128 || strings.ContainsAny(s, "/\x00") {
			return fmt.Errorf("%w: incomplete workload binding", ErrFenceIncarnation)
		}
	}
	base := Config{Cluster: c.Cluster, Node: c.Node, PodUID: c.PodUID, NetNSInode: c.NetNSInode, IfIndex: c.IfIndex, IfName: c.IfName, MAC: c.MAC, PeerIfIndex: c.PeerIfIndex, Direction: c.Direction, CiliumLinkID: c.CiliumLinkID, CiliumProgramID: c.CiliumProgramID}
	if err := base.Validate(); err != nil {
		return err
	}
	if fenceReservedDevice(c.IfName) {
		return ErrFenceReserved
	}
	for _, p := range []string{c.PinRoot, c.LockRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || len(p) > 4096 {
			return ErrFenceUnsafe
		}
	}
	if c.PinRoot == "/sys/fs/bpf" || c.PinRoot == "/sys/fs/bpf/cilium" || strings.HasPrefix(c.PinRoot, "/sys/fs/bpf/cilium/") || c.PinRoot == c.LockRoot {
		return ErrFenceUnsafe
	}
	return nil
}
func (c FenceConfig) key() string {
	data, _ := json.Marshal([]any{c.Cluster, c.Node, c.NamespaceUID, c.PodUID, c.Direction})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (c FenceConfig) hash() [32]byte { data, _ := json.Marshal(c); return sha256.Sum256(data) }

// Walk all components with O_NOFOLLOW. The held leaf, not a re-resolved pathname,
// anchors every child operation. Roots must be provisioned explicitly, not here.
func fenceOpenDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrFenceUnsafe
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			unix.Close(fd)
			return nil, ErrFenceUnsafe
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFenceUnsafe, err)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	if err := fencePrivateDirectory(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func fencePrivateDirectory(f *os.File) error {
	var s unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &s); err != nil {
		return err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&07777 != 0700 || s.Uid != uint32(os.Geteuid()) {
		return ErrFenceUnsafe
	}
	return nil
}
func fenceSameDirectory(path string, held *os.File) error {
	current, err := fenceOpenDirectory(path)
	if err != nil {
		return err
	}
	defer current.Close()
	var a, b unix.Stat_t
	if err := unix.Fstat(int(held.Fd()), &a); err != nil {
		return err
	}
	if err := unix.Fstat(int(current.Fd()), &b); err != nil {
		return err
	}
	if a.Dev != b.Dev || a.Ino != b.Ino {
		return ErrFenceUnsafe
	}
	return nil
}
func fencePrivateFile(f *os.File) error {
	var s unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &s); err != nil {
		return err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&07777 != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || s.Size != 0 {
		return ErrFenceUnsafe
	}
	return nil
}
func openFenceFS(c FenceConfig, create bool) (result *fenceFS, retErr error) {
	fs := &fenceFS{rootPath: c.PinRoot, lockPath: c.LockRoot, name: c.key()}
	defer func() {
		if retErr != nil {
			fs.close()
		}
	}()
	var err error
	fs.root, err = fenceOpenDirectory(c.PinRoot)
	if err != nil {
		return nil, err
	}
	fs.locks, err = fenceOpenDirectory(c.LockRoot)
	if err != nil {
		return nil, err
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(fs.root.Fd()), &st); err != nil {
		return nil, err
	}
	if uint64(st.Type) != fenceBPFMagic {
		return nil, ErrFenceUnsafe
	}
	if err := unix.Fstatfs(int(fs.locks.Fd()), &st); err != nil {
		return nil, err
	}
	if uint64(st.Type) == fenceBPFMagic {
		return nil, ErrFenceUnsafe
	}
	lockname := fs.name + ".lock"
	fd, err := unix.Openat(int(fs.locks.Fd()), lockname, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	fs.owner = os.NewFile(uintptr(fd), lockname)
	if err := fencePrivateFile(fs.owner); err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFenceBusy, err)
	}
	if create {
		if err := unix.Mkdirat(int(fs.root.Fd()), fs.name, 0700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil, ErrFenceIncomplete
			}
			return nil, err
		}
	}
	fd, err = unix.Openat(int(fs.root.Fd()), fs.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrFenceNotInstalled
		}
		return nil, err
	}
	fs.dir = os.NewFile(uintptr(fd), fs.name)
	if err := fs.validate(); err != nil {
		return nil, err
	}
	return fs, nil
}
func (fs *fenceFS) validate() error {
	if err := fenceSameDirectory(fs.rootPath, fs.root); err != nil {
		return err
	}
	if err := fenceSameDirectory(fs.lockPath, fs.locks); err != nil {
		return err
	}
	if err := fencePrivateFile(fs.owner); err != nil {
		return err
	}
	if err := fencePrivateDirectory(fs.dir); err != nil {
		return err
	}
	var a, b unix.Stat_t
	if err := unix.Fstat(int(fs.dir.Fd()), &a); err != nil {
		return err
	}
	if err := unix.Fstatat(int(fs.root.Fd()), fs.name, &b, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if b.Mode&unix.S_IFMT != unix.S_IFDIR || a.Ino != b.Ino || a.Dev != b.Dev {
		return ErrFenceUnsafe
	}
	if err := unix.Fstat(int(fs.owner.Fd()), &a); err != nil {
		return err
	}
	if err := unix.Fstatat(int(fs.locks.Fd()), fs.name+".lock", &b, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if a.Dev != b.Dev || a.Ino != b.Ino || b.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrFenceUnsafe
	}
	return nil
}
func (fs *fenceFS) path(name string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", fs.dir.Fd(), name)
}
func (fs *fenceFS) entry(name string) error {
	if err := fs.validate(); err != nil {
		return err
	}
	var s unix.Stat_t
	if err := unix.Fstatat(int(fs.dir.Fd()), name, &s, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&07777 != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 {
		return ErrFenceUnsafe
	}
	return nil
}
func (fs *fenceFS) securePin(name string, pin func(string) error) error {
	if err := fs.validate(); err != nil {
		return err
	}
	if err := pin(fs.path(name)); err != nil {
		return err
	}
	// Parent is0700 and exclusively locked. Pin files get exactly0600 before use.
	if err := unix.Fchmodat(int(fs.dir.Fd()), name, 0600, 0); err != nil {
		return err
	}
	return fs.entry(name)
}
func (fs *fenceFS) close() error {
	var errs []error
	for _, f := range []*os.File{fs.dir, fs.owner, fs.locks, fs.root} {
		if f != nil {
			errs = append(errs, f.Close())
		}
	}
	fs.dir = nil
	fs.owner = nil
	fs.locks = nil
	fs.root = nil
	return errors.Join(errs...)
}
func fenceQuery(c FenceConfig) (uint64, []fenceAttachment, error) {
	at, err := c.attachType()
	if err != nil {
		return 0, nil, err
	}
	q, err := link.QueryPrograms(link.QueryOptions{Target: c.IfIndex, Attach: at})
	if err != nil {
		return 0, nil, err
	}
	if q.Revision == 0 {
		return 0, nil, ErrFenceIncarnation
	}
	out := make([]fenceAttachment, 0, len(q.Programs))
	for _, p := range q.Programs {
		id, ok := p.LinkID()
		if !ok {
			return 0, nil, ErrFenceIncarnation
		}
		out = append(out, fenceAttachment{uint32(p.ID), uint32(id)})
	}
	return q.Revision, out, nil
}
func fenceNew(c FenceConfig, fs *fenceFS) (f *Fence, retErr error) {
	f = &Fence{cfg: c, fs: fs}
	owned := f
	defer func() {
		if retErr != nil {
			_ = owned.releaseUnlocked()
		}
	}()
	var err error
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
	f.cpus, err = ebpf.PossibleCPU()
	return f, err
}
func (f *Fence) device() error {
	current, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer current.Close()
	a, err := inode(current)
	if err != nil {
		return err
	}
	b, err := inode(f.ns)
	if err != nil {
		return err
	}
	if a != f.cfg.NetNSInode || b != a {
		return ErrFenceIncarnation
	}
	dev, err := f.nl.LinkByIndex(f.cfg.IfIndex)
	if err != nil {
		return err
	}
	attrs := dev.Attrs()
	if dev.Type() != "veth" || attrs.Name != f.cfg.IfName || attrs.HardwareAddr.String() != f.cfg.MAC || attrs.ParentIndex != f.cfg.PeerIfIndex || fenceReservedDevice(attrs.Name) {
		return ErrFenceIncarnation
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := f.nl.FilterList(dev, parent)
		if err != nil {
			return err
		}
		if len(filters) != 0 {
			return ErrFenceIncarnation
		}
	}
	return nil
}
func fenceSpec(c FenceConfig, elf []byte) (*ebpf.CollectionSpec, error) {
	if len(elf) == 0 || len(elf) > 4*1024*1024 {
		return nil, fmt.Errorf("%w: ELF size", ErrFenceIncarnation)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, err
	}
	if len(spec.Programs) != 1 || len(spec.Maps) != 1 || spec.Programs["cmtc_fence"] == nil || spec.Maps["accounted"] == nil {
		return nil, fmt.Errorf("%w: deny-only ELF schema", ErrFenceIncarnation)
	}
	p := spec.Programs["cmtc_fence"]
	if p.Type != ebpf.SchedCLS {
		return nil, ErrFenceIncarnation
	}
	p.AttachType, _ = c.attachType()
	m := spec.Maps["accounted"]
	if m.Type != ebpf.PerCPUArray || m.KeySize != 4 || m.ValueSize != 16 || m.MaxEntries != 1 || m.Flags != 0 {
		return nil, ErrFenceIncarnation
	}
	return spec, nil
}
func fenceMapID(m *ebpf.Map) (uint32, error) {
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return 0, ErrFenceIncarnation
	}
	return uint32(id), nil
}
func (f *Fence) point(name string) error {
	if f.checkpoint != nil {
		return f.checkpoint(name)
	}
	return nil
}

// InstallFence preserves all created pins on failure. If attachment happened,
// a partial handle is returned with the error so the caller can retain its FD.
// Only nil error establishes COMMITTED persistence, never mTLS/Protected.
func InstallFence(c FenceConfig, elf []byte) (*Fence, error) { return installFence(c, elf, nil) }
func installFence(c FenceConfig, elf []byte, checkpoint func(string) error) (f *Fence, retErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	spec, err := fenceSpec(c, elf)
	if err != nil {
		return nil, err
	}
	fs, err := openFenceFS(c, true)
	if err != nil {
		return nil, err
	}
	f, err = fenceNew(c, fs)
	if err != nil {
		return nil, err
	}
	f.checkpoint = checkpoint
	owned := f
	defer func() {
		if retErr != nil && owned.own == nil {
			retErr = errors.Join(retErr, owned.releaseUnlocked())
			f = nil
		}
	}()
	if err = f.device(); err != nil {
		return f, err
	}
	anchor, err := link.NewFromID(link.ID(c.CiliumLinkID))
	if err != nil {
		return f, err
	}
	// Close the foreign reference before returning, including every error path.
	defer anchor.Close()
	ai, err := anchor.Info()
	if err != nil {
		return f, err
	}
	at, _ := c.attachType()
	tx := ai.TCX()
	if tx == nil || tx.Ifindex != uint32(c.IfIndex) || uint32(tx.AttachType) != uint32(at) || uint32(ai.Program) != c.CiliumProgramID {
		return f, ErrFenceIncarnation
	}
	ap, err := ebpf.NewProgramFromID(ai.Program)
	if err != nil {
		return f, err
	}
	pi, err := ap.Info()
	ap.Close()
	if err != nil {
		return f, err
	}
	expectedName := "cil_from_container"
	if c.Direction == "egress" {
		expectedName = "cil_to_container"
	}
	truncated := expectedName
	if len(truncated) > 15 {
		truncated = truncated[:15]
	}
	if pi.Name != expectedName && pi.Name != truncated {
		return f, ErrFenceReserved
	}
	revision, before, err := fenceQuery(c)
	if err != nil {
		return f, err
	}
	if len(before) == 0 || before[0] != (fenceAttachment{c.CiliumProgramID, c.CiliumLinkID}) {
		return f, ErrFenceIncarnation
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return f, err
	}
	f.program = coll.Programs["cmtc_fence"]
	delete(coll.Programs, "cmtc_fence")
	f.counters = coll.Maps["accounted"]
	delete(coll.Maps, "accounted")
	coll.Close()
	if err = f.counters.Freeze(); err != nil {
		return f, err
	}
	pinfo, err := f.program.Info()
	if err != nil {
		return f, err
	}
	pid, ok := pinfo.ID()
	if !ok {
		return f, ErrFenceIncarnation
	}
	tag, err := hex.DecodeString(pinfo.Tag)
	if err != nil || len(tag) != 8 {
		return f, ErrFenceIncarnation
	}
	counterID, err := fenceMapID(f.counters)
	if err != nil {
		return f, err
	}
	baselineBytes, _ := json.Marshal(before)
	f.id = fenceIdentity{BaselineHash: sha256.Sum256(baselineBytes), Magic: fenceIdentityMagic, Schema: fenceSchema, ConfigHash: c.hash(), ELFHash: sha256.Sum256(elf), ProgramID: uint32(pid), CounterID: counterID}
	copy(f.id.Tag[:], tag)
	if _, err = rand.Read(f.id.Epoch[:]); err != nil {
		return f, err
	}
	f.identityMap, err = ebpf.NewMap(&ebpf.MapSpec{Name: "cmtc_fence_id", Type: ebpf.Array, KeySize: 4, ValueSize: uint32(binary.Size(f.id)), MaxEntries: 1})
	if err != nil {
		return f, err
	}
	f.id.SelfID, err = fenceMapID(f.identityMap)
	if err != nil {
		return f, err
	}
	if err = f.identityMap.Update(uint32(0), f.id, ebpf.UpdateAny); err != nil {
		return f, err
	}
	if err = f.identityMap.Freeze(); err != nil {
		return f, err
	}
	for _, item := range []struct {
		name string
		pin  func(string) error
	}{{"accounted", f.counters.Pin}, {"program", f.program.Pin}, {"identity", f.identityMap.Pin}} {
		if err = fs.securePin(item.name, item.pin); err != nil {
			return f, err
		}
		if err = f.point("pinned-" + item.name); err != nil {
			return f, err
		}
	}
	if err = f.device(); err != nil {
		return f, err
	}
	if err = fs.validate(); err != nil {
		return f, err
	}
	f.own, err = link.AttachTCX(link.TCXOptions{Interface: c.IfIndex, Program: f.program, Attach: at, Anchor: link.BeforeLink(anchor), ExpectedRevision: revision})
	if err != nil {
		return f, err
	}
	if err = f.point("attached-unpinned"); err != nil {
		return f, err
	}
	if err = fs.securePin("link", func(path string) error {
		err := f.own.Pin(path)
		if err == nil {
			f.pinned = true
		}
		return err
	}); err != nil {
		return f, err
	}
	if err = f.point("pinned-link"); err != nil {
		return f, err
	}
	li, err := f.own.Info()
	if err != nil {
		return f, err
	}
	f.commitMap, err = ebpf.NewMap(&ebpf.MapSpec{Name: "cmtc_fence_cmt", Type: ebpf.Array, KeySize: 4, ValueSize: uint32(binary.Size(fenceCommit{})), MaxEntries: 1})
	if err != nil {
		return f, err
	}
	selfID, err := fenceMapID(f.commitMap)
	if err != nil {
		return f, err
	}
	f.commit = fenceCommit{Magic: fenceCommitMagic, Schema: fenceSchema, IdentityID: f.id.SelfID, LinkID: uint32(li.ID), SelfID: selfID, Epoch: f.id.Epoch}
	if err = f.commitMap.Update(uint32(0), f.commit, ebpf.UpdateAny); err != nil {
		return f, err
	}
	if err = f.commitMap.Freeze(); err != nil {
		return f, err
	}
	if err = fs.securePin("commit", f.commitMap.Pin); err != nil {
		return f, err
	}
	f.committed = true
	f.expected = append([]fenceAttachment{{f.id.ProgramID, f.commit.LinkID}}, before...)
	if err = f.point("committed"); err != nil {
		return f, err
	}
	if err = f.verify(); err != nil {
		return f, err
	}
	return f, nil
}

func fenceValidateFrozen(m *ebpf.Map, size uint32) error {
	info, err := m.Info()
	if err != nil {
		return err
	}
	if info.Type != ebpf.Array || info.KeySize != 4 || info.ValueSize != size || info.MaxEntries != 1 || info.Flags != 0 || !info.Frozen() {
		return ErrFenceIncarnation
	}
	return nil
}
func loadFence(c FenceConfig, elf []byte) (f *Fence, retErr error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	spec, err := fenceSpec(c, elf)
	if err != nil {
		return nil, err
	}
	fs, err := openFenceFS(c, false)
	if err != nil {
		return nil, err
	}
	f, err = fenceNew(c, fs)
	if err != nil {
		return nil, err
	}
	owned := f
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, owned.releaseUnlocked())
			f = nil
		}
	}()
	entries, err := os.ReadDir(fs.path("."))
	if err != nil {
		return nil, err
	}
	if len(entries) != len(fencePinNames) {
		return nil, ErrFenceIncomplete
	}
	for _, name := range fencePinNames {
		if err = fs.entry(name); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFenceIncomplete, err)
		}
	}
	f.identityMap, err = ebpf.LoadPinnedMap(fs.path("identity"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	if err = fenceValidateFrozen(f.identityMap, uint32(binary.Size(f.id))); err != nil {
		return nil, err
	}
	if err = f.identityMap.Lookup(uint32(0), &f.id); err != nil {
		return nil, err
	}
	selfID, err := fenceMapID(f.identityMap)
	if err != nil {
		return nil, err
	}
	if f.id.Magic != fenceIdentityMagic || f.id.Schema != fenceSchema || f.id.Reserved != 0 || f.id.Reserved2 != 0 || f.id.SelfID != selfID || f.id.ConfigHash != c.hash() || f.id.ELFHash != sha256.Sum256(elf) || f.id.Epoch == ([16]byte{}) {
		return nil, ErrFenceIncarnation
	}
	f.commitMap, err = ebpf.LoadPinnedMap(fs.path("commit"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	if err = fenceValidateFrozen(f.commitMap, uint32(binary.Size(f.commit))); err != nil {
		return nil, err
	}
	if err = f.commitMap.Lookup(uint32(0), &f.commit); err != nil {
		return nil, err
	}
	selfID, err = fenceMapID(f.commitMap)
	if err != nil {
		return nil, err
	}
	if f.commit.Magic != fenceCommitMagic || f.commit.Schema != fenceSchema || f.commit.Reserved != 0 || f.commit.Reserved2 != 0 || f.commit.SelfID != selfID || f.commit.IdentityID != f.id.SelfID || f.commit.Epoch != f.id.Epoch || f.commit.LinkID == 0 {
		return nil, ErrFenceIncarnation
	}
	f.counters, err = ebpf.LoadPinnedMap(fs.path("accounted"), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	info, err := f.counters.Info()
	if err != nil {
		return nil, err
	}
	counterID, err := fenceMapID(f.counters)
	if err != nil {
		return nil, err
	}
	if err = spec.Maps["accounted"].Compatible(f.counters); err != nil {
		return nil, err
	}
	if counterID != f.id.CounterID || !info.Frozen() {
		return nil, ErrFenceIncarnation
	}
	f.program, err = ebpf.LoadPinnedProgram(fs.path("program"), nil)
	if err != nil {
		return nil, err
	}
	pi, err := f.program.Info()
	if err != nil {
		return nil, err
	}
	pid, ok := pi.ID()
	if !ok {
		return nil, ErrFenceIncarnation
	}
	if uint32(pid) != f.id.ProgramID || pi.Type != ebpf.SchedCLS || pi.Tag != hex.EncodeToString(f.id.Tag[:]) {
		return nil, ErrFenceIncarnation
	}
	if err = spec.Programs["cmtc_fence"].Compatible(pi); err != nil {
		return nil, err
	}
	maps, ok := pi.MapIDs()
	if !ok || len(maps) != 1 || uint32(maps[0]) != f.id.CounterID {
		return nil, ErrFenceIncarnation
	}
	f.own, err = link.LoadPinnedLink(fs.path("link"), nil)
	if err != nil {
		return nil, err
	}
	f.pinned = true
	f.committed = true
	li, err := f.own.Info()
	if err != nil {
		return nil, err
	}
	at, _ := c.attachType()
	tx := li.TCX()
	if tx == nil || uint32(li.ID) != f.commit.LinkID || uint32(li.Program) != f.id.ProgramID || uint32(tx.AttachType) != uint32(at) {
		return nil, ErrFenceIncarnation
	}
	if err = fs.validate(); err != nil {
		return nil, err
	}
	return f, nil
}
func AdoptFence(c FenceConfig, elf []byte) (f *Fence, retErr error) {
	f, err := loadFence(c, elf)
	if err != nil {
		return nil, err
	}
	owned := f
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, owned.releaseUnlocked())
			f = nil
		}
	}()
	if err = f.device(); err != nil {
		return nil, err
	}
	li, err := f.own.Info()
	if err != nil {
		return nil, err
	}
	if li.TCX().Ifindex != uint32(c.IfIndex) {
		return nil, ErrFenceIncarnation
	}
	_, chain, err := fenceQuery(c)
	if err != nil {
		return nil, err
	}
	if len(chain) < 2 || chain[0] != (fenceAttachment{f.id.ProgramID, f.commit.LinkID}) || chain[1] != (fenceAttachment{c.CiliumProgramID, c.CiliumLinkID}) {
		return nil, ErrFenceIncarnation
	}
	baselineBytes, _ := json.Marshal(chain[1:])
	if sha256.Sum256(baselineBytes) != f.id.BaselineHash {
		return nil, ErrFenceIncarnation
	}
	f.expected = chain
	if err = f.verify(); err != nil {
		return nil, err
	}
	return f, nil
}
func (f *Fence) verify() error {
	if f.closed {
		return ErrFenceClosed
	}
	if !f.committed {
		return ErrFenceIncomplete
	}
	if err := f.fs.validate(); err != nil {
		return err
	}
	entries, err := os.ReadDir(f.fs.path("."))
	if err != nil {
		return err
	}
	if len(entries) != len(fencePinNames) {
		return ErrFenceIncomplete
	}
	for _, name := range fencePinNames {
		if err := f.fs.entry(name); err != nil {
			return err
		}
	}
	if err := f.verifyPinIDs(); err != nil {
		return err
	}
	if err := f.device(); err != nil {
		return err
	}
	li, err := f.own.Info()
	if err != nil {
		return err
	}
	if li.TCX() == nil || li.TCX().Ifindex != uint32(f.cfg.IfIndex) || uint32(li.ID) != f.commit.LinkID || uint32(li.Program) != f.id.ProgramID {
		return ErrFenceIncarnation
	}
	_, chain, err := fenceQuery(f.cfg)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(chain, f.expected) {
		return ErrFenceIncarnation
	}
	return nil
}
func (f *Fence) Account() (FenceCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.verify(); err != nil {
		return FenceCount{}, err
	}
	values := make([]struct{ Packets, Bytes uint64 }, f.cpus)
	if err := f.counters.Lookup(uint32(0), &values); err != nil {
		return FenceCount{}, err
	}
	var out FenceCount
	for _, v := range values {
		out.DroppedPackets += v.Packets
		out.DroppedBytes += v.Bytes
	}
	return out, nil
}
func (f *Fence) releaseUnlocked() error {
	if f.closed {
		return nil
	}
	if f.own != nil && !f.pinned {
		info, err := f.own.Info()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFenceUnpinnedLive, err)
		}
		if info.TCX() == nil || info.TCX().Ifindex != 0 {
			return ErrFenceUnpinnedLive
		}
	}
	f.closed = true
	var errs []error
	if f.own != nil {
		errs = append(errs, f.own.Close())
		f.own = nil
	}
	if f.program != nil {
		errs = append(errs, f.program.Close())
		f.program = nil
	}
	for _, m := range []*ebpf.Map{f.counters, f.identityMap, f.commitMap} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	f.counters = nil
	f.identityMap = nil
	f.commitMap = nil
	if f.nl != nil {
		errs = append(errs, f.nl.Close())
		f.nl = nil
	}
	if f.ns != nil {
		errs = append(errs, f.ns.Close())
		f.ns = nil
	}
	if f.fs != nil {
		errs = append(errs, f.fs.close())
		f.fs = nil
	}
	return errors.Join(errs...)
}

// ReleaseProcess never unpins. On an uncommitted/unpinned LIVE attachment it
// refuses to close the only owning FD; caller must retain the returned handle.
func (f *Fence) ReleaseProcess() error { f.mu.Lock(); defer f.mu.Unlock(); return f.releaseUnlocked() }

// RetireDefunctFence has NO live counterpart. A positive TCX.Ifindex==0 proof
// from the exact held old link is required, even when its numeric ifindex has
// been reused by a new device. Unknown/ENOLINK is not sufficient evidence.
func RetireDefunctFence(c FenceConfig, elf []byte) (retErr error) {
	f, err := loadFence(c, elf)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, f.ReleaseProcess()) }()
	info, err := f.own.Info()
	if err != nil {
		return err
	}
	if info.TCX() == nil || info.TCX().Ifindex != 0 {
		return ErrFenceLive
	}
	// Revalidate ALL pin IDs before the first destructive operation. Exclusive
	// ordinary-filesystem lock serializes trusted installer/adopter/retirer peers.
	if err = f.fs.validate(); err != nil {
		return err
	}
	for _, name := range fencePinNames {
		if err = f.fs.entry(name); err != nil {
			return err
		}
	}
	if err = f.verifyPinIDs(); err != nil {
		return err
	}
	info, err = f.own.Info()
	if err != nil {
		return err
	}
	if info.TCX() == nil || info.TCX().Ifindex != 0 {
		return ErrFenceLive
	}
	// All names are constants and all parents are held dirfds. Never RemoveAll,
	// follow a symlink, discover another incarnation or touch Cilium's pin tree.
	for _, name := range []string{"link", "commit", "identity", "program", "accounted"} {
		if err = unix.Unlinkat(int(f.fs.dir.Fd()), name, 0); err != nil {
			return err
		}
	}
	return unix.Unlinkat(int(f.fs.root.Fd()), f.fs.name, unix.AT_REMOVEDIR)
}
func (f *Fence) verifyPinIDs() error {
	// Open independent references so an accidental replaced pin cannot be removed
	// merely because old FDs are still valid. These opens perform no mutation.
	p, err := ebpf.LoadPinnedProgram(f.fs.path("program"), nil)
	if err != nil {
		return err
	}
	defer p.Close()
	pi, err := p.Info()
	if err != nil {
		return err
	}
	id, ok := pi.ID()
	if !ok || uint32(id) != f.id.ProgramID {
		return ErrFenceIncarnation
	}
	for _, item := range []struct {
		name string
		id   uint32
	}{{"accounted", f.id.CounterID}, {"identity", f.id.SelfID}, {"commit", f.commit.SelfID}} {
		m, err := ebpf.LoadPinnedMap(f.fs.path(item.name), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		id, err := fenceMapID(m)
		m.Close()
		if err != nil {
			return err
		}
		if id != item.id {
			return ErrFenceIncarnation
		}
	}
	l, err := link.LoadPinnedLink(f.fs.path("link"), nil)
	if err != nil {
		return err
	}
	defer l.Close()
	li, err := l.Info()
	if err != nil {
		return err
	}
	if uint32(li.ID) != f.commit.LinkID || uint32(li.Program) != f.id.ProgramID {
		return ErrFenceIncarnation
	}
	return nil
}
