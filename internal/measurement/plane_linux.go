//go:build linux

package measurement

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

// retireDelay is how long a detached Pod's arrays are kept before their final reading. Program runs that started
// before the detach end within an RCU grace period, and their counts must reach the namespace's total.
const retireDelay = time.Second

// kernelAttachType gives the kernel's number of each attach type, for BPF_PROG_QUERY.
var kernelAttachType = map[ebpf.AttachType]uint32{
	ebpf.AttachCGroupInetEgress:  unix.BPF_CGROUP_INET_EGRESS,
	ebpf.AttachCGroupInetIngress: unix.BPF_CGROUP_INET_INGRESS,
}

// Plane loads, attaches and reads the measurement programs of one node. It holds every link by file descriptor
// only: nothing is pinned, so the kernel detaches the programs when the process exits. Use it from one goroutine.
type Plane struct {
	spec        *ebpf.CollectionSpec
	maps        map[string]*ebpf.Map
	cgroupRoot  string
	log         logr.Logger
	execution   string
	possibleCPU int
	// loadErr is why the kernel refused the maps or the programs. The plane then attaches nothing.
	loadErr error

	nodeAddresses   map[nodeAddress]bool // the keys of MapNodeAddresses
	nodeAddressesOK bool

	attached map[string]*attachment // by Pod UID
	retiring []*attachment
	states   map[string]PodState // the desired Pods that are not attached, by Pod UID
	nextID   uint64              // the ID of the next attachment, for the accumulator
	acc      *Accumulator
	node     NodeCounters
	retired  ProgramStats
}

// attachment is one Pod's copy of both programs, with its own MapTraffic and MapDNS, and its two links.
type attachment struct {
	id   uint64
	pod  DesiredPod
	path string
	// cgroupID is the inode of the Pod cgroup directory, which is the kernel's cgroup ID on cgroup v2.
	cgroupID uint64
	coll     *ebpf.Collection
	progIDs  [NumDirections]ebpf.ProgramID
	links    [NumDirections]*link.RawLink
	since    time.Time
}

// programSet is a set of kernel program IDs.
type programSet map[ebpf.ProgramID]bool

// OpenPlane prepares the plane for the spec that LoadSpec checked; the plane takes the spec over. When the kernel
// refuses the maps or the programs, the plane still runs: it reports both hooks and every Pod unavailable.
func OpenPlane(spec *ebpf.CollectionSpec, cgroupRoot string, log logr.Logger) (*Plane, error) {
	if err := spec.Variables[VariableBounds].Set(DNSDurationBoundsNs()); err != nil {
		return nil, fmt.Errorf("set %s: %w", VariableBounds, err)
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	p := &Plane{spec: spec, maps: map[string]*ebpf.Map{}, cgroupRoot: filepath.Clean(cgroupRoot), log: log,
		execution: hex.EncodeToString(id), possibleCPU: cpus, nodeAddresses: map[nodeAddress]bool{},
		attached: map[string]*attachment{}, states: map[string]PodState{}, acc: NewAccumulator()}
	if p.loadErr = p.load(); p.loadErr != nil {
		log.Error(p.loadErr, "the kernel refused the measurement programs; every Pod is unavailable", "stage", "load",
			"enforcementAvailable", false)
	}
	return p, nil
}

func (p *Plane) load() error {
	for _, name := range SharedMaps {
		m, err := ebpf.NewMap(p.spec.Maps[name])
		if err != nil {
			return fmt.Errorf("create map %s: %w", name, err)
		}
		p.maps[name] = m
	}
	// A trial load proves that the verifier accepts both programs before any Pod needs them.
	coll, err := p.collection()
	if err != nil {
		return err
	}
	coll.Close()
	return nil
}

// collection loads one copy of both programs, with a new MapTraffic and MapDNS for one Pod. The copy shares the
// plane's other maps: cilium/ebpf duplicates the descriptor of each replacement map, so closing the copy never closes
// the plane's maps.
func (p *Plane) collection() (*ebpf.Collection, error) {
	coll, err := ebpf.NewCollectionWithOptions(p.spec, ebpf.CollectionOptions{MapReplacements: p.maps})
	if err != nil {
		return nil, fmt.Errorf("load the programs: %w", err)
	}
	return coll, nil
}

// SetNodeAddresses replaces the node's Pod addresses in MapNodeAddresses. A DNS server at one of them is same_node.
func (p *Plane) SetNodeAddresses(addresses []string) error {
	p.nodeAddressesOK = false
	if p.loadErr != nil {
		return p.loadErr
	}
	want := make(map[nodeAddress]bool, len(addresses))
	for _, a := range addresses {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return err
		}
		// As16 gives an IPv4 address in its IPv4-mapped form, the form bpf/measure.c stores.
		want[nodeAddress(addr.As16())] = true
	}
	if len(want) > MaxNodeAddresses {
		return fmt.Errorf("%d node addresses, more than %d", len(want), MaxNodeAddresses)
	}
	m := p.maps[MapNodeAddresses]
	for key := range p.nodeAddresses {
		if want[key] {
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		delete(p.nodeAddresses, key)
	}
	for key := range want {
		if p.nodeAddresses[key] {
			continue
		}
		if err := m.Put(key, uint32(1)); err != nil {
			return err
		}
		p.nodeAddresses[key] = true
	}
	p.nodeAddressesOK = true
	return nil
}

// Reconcile detaches the Pods that are no longer desired or that fail verify, and attaches every desired Pod whose
// cgroup exists. Each desired Pod ends attached, waiting (no cgroup yet) or unavailable (with a logged reason).
func (p *Plane) Reconcile(desired []DesiredPod, now time.Time) {
	want := make(map[string]DesiredPod, len(desired))
	for _, d := range desired {
		want[d.UID] = d
	}
	parents := map[string]programSet{}
	for uid, a := range p.attached {
		d, ok := want[uid]
		if !ok || d.Namespace != a.pod.Namespace {
			p.detach(a, now, "no longer an enrolled Pod of this node")
			continue
		}
		a.pod = d
		if err := p.verify(a, parents); err != nil {
			p.detach(a, now, err.Error())
		}
	}

	states := map[string]PodState{}
	var cgroups map[string][]string
	var findErr error
	listed := false
	for _, d := range desired {
		if p.attached[d.UID] != nil {
			continue
		}
		if !listed && p.loadErr == nil {
			cgroups, findErr = FindPodCgroups(p.cgroupRoot)
			listed = true
		}
		if state, attached := p.attachPod(d, cgroups, findErr, now); !attached {
			states[d.UID] = state
		}
	}
	for uid, s := range states {
		if old, ok := p.states[uid]; !ok || old.State != s.State || old.Reason != s.Reason {
			p.log.Info("Pod not measured", "stage", "attach", "podUID", uid, "namespace", s.Namespace,
				"state", s.State, "reason", s.Reason, "enforcementAvailable", false)
		}
	}
	p.states = states
	p.retire(now)
}

// attachPod attaches one desired Pod. When it cannot, it returns the Pod's state and false.
func (p *Plane) attachPod(d DesiredPod, cgroups map[string][]string, findErr error, now time.Time) (PodState, bool) {
	state := PodState{UID: d.UID, Namespace: d.Namespace, State: StateUnavailable}
	paths := cgroups[d.UID]
	switch {
	case p.loadErr != nil:
		state.Reason = "programs not loaded: " + p.loadErr.Error()
	case findErr != nil:
		state.Reason = "list Pod cgroups: " + findErr.Error()
	case len(paths) == 0:
		state.State, state.Reason = StateWaiting, "Pod cgroup not created yet"
	case len(paths) > 1:
		state.Reason = fmt.Sprintf("%d Pod cgroups for one Pod: %s", len(paths), strings.Join(paths, ", "))
	default:
		a, err := p.attach(d, paths[0], now)
		if err != nil {
			state.Reason = err.Error()
			return state, false
		}
		p.attached[d.UID] = a
		p.log.Info("Pod attached", "stage", "attach", "podUID", d.UID, "namespace", d.Namespace, "cgroup", a.path,
			"cgroupID", a.cgroupID, "programIDs", a.progIDs, "enforcementAvailable", false)
		return PodState{}, true
	}
	return state, false
}

// attach loads a copy of the programs for the Pod and attaches both to the Pod cgroup through bpf_links, never
// through the legacy attach that outlives the process.
func (p *Plane) attach(d DesiredPod, path string, now time.Time) (*attachment, error) {
	if err := checkAncestors(p.cgroupRoot, path); err != nil {
		return nil, err
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	// fstat the descriptor that the links use, so the recorded ID is the ID of the cgroup attached to.
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(dir.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, fmt.Errorf("%s is not on cgroup v2", path)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return nil, err
	}
	coll, err := p.collection()
	if err != nil {
		return nil, err
	}
	a := &attachment{id: p.nextID, pod: d, path: path, cgroupID: st.Ino, coll: coll, since: now}
	p.nextID++
	for i, prog := range Programs {
		info, err := coll.Programs[prog.Name].Info()
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("read the ID of %s: %w", prog.Name, err)
		}
		id, ok := info.ID()
		if !ok {
			coll.Close()
			return nil, fmt.Errorf("the kernel reports no ID for %s", prog.Name)
		}
		a.progIDs[i] = id
	}
	// From the first attach on, the arrays may count packets, so a failure from here on goes through detach and
	// retire, which take their final reading.
	for i, prog := range Programs {
		l, err := link.AttachRawLink(link.RawLinkOptions{Target: int(dir.Fd()), Program: coll.Programs[prog.Name],
			Attach: prog.Attach})
		if err != nil {
			err = fmt.Errorf("attach %s to %s: %w", prog.Name, path, err)
			p.detach(a, now, err.Error())
			return nil, err
		}
		a.links[i] = l
	}
	if err := p.verify(a, map[string]programSet{}); err != nil {
		p.detach(a, now, err.Error())
		return nil, err
	}
	return a, nil
}

// verify checks that the Pod cgroup is still the one attached to, that both programs still run for it, and that
// every program that runs for its parent cgroup still runs for it (checkAncestors explains how one could stop).
func (p *Plane) verify(a *attachment, parents map[string]programSet) error {
	var st unix.Stat_t
	if err := unix.Stat(a.path, &st); err != nil {
		return fmt.Errorf("Pod cgroup gone: %w", err)
	}
	if st.Ino != a.cgroupID {
		return fmt.Errorf("Pod cgroup %s was recreated", a.path)
	}
	parentDir := filepath.Dir(a.path)
	for i, prog := range Programs {
		// The parent is read first: a program attached between the two reads then shows in the Pod's list only.
		key := parentDir + " " + prog.Name
		parent, ok := parents[key]
		if !ok {
			var err error
			if parent, err = queryPrograms(parentDir, prog.Attach, unix.BPF_F_QUERY_EFFECTIVE); err != nil {
				return err
			}
			parents[key] = parent
		}
		pod, err := queryPrograms(a.path, prog.Attach, unix.BPF_F_QUERY_EFFECTIVE)
		if err != nil {
			return err
		}
		if !pod[a.progIDs[i]] {
			return fmt.Errorf("program %d no longer runs for %s at %s", a.progIDs[i], a.path, prog.Attach)
		}
		for id := range parent {
			if !pod[id] {
				return fmt.Errorf("program %d runs for %s but not for the Pod cgroup below it: it was attached "+
					"without BPF_F_ALLOW_MULTI, and a program on the Pod cgroup overrides it", id, parentDir)
			}
		}
	}
	return nil
}

// checkAncestors refuses a Pod cgroup below a cgroup that holds cgroup_skb programs attached without
// BPF_F_ALLOW_MULTI. The kernel runs such a program for a cgroup only while no cgroup between the two has a program
// of the same attach type (kernel/bpf/cgroup.c:401-443, compute_effective_progs). A bpf_link always attaches with
// BPF_F_ALLOW_MULTI (cgroup.c:1304-1305), so the plane's program on the Pod cgroup would stop that program for the
// Pod: an observer would change a verdict.
//
// The walk reads every cgroup from the Pod cgroup's parent up to root, the top of the mount. A program that runs for
// root but is not attached to it comes from a cgroup above the mount (a nested container, as on kind), whose flags
// the loader cannot read; that is refused too. verify catches a program attached after the plane's own.
func checkAncestors(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("Pod cgroup %s is not below %s", path, root)
	}
	for _, prog := range Programs {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			count, flags, err := attachedPrograms(dir, prog.Attach)
			if err != nil {
				return err
			}
			if count > 0 && flags&unix.BPF_F_ALLOW_MULTI == 0 {
				return fmt.Errorf("cgroup %s holds %d %s program(s) attached without BPF_F_ALLOW_MULTI (flags %#x); "+
					"a program on the Pod cgroup would stop them for the Pod", dir, count, prog.Attach, flags)
			}
			if dir == root {
				break
			}
		}
		own, err := queryPrograms(root, prog.Attach, 0)
		if err != nil {
			return err
		}
		running, err := queryPrograms(root, prog.Attach, unix.BPF_F_QUERY_EFFECTIVE)
		if err != nil {
			return err
		}
		for id := range running {
			if !own[id] {
				return fmt.Errorf("%s program %d runs for %s from a cgroup above the mount, whose attach flags "+
					"cannot be read", prog.Attach, id, root)
			}
		}
	}
	return nil
}

// progQueryAttr is the BPF_PROG_QUERY member of union bpf_attr (include/uapi/linux/bpf.h). cilium/ebpf's
// link.QueryPrograms does not return the attach flags, which checkAncestors needs. The struct has every field up to
// revision, so it holds whatever a newer kernel writes back.
type progQueryAttr struct {
	targetFD        uint32
	attachType      uint32
	queryFlags      uint32
	attachFlags     uint32
	progIDs         uint64
	progCount       uint32
	_               uint32
	progAttachFlags uint64
	linkIDs         uint64
	linkAttachFlags uint64
	revision        uint64
}

// attachedPrograms returns how many programs of the attach type are attached to the cgroup itself (not inherited),
// and the flags they were attached with.
func attachedPrograms(dir string, attach ebpf.AttachType) (count, flags uint32, err error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	attr := progQueryAttr{targetFD: uint32(f.Fd()), attachType: kernelAttachType[attach]}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, 0, fmt.Errorf("query the %s programs of %s: %w", attach, dir, errno)
	}
	return attr.progCount, attr.attachFlags, nil
}

// queryPrograms returns the programs of the attach type attached to the cgroup itself (flags 0), or every program
// that runs for it, its own and the inherited ones (flags BPF_F_QUERY_EFFECTIVE).
func queryPrograms(dir string, attach ebpf.AttachType, flags uint32) (programSet, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := link.QueryPrograms(link.QueryOptions{Target: int(f.Fd()), Attach: attach, QueryFlags: flags})
	if err != nil {
		return nil, fmt.Errorf("query the %s programs of %s: %w", attach, dir, err)
	}
	set := programSet{}
	for _, prog := range r.Programs {
		set[prog.ID] = true
	}
	return set, nil
}

func (a *attachment) closeLinks() {
	for i, l := range a.links {
		if l != nil {
			_ = l.Close()
			a.links[i] = nil
		}
	}
}

// detach closes the Pod's links and queues the attachment for retire.
func (p *Plane) detach(a *attachment, now time.Time, reason string) {
	a.closeLinks()
	delete(p.attached, a.pod.UID)
	a.since = now
	p.retiring = append(p.retiring, a)
	p.log.Info("Pod detached", "stage", "detach", "podUID", a.pod.UID, "namespace", a.pod.Namespace,
		"reason", reason, "enforcementAvailable", false)
}

// retire takes the final reading of each detached Pod's arrays after retireDelay, then closes its programs and
// arrays.
func (p *Plane) retire(now time.Time) {
	keep := p.retiring[:0]
	for _, a := range p.retiring {
		if now.Sub(a.since) < retireDelay {
			keep = append(keep, a)
			continue
		}
		if err := p.observe(a, now); err != nil {
			p.log.Error(err, "final reading of a detached Pod lost", "stage", "retire", "podUID", a.pod.UID,
				"namespace", a.pod.Namespace)
		}
		p.retired.add(a.stats())
		p.acc.Release(a.id)
		a.coll.Close()
	}
	p.retiring = keep
}

func (p *Plane) observe(a *attachment, now time.Time) error {
	c, err := readPodCounters(a.coll.Maps[MapTraffic], a.coll.Maps[MapDNS], p.possibleCPU)
	if err != nil {
		return err
	}
	return p.acc.Observe(a.id, a.pod.Namespace, c, now)
}

// readPodCounters reads a Pod's two counter arrays and sums each cell over the CPUs.
func readPodCounters(traffic, dns *ebpf.Map, cpus int) (PodCounters, error) {
	var t [TrafficCells]Counter
	err := readCells(traffic, TrafficCells, cpus, func(cell int, v Counter) {
		t[cell].Packets += v.Packets
		t[cell].Bytes += v.Bytes
	})
	if err != nil {
		return PodCounters{}, fmt.Errorf("read %s: %w", MapTraffic, err)
	}
	var d [PodDNSCells]uint64
	if err := readCells(dns, PodDNSCells, cpus, func(cell int, v uint64) { d[cell] += v }); err != nil {
		return PodCounters{}, fmt.Errorf("read %s: %w", MapDNS, err)
	}
	return PodCountersFromCells(t, d), nil
}

// readNodeCounters reads cmtc_node and sums each cell over the CPUs.
func readNodeCounters(node *ebpf.Map, cpus int) (NodeCounters, error) {
	var n [NodeCells]uint64
	if err := readCells(node, NodeCells, cpus, func(cell int, v uint64) { n[cell] += v }); err != nil {
		return NodeCounters{}, fmt.Errorf("read %s: %w", MapNode, err)
	}
	return NodeCountersFromCells(n), nil
}

// readCells reads every cell of a per-CPU array map of cells cells in one BPF_MAP_LOOKUP_BATCH call, and calls add
// with the value of each cell on each possible CPU. The kernel returns the cells in key order, each with one value per
// possible CPU.
func readCells[T Counter | uint64](m *ebpf.Map, cells, cpus int, add func(cell int, value T)) error {
	keys := make([]uint32, cells)
	values := make([]T, cells*cpus)
	var cursor ebpf.MapBatchCursor
	n, err := m.BatchLookup(&cursor, keys, values, nil)
	// ErrKeyNotExist only says that the batch reached the end of the array.
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if n != cells {
		return fmt.Errorf("%d of %d cells read", n, cells)
	}
	for i, key := range keys {
		if key != uint32(i) {
			return fmt.Errorf("cell %d returned at position %d", key, i)
		}
	}
	for i, v := range values {
		add(i/cpus, v)
	}
	return nil
}

// Read samples the counters of every attached Pod and the node counters.
func (p *Plane) Read(now time.Time) {
	if p.loadErr != nil {
		return
	}
	for _, a := range p.attached {
		if err := p.observe(a, now); err != nil {
			// A Pod whose counters cannot be read is detached; Reconcile attaches it again with new arrays.
			p.detach(a, now, "read counters: "+err.Error())
		}
	}
	if n, err := readNodeCounters(p.maps[MapNode], p.possibleCPU); err != nil {
		p.log.Error(err, "node counters not read", "stage", "read")
	} else {
		p.node = n
	}
	p.acc.Prune(now, NamespaceRetention)
}

func (a *attachment) stats() ProgramStats {
	var s ProgramStats
	for i, prog := range Programs {
		st, err := a.coll.Programs[prog.Name].Stats()
		if err != nil {
			continue
		}
		s.RunTimeNs[i] = uint64(st.Runtime)
		s.Runs[i] = st.RunCount
	}
	return s
}

func (s *ProgramStats) add(o ProgramStats) {
	for i := range s.Runs {
		s.RunTimeNs[i] += o.RunTimeNs[i]
		s.Runs[i] += o.Runs[i]
	}
}

// Snapshot returns the state and counters that the node agent exports.
func (p *Plane) Snapshot(bootID string, monotonicNs int64) Snapshot {
	loaded := p.loadErr == nil
	s := Snapshot{Version: ExchangeVersion, BootID: bootID, MonotonicNs: monotonicNs, Execution: p.execution,
		Hooks: map[string]bool{HookEgress: loaded, HookIngress: loaded,
			HookNodeAddresses: loaded && p.nodeAddressesOK, HookProgramStats: loaded && statsEnabled()},
		Pods: []PodState{}, Namespaces: p.acc.Totals(), Node: p.node}
	for _, a := range p.attached {
		s.Pods = append(s.Pods, PodState{UID: a.pod.UID, Namespace: a.pod.Namespace, State: StateAttached})
	}
	for _, st := range p.states {
		s.Pods = append(s.Pods, st)
	}
	sort.Slice(s.Pods, func(i, j int) bool { return s.Pods[i].UID < s.Pods[j].UID })
	if s.Hooks[HookProgramStats] {
		// Detached programs keep counting in the total until they are retired, so the total never decreases.
		total := p.retired
		for _, a := range p.attached {
			total.add(a.stats())
		}
		for _, a := range p.retiring {
			total.add(a.stats())
		}
		s.Programs = &total
	}
	return s
}

// statsEnabled reports kernel.bpf_stats_enabled, which the node owner sets; the loader cannot.
func statsEnabled() bool {
	b, err := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// Close detaches every program and releases every kernel object.
func (p *Plane) Close() error {
	for _, a := range p.attached {
		a.closeLinks()
		a.coll.Close()
	}
	for _, a := range p.retiring {
		a.coll.Close()
	}
	p.attached, p.retiring = map[string]*attachment{}, nil
	var errs []error
	for _, m := range p.maps {
		errs = append(errs, m.Close())
	}
	return errors.Join(errs...)
}
