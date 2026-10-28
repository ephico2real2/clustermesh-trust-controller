package measurement

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
)

// The node agent and the loader share two emptyDir volumes. The agent writes DesiredFile into one and the loader
// writes SnapshotFile into the other; each container mounts the other's volume read-only.
const (
	DesiredFile  = "desired.json"
	SnapshotFile = "snapshot.json"
	// ExchangeVersion is the version of both files. A reader refuses any other.
	ExchangeVersion = 1

	maxExchangeBytes = 4 << 20
	maxDesiredPods   = 4096
)

// Desired is the node agent's list of the Pods the loader measures.
type Desired struct {
	Version int          `json:"version"`
	Node    string       `json:"node"`
	Pods    []DesiredPod `json:"pods"`
	// NodeAddresses are the IP addresses of every Pod on this node, enrolled or not, hostNetwork included. A DNS
	// server at one of them is on the same node.
	NodeAddresses []string `json:"nodeAddresses"`
}

// DesiredPod is one enrolled Pod of the node.
type DesiredPod struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	// Required is true for a Running Pod that is not terminating. The plane is ready only when every Pod required
	// for AttachGrace is attached. A Pending Pod may have no cgroup yet, and a terminating Pod loses its cgroup
	// before it leaves the API, so neither is required; both are measured while their cgroup exists.
	Required bool `json:"required"`
}

// Snapshot is the loader's state and counters, rewritten every second.
type Snapshot struct {
	Version int `json:"version"`
	// BootID and MonotonicNs date the snapshot on the kernel's monotonic clock, which the agent reads too. Wall time
	// is never compared: the lab's guest clock has been stepped backwards.
	BootID      string `json:"bootID"`
	MonotonicNs int64  `json:"monotonicNs"`
	// Execution identifies one run of the loader; it changes when the loader restarts and its counters restart.
	Execution  string                 `json:"execution"`
	Hooks      map[string]bool        `json:"hooks"`
	Pods       []PodState             `json:"pods"`
	Namespaces map[string]PodCounters `json:"namespaces"`
	Node       NodeCounters           `json:"node"`
	Programs   *ProgramStats          `json:"programs,omitempty"`
}

// PodState is the loader's state for one desired Pod. Reason explains an unavailable Pod; it goes to logs, never to
// metric labels.
type PodState struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}

// ProgramStats are the kernel's run statistics of the programs, by direction. They exist only while
// kernel.bpf_stats_enabled=1.
type ProgramStats struct {
	RunTimeNs [NumDirections]uint64 `json:"runTimeNs"`
	Runs      [NumDirections]uint64 `json:"runs"`
}

var (
	podUIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	validStates      = map[string]bool{StateAttached: true, StateWaiting: true, StateUnavailable: true}
)

// Validate rejects a desired list the loader must not act on.
func (d Desired) Validate() error {
	if d.Version != ExchangeVersion {
		return fmt.Errorf("desired version %d, want %d", d.Version, ExchangeVersion)
	}
	if len(d.Pods) > maxDesiredPods {
		return fmt.Errorf("desired list has %d Pods, more than %d", len(d.Pods), maxDesiredPods)
	}
	seen := make(map[string]bool, len(d.Pods))
	for _, p := range d.Pods {
		if !podUIDPattern.MatchString(p.UID) || !namespacePattern.MatchString(p.Namespace) {
			return fmt.Errorf("invalid desired Pod %q in namespace %q", p.UID, p.Namespace)
		}
		if seen[p.UID] {
			return fmt.Errorf("duplicate desired Pod %q", p.UID)
		}
		seen[p.UID] = true
	}
	for _, a := range d.NodeAddresses {
		if addr, err := netip.ParseAddr(a); err != nil || addr.Zone() != "" || addr.String() != a {
			return fmt.Errorf("invalid node address %q", a)
		}
	}
	return nil
}

// Validate rejects a snapshot whose names could not be metric label values.
func (s Snapshot) Validate() error {
	if s.Version != ExchangeVersion {
		return fmt.Errorf("snapshot version %d, want %d", s.Version, ExchangeVersion)
	}
	for ns := range s.Namespaces {
		if !namespacePattern.MatchString(ns) {
			return fmt.Errorf("invalid snapshot namespace %q", ns)
		}
	}
	for _, p := range s.Pods {
		if !podUIDPattern.MatchString(p.UID) || !namespacePattern.MatchString(p.Namespace) || !validStates[p.State] {
			return fmt.Errorf("invalid snapshot Pod %q in namespace %q with state %q", p.UID, p.Namespace, p.State)
		}
	}
	return nil
}

// Fresh reports why a snapshot must not be exported, or nil. The snapshot must come from this boot and be at most
// SnapshotMaxAge old on the monotonic clock.
func (s Snapshot) Fresh(bootID string, nowNs int64) error {
	if s.BootID == "" || s.BootID != bootID {
		return errors.New("snapshot is from another boot")
	}
	age := nowNs - s.MonotonicNs
	if age < 0 {
		return errors.New("snapshot is newer than the clock that reads it")
	}
	if age > SnapshotMaxAge.Nanoseconds() {
		// A fixed message: the agent logs each change of reason, not each second of age.
		return fmt.Errorf("snapshot older than %s", SnapshotMaxAge)
	}
	return nil
}

// WriteFileAtomic replaces dir/name with the JSON form of v. Readers see the old file or the new one, never a part
// of one. The file is world-readable because the other container runs as another user.
func WriteFileAtomic(dir, name string, v any) (err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

// ReadDesired reads and validates the agent's desired list.
func ReadDesired(path string) (Desired, error) {
	var d Desired
	if err := readExchange(path, &d); err != nil {
		return Desired{}, err
	}
	return d, d.Validate()
}

// ReadSnapshot reads and validates the loader's snapshot.
func ReadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	if err := readExchange(path, &s); err != nil {
		return Snapshot{}, err
	}
	return s, s.Validate()
}

func readExchange(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxExchangeBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxExchangeBytes {
		return fmt.Errorf("%s exceeds %d bytes", path, maxExchangeBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return fmt.Errorf("%s holds more than one JSON value", path)
	}
	return nil
}
