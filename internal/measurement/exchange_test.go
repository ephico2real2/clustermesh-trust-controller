package measurement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	uidA = "4f9d2c3e-7a1b-4c5d-9e8f-0a1b2c3d4e5f"
	uidB = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
)

func validDesired() Desired {
	return Desired{Version: ExchangeVersion, Node: "node-a", NodeAddresses: []string{"10.0.0.5", "fd00::5"},
		Pods: []DesiredPod{{UID: uidA, Namespace: "shop", Required: true}, {UID: uidB, Namespace: "shop"}}}
}

func TestDesiredValidate(t *testing.T) {
	if err := validDesired().Validate(); err != nil {
		t.Fatalf("valid desired list refused: %v", err)
	}
	for _, c := range []struct {
		name   string
		change func(*Desired)
		want   string
	}{
		{"another version", func(d *Desired) { d.Version = 2 }, "desired version 2"},
		{"a UID that is not a UID", func(d *Desired) { d.Pods[0].UID = "../../etc" }, "invalid desired Pod"},
		{"an upper-case namespace", func(d *Desired) { d.Pods[0].Namespace = "Shop" }, "invalid desired Pod"},
		{"a duplicate Pod", func(d *Desired) { d.Pods[1].UID = uidA }, "duplicate desired Pod"},
		{"an address with a zone", func(d *Desired) { d.NodeAddresses = []string{"fe80::1%eth0"} }, "invalid node address"},
		{"an address not in its canonical form", func(d *Desired) { d.NodeAddresses = []string{"fd00:0::5"} },
			"invalid node address"},
		{"too many Pods", func(d *Desired) {
			d.Pods = make([]DesiredPod, maxDesiredPods+1)
		}, "more than 4096"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := validDesired()
			c.change(&d)
			if err := d.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Validate = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestSnapshotValidate(t *testing.T) {
	s := Snapshot{Version: ExchangeVersion, Pods: []PodState{{UID: uidA, Namespace: "shop", State: StateAttached}},
		Namespaces: map[string]PodCounters{"shop": {}}}
	if err := s.Validate(); err != nil {
		t.Fatalf("valid snapshot refused: %v", err)
	}
	bad := s
	bad.Namespaces = map[string]PodCounters{`shop",evil="1`: {}}
	if err := bad.Validate(); err == nil {
		t.Fatal("a namespace that is no label value was accepted")
	}
	bad = s
	bad.Pods = []PodState{{UID: uidA, Namespace: "shop", State: "enforcing"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("an unknown state was accepted")
	}
}

func TestSnapshotFresh(t *testing.T) {
	s := Snapshot{BootID: "boot-1", MonotonicNs: 10 * int64(time.Second)}
	if err := s.Fresh("boot-1", s.MonotonicNs+SnapshotMaxAge.Nanoseconds()); err != nil {
		t.Fatalf("a snapshot SnapshotMaxAge old is refused: %v", err)
	}
	for _, c := range []struct {
		name string
		boot string
		now  int64
		want string
	}{
		{"older than SnapshotMaxAge", "boot-1", s.MonotonicNs + SnapshotMaxAge.Nanoseconds() + 1, "older than 3s"},
		{"from another boot", "boot-2", s.MonotonicNs, "another boot"},
		{"newer than the reader's clock", "boot-1", s.MonotonicNs - 1, "newer than the clock"},
	} {
		if err := s.Fresh(c.boot, c.now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Fresh = %v, want an error containing %q", c.name, err, c.want)
		}
	}
	if err := (Snapshot{}).Fresh("", 0); err == nil {
		t.Error("a snapshot without a boot ID was accepted")
	}
}

func TestExchangeFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := validDesired()
	if err := WriteFileAtomic(dir, DesiredFile, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDesired(filepath.Join(dir, DesiredFile))
	if err != nil {
		t.Fatal(err)
	}
	if got.Node != want.Node || len(got.Pods) != 2 || got.Pods[0] != want.Pods[0] || len(got.NodeAddresses) != 2 {
		t.Fatalf("read %+v, wrote %+v", got, want)
	}
	info, err := os.Stat(filepath.Join(dir, DesiredFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644: the other container runs as another user", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d files in the directory, want only %s", len(entries), DesiredFile)
	}
}

func TestReadExchangeRefusesWhatItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, content, want string
	}{
		{"an unknown field", `{"version":1,"node":"n","pods":[],"nodeAddresses":[],"enforce":true}`, "unknown field"},
		{"two JSON values", `{"version":1,"node":"n","pods":[],"nodeAddresses":[]} {}`, "more than one JSON value"},
		{"more than 4 MiB", `{"version":1,"node":"` + strings.Repeat("n", maxExchangeBytes) + `"}`, "exceeds"},
		{"another version", `{"version":2,"node":"n","pods":[],"nodeAddresses":[]}`, "desired version 2"},
	} {
		path := filepath.Join(dir, "desired-"+strings.ReplaceAll(c.name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadDesired(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: ReadDesired = %v, want an error containing %q", c.name, err, c.want)
		}
	}
}
