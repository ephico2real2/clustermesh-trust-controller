//go:build linux && cmtc_bpf_privileged

package measurement

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// These tests run the loader binary, cmd/cmtc-measure, as the DaemonSet runs it: root with CAP_BPF and CAP_NET_ADMIN
// only and no API token. setpriv (util-linux) removes every other capability from all five sets before it starts the
// binary, as the container runtime does for "drop: [ALL], add: [BPF, NET_ADMIN]". scripts/measurement/test-kernel.sh
// builds the binary and names it in CMTC_MEASURE_BIN.

// loaderCapabilities is the loader container's capability set, in setpriv's syntax.
const loaderCapabilities = "-all,+bpf,+net_admin"

// kubelet mounts a Pod's API token here; cmd/cmtc-measure refuses to start when the file exists.
const (
	secretsDir = "/var/run/secrets"
	tokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// loaderRun is one loader with its own cgroup tree, one Pod and the two exchange directories. The loader sees the
// tree through a read-only view, as the DaemonSet mounts the host's cgroup tree into it.
type loaderRun struct {
	tree                    cgroupTree
	view                    string
	pod                     string
	desiredDir, snapshotDir string
}

// newLoaderRun prepares a run whose desired list, written as the agent writes it, requires the run's Pod.
func newLoaderRun(t *testing.T) loaderRun {
	t.Helper()
	r := newLoaderRunWithoutList(t)
	r.writeDesired(t)
	return r
}

// newLoaderRunWithoutList prepares a run whose agent has not written a desired list yet.
func newLoaderRunWithoutList(t *testing.T) loaderRun {
	t.Helper()
	tree := newCgroupTree(t)
	r := loaderRun{tree: tree, pod: tree.createPod(t, testUID), desiredDir: t.TempDir(), snapshotDir: t.TempDir()}
	r.view = readOnlyView(t, tree.root)
	return r
}

func (r loaderRun) writeDesired(t *testing.T) {
	t.Helper()
	d := Desired{Version: ExchangeVersion, Node: "test-node", NodeAddresses: []string{},
		Pods: []DesiredPod{{UID: testUID, Namespace: testNamespace, Required: true}}}
	if err := WriteFileAtomic(r.desiredDir, DesiredFile, d); err != nil {
		t.Fatal(err)
	}
}

// command returns the loader started with caps, a capability set in setpriv's syntax, or with every capability of
// root when caps is empty.
func (r loaderRun) command(t *testing.T, caps string) *exec.Cmd {
	t.Helper()
	bin := os.Getenv("CMTC_MEASURE_BIN")
	if bin == "" {
		t.Fatal("CMTC_MEASURE_BIN must name the cmtc-measure binary; scripts/measurement/test-kernel.sh builds it")
	}
	args := []string{"--cgroup-root=" + r.view, "--desired-dir=" + r.desiredDir, "--snapshot-dir=" + r.snapshotDir}
	if caps == "" {
		return exec.Command(bin, args...)
	}
	setpriv := []string{"--bounding-set=" + caps, "--inh-caps=-all", "--ambient-caps=-all", "--", bin}
	return exec.Command("setpriv", append(setpriv, args...)...)
}

// readOnlyView bind-mounts dir read-only on a new directory and returns that directory.
func readOnlyView(t *testing.T, dir string) string {
	t.Helper()
	view := t.TempDir()
	if err := unix.Mount(dir, view, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind-mount %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(view, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount %s: %v", view, err)
		}
	})
	if err := unix.Mount("", view, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatalf("make %s read-only: %v", view, err)
	}
	if err := unix.Mkdir(filepath.Join(view, "cmtc-test-write"), 0o755); !errors.Is(err, unix.EROFS) {
		t.Fatalf("mkdir in the read-only view returned %v, want EROFS", err)
	}
	return view
}

// mountToken creates the file where kubelet mounts a Pod's API token. It refuses to run where /var/run/secrets
// exists, so that it never removes a real token.
func mountToken(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(secretsDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists (%v); run the kernel tests in a disposable container", secretsDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(secretsDir) })
	if err := os.WriteFile(tokenPath, []byte("not a token"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoaderRefusesMorePrivilegeThanItNeeds(t *testing.T) {
	requirePrivileged(t)
	for _, c := range []struct {
		name, caps string
		token      bool
		want       string
	}{
		{"every capability of root", "", false, "the effective capability set holds CAP_CHOWN"},
		{"CAP_PERFMON as well", "-all,+bpf,+net_admin,+perfmon", false,
			"the effective capability set holds CAP_PERFMON beyond"},
		{"CAP_SYS_ADMIN as well", "-all,+bpf,+net_admin,+sys_admin", false,
			"the effective capability set holds CAP_SYS_ADMIN beyond"},
		{"CAP_BPF without CAP_NET_ADMIN", "-all,+bpf", false, "the effective capability set lacks CAP_NET_ADMIN"},
		{"an API token", loaderCapabilities, true, "an API token is mounted at " + tokenPath},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newLoaderRun(t)
			if c.token {
				mountToken(t)
			}
			out, err := r.command(t, c.caps).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("loader ended with %v, want exit status 1\n%s", err, out)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("loader output lacks %q:\n%s", c.want, out)
			}
			requireNoPrograms(t, r.pod)
			if _, err := os.Stat(filepath.Join(r.snapshotDir, SnapshotFile)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the loader wrote a snapshot before it refused to start (%v)", err)
			}
		})
	}
}

// With exactly its capabilities the loader attaches both programs to the desired Pod. However it stops, the kernel
// detaches them: the loader holds its bpf_links by descriptor only and pins nothing.
func TestLoaderAttachesAndLeavesNoProgramWhenItStops(t *testing.T) {
	requirePrivileged(t)
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(sig.String(), func(t *testing.T) {
			r := newLoaderRun(t)
			cmd := r.command(t, loaderCapabilities)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})

			s := waitForSnapshot(t, r.snapshotDir, func(s Snapshot) bool {
				return len(s.Pods) == 1 && s.Pods[0].State == StateAttached
			})
			if !s.Hooks[HookEgress] || !s.Hooks[HookIngress] || s.Execution == "" {
				t.Fatalf("snapshot hooks %v execution %q", s.Hooks, s.Execution)
			}
			for _, prog := range Programs {
				ids := running(t, r.pod, prog.Attach)
				if len(ids) != 1 {
					t.Fatalf("%d %s programs run for the Pod cgroup, want 1", len(ids), prog.Attach)
				}
				for id := range ids {
					requireProgramName(t, id, prog.Name)
				}
			}

			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			waited = true
			if sig == syscall.SIGTERM {
				if err != nil {
					t.Fatalf("loader ended with %v after SIGTERM, want exit status 0\n%s", err, out.String())
				}
				if !strings.Contains(out.String(), "every program detached") {
					t.Fatalf("loader output lacks its stop message:\n%s", out.String())
				}
			}
			requireNoPrograms(t, r.pod)
		})
	}
}

// Until the agent writes its first list, the loader attaches nothing and reports the node's addresses unavailable:
// it has none, so it could not tell a same_node DNS server from an off_node one.
func TestLoaderReportsNoNodeAddressesBeforeTheAgentsList(t *testing.T) {
	requirePrivileged(t)
	r := newLoaderRunWithoutList(t)
	cmd := r.command(t, loaderCapabilities)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	s := waitForSnapshot(t, r.snapshotDir, func(Snapshot) bool { return true })
	want := map[string]bool{HookEgress: true, HookIngress: true, HookNodeAddresses: false,
		HookProgramStats: s.Hooks[HookProgramStats]}
	if !reflect.DeepEqual(s.Hooks, want) || len(s.Pods) != 0 {
		t.Fatalf("snapshot before the agent's list: hooks %v, Pods %+v; want hooks %v and no Pod\n%s", s.Hooks, s.Pods,
			want, out.String())
	}
	requireNoPrograms(t, r.pod)

	r.writeDesired(t)
	waitForSnapshot(t, r.snapshotDir, func(s Snapshot) bool {
		return s.Hooks[HookNodeAddresses] && len(s.Pods) == 1 && s.Pods[0].State == StateAttached
	})
}

// waitForSnapshot reads the loader's snapshot every 100ms until done accepts it, for at most 10s. The loader writes it
// every second.
func waitForSnapshot(t *testing.T, dir string, done func(Snapshot) bool) Snapshot {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, err := ReadSnapshot(filepath.Join(dir, SnapshotFile))
		if err == nil && done(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("no snapshot in the expected state within 10s: last %+v, error %v", s, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// requireProgramName fails unless the program with id is the measurement program name. The kernel keeps only the first
// 15 bytes of a name (BPF_OBJ_NAME_LEN); cilium/ebpf reads the whole name from the program's BTF function info.
func requireProgramName(t *testing.T, id ebpf.ProgramID, name string) {
	t.Helper()
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != name {
		t.Fatalf("program %d is %q, want %q", id, info.Name, name)
	}
}
