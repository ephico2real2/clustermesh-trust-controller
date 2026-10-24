//go:build linux

package datapath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func unitFenceConfig() FenceConfig {
	return FenceConfig{Cluster: "cluster-a", Node: "node-a", NamespaceUID: "namespace-uid", PodUID: "pod-uid", NetNSInode: 7, IfIndex: 2, IfName: "lxc-test", MAC: "02:00:00:00:00:01", PeerIfIndex: 3, Direction: "ingress", CiliumLinkID: 11, CiliumProgramID: 12, PinRoot: "/sys/fs/bpf/cmtc-fence", LockRoot: "/run/cmtc-fence-locks"}
}
func TestFenceConfigRejectsIncompleteUnsafeAndReserved(t *testing.T) {
	for name, change := range map[string]func(*FenceConfig){
		"namespaceUID": func(c *FenceConfig) { c.NamespaceUID = "" }, "podUID": func(c *FenceConfig) { c.PodUID = "" }, "clusterWhitespace": func(c *FenceConfig) { c.Cluster = " a" }, "nodeNUL": func(c *FenceConfig) { c.Node = "n\x00x" }, "namespaceSlash": func(c *FenceConfig) { c.NamespaceUID = "a/b" },
		"pinRootSymlinkSyntax": func(c *FenceConfig) { c.PinRoot = "/sys/fs/bpf/../bpf/test" }, "relativeLock": func(c *FenceConfig) { c.LockRoot = "run/locks" }, "ciliumPinRoot": func(c *FenceConfig) { c.PinRoot = "/sys/fs/bpf/cilium/owned" }, "globalPinRoot": func(c *FenceConfig) { c.PinRoot = "/sys/fs/bpf" }, "sameRoot": func(c *FenceConfig) { c.LockRoot = c.PinRoot },
		"host": func(c *FenceConfig) { c.IfName = "cilium_host" }, "loopback": func(c *FenceConfig) { c.IfName = "lo" }, "kube": func(c *FenceConfig) { c.IfName = "kube-ipvs0" }, "badMAC": func(c *FenceConfig) { c.MAC = "02:00:00:00:00:AA" }, "unknownDirection": func(c *FenceConfig) { c.Direction = "both" },
	} {
		t.Run(name, func(t *testing.T) {
			c := unitFenceConfig()
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	if err := unitFenceConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestFenceOwnershipKeyAndFullIncarnationDigest(t *testing.T) {
	c := unitFenceConfig()
	other := c
	other.IfIndex++
	if c.key() != other.key() || c.hash() == other.hash() {
		t.Fatal("replacement sandbox must address same ownership record but fail full binding")
	}
	for _, change := range []func(*FenceConfig){func(c *FenceConfig) { c.NamespaceUID += "new" }, func(c *FenceConfig) { c.PodUID += "new" }, func(c *FenceConfig) { c.Cluster += "new" }, func(c *FenceConfig) { c.Node += "new" }, func(c *FenceConfig) { c.Direction = "egress" }} {
		other = c
		change(&other)
		if c.key() == other.key() {
			t.Fatal("ownership key collides after ownership reuse")
		}
	}
}
func TestFenceDirectoryRejectsSymlinkAndPermissions(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	held, err := fenceOpenDirectory(private)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	sym := filepath.Join(root, "symlink")
	if err = os.Symlink(private, sym); err != nil {
		t.Fatal(err)
	}
	if f, err := fenceOpenDirectory(sym); err == nil {
		f.Close()
		t.Fatal("followed symlink")
	}
	if err = os.Chmod(private, 0750); err != nil {
		t.Fatal(err)
	}
	if f, err := fenceOpenDirectory(private); err == nil {
		f.Close()
		t.Fatal("accepted group readable root")
	}
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(private, private+"-old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err = fenceSameDirectory(private, held); !errors.Is(err, ErrFenceUnsafe) {
		t.Fatalf("path replacement not rejected: %v", err)
	}
}
func TestFencePrivateLockFileRejectsHardlinkNonemptyAndPermissions(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "lock")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = fencePrivateFile(f); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(name, name+"alias"); err != nil {
		t.Fatal(err)
	}
	if err = fencePrivateFile(f); !errors.Is(err, ErrFenceUnsafe) {
		t.Fatalf("hardlinked lock accepted: %v", err)
	}
	if err = os.Remove(name + "alias"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = fencePrivateFile(f); !errors.Is(err, ErrFenceUnsafe) {
		t.Fatalf("nonempty lock accepted: %v", err)
	}
	if err = f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if err = f.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	if err = fencePrivateFile(f); !errors.Is(err, ErrFenceUnsafe) {
		t.Fatalf("public lock accepted: %v", err)
	}
}
func TestFenceLockNeverBlocksAndDetectsReplacement(t *testing.T) {
	root, locks := t.TempDir(), t.TempDir()
	for _, path := range []string{root, locks} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := unitFenceConfig()
	name := c.key()
	if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
		t.Fatal(err)
	}
	rd, err := fenceOpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := fenceOpenDirectory(locks)
	if err != nil {
		rd.Close()
		t.Fatal(err)
	}
	dd, err := fenceOpenDirectory(filepath.Join(root, name))
	if err != nil {
		rd.Close()
		ld.Close()
		t.Fatal(err)
	}
	path := filepath.Join(locks, name+".lock")
	owner, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		rd.Close()
		ld.Close()
		dd.Close()
		t.Fatal(err)
	}
	fs := &fenceFS{root: rd, locks: ld, dir: dd, owner: owner, rootPath: root, lockPath: locks, name: name}
	defer fs.close()
	if err = unix.Flock(int(owner.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("second process owner not excluded: %v", err)
	}
	if err = fs.validate(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+"old"); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Close()
	if err = fs.validate(); !errors.Is(err, ErrFenceUnsafe) {
		t.Fatalf("replaced lock inode accepted: %v", err)
	}
}
func TestFenceClosedCannotVerifyAndReleaseIsIdempotent(t *testing.T) {
	f := &Fence{closed: true}
	if _, err := f.Account(); !errors.Is(err, ErrFenceClosed) {
		t.Fatalf("closed account: %v", err)
	}
	for range 2 {
		if err := f.ReleaseProcess(); err != nil {
			t.Fatal(err)
		}
	}
}
