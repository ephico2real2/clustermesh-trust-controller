//go:build linux && cmtc_bpf_privileged

package datapath

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Additional real kernel tests. Uses fixture/newFixture/requirePrivileged from
// observer_privileged_test.go. Run sequentially in the private owned test
// container network namespace, never on a kind node or host network namespace.

type observerChild struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error // Read only after done closes.
	logPath string
}

func requireObserverBinary(t *testing.T) string {
	t.Helper()
	p := os.Getenv("CMTC_BPF_OBSERVER_BIN")
	if p == "" {
		t.Fatal("CMTC_BPF_OBSERVER_BIN must point to the freshly built static observer binary")
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode()&0111 == 0 {
		t.Fatalf("observer binary not executable: %s (%v)", p, err)
	}
	return p
}

func startObserverChild(t *testing.T, f fixture, binary string) *observerChild {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, data, 0400); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "observer.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.Command(binary, "--config="+cfgPath, "--elf="+os.Getenv("CMTC_BPF_ELF"))
	// Do not inherit parent-owned BPF link/program/netlink FDs. os/exec closes
	// non-ExtraFiles descriptors through CLOEXEC; ExtraFiles remains empty.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "NODE_NAME=") && !strings.HasPrefix(entry, "CLUSTER_NAME=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "NODE_NAME="+f.cfg.Node, "CLUSTER_NAME="+f.cfg.Cluster)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	child := &observerChild{cmd: cmd, done: make(chan struct{}), logPath: logPath}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { child.err = cmd.Wait(); close(child.done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-child.done:
		case <-time.After(5 * time.Second):
			t.Errorf("child %d failed to reap", cmd.Process.Pid)
		}
	})
	return child
}

func childLog(c *observerChild) string {
	data, err := os.ReadFile(c.logPath)
	if err != nil {
		return fmt.Sprintf("read child log: %v", err)
	}
	return string(data)
}

func waitChildReady(t *testing.T, c *observerChild, cfg Config, baseline []attachment) attachment {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-c.done:
			t.Fatalf("observer exited before ready: %v\n%s", c.err, childLog(c))
		default:
		}
		_, ids, err := query(cfg)
		if err == nil && len(ids) == len(baseline)+1 && reflect.DeepEqual(ids[1:], baseline) {
			resp, err := client.Get("http://127.0.0.1:18082/readyz")
			if err == nil {
				code := resp.StatusCode
				_ = resp.Body.Close()
				if code == http.StatusOK {
					return ids[0]
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("observer did not become ready with exact foreign baseline\n%s", childLog(c))
	return attachment{}
}

func killAndReapObserver(t *testing.T, c *observerChild) {
	t.Helper()
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL child: %v\n%s", err, childLog(c))
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("SIGKILL child not reaped")
	}
	var exit *exec.ExitError
	if !errors.As(c.err, &exit) {
		t.Fatalf("want signaled ExitError, got %v", c.err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("child did not exit due to actual SIGKILL: %v", exit.Sys())
	}
}

func requireExactChain(t *testing.T, cfg Config, want []attachment) {
	t.Helper()
	_, got, err := query(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TCX chain mismatch: got %v want %v", got, want)
	}
}

func TestPrivilegedSubprocessSIGKILLRestartPreservesForeignLink(t *testing.T) {
	_ = requirePrivileged(t)
	binary := requireObserverBinary(t)
	// Fixed loopback port is part of the primary's intentionally narrow CLI.
	// Refuse a busy port instead of accepting another process's readiness.
	listener, err := net.Listen("tcp", "127.0.0.1:18082")
	if err != nil {
		t.Fatalf("private test namespace observer port already occupied: %v", err)
	}
	_ = listener.Close()
	f := newFixture(t)
	_, baseline, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := startObserverChild(t, f, binary)
	firstOwn := waitChildReady(t, first, f.cfg, baseline)
	if firstOwn.Link == 0 || firstOwn.Link == f.cfg.CiliumLinkID {
		t.Fatal("child failed to create separate observer link")
	}
	killAndReapObserver(t, first)
	requireExactChain(t, f.cfg, baseline)
	// Link remains usable and is owned by the parent fixture, not the child.
	foreign, err := f.policy.Info()
	if err != nil {
		t.Fatal(err)
	}
	if uint32(foreign.ID) != f.cfg.CiliumLinkID {
		t.Fatal("parent-owned link changed")
	}
	second := startObserverChild(t, f, binary)
	_ = waitChildReady(t, second, f.cfg, baseline)
	killAndReapObserver(t, second)
	requireExactChain(t, f.cfg, baseline)
}

func TestPrivilegedConcurrentSampleClose(t *testing.T) {
	elf := requirePrivileged(t)
	f := newFixture(t)
	_, baseline, err := query(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(f.cfg, elf)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	raceStart := make(chan struct{})
	closeStarted := make(chan struct{})
	errs := make(chan error, 16)
	var workers, staged sync.WaitGroup
	var successes atomic.Uint64
	staged.Add(8)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := o.Sample(); err != nil {
				errs <- fmt.Errorf("initial worker sample failed: %w", err)
				staged.Done()
				return
			}
			successes.Add(1)
			staged.Done()
			<-raceStart
			for range 50 {
				_, err := o.Sample()
				if err != nil {
					select {
					case <-closeStarted:
						if err.Error() != "observer is closed" {
							errs <- err
						}
					default:
						errs <- fmt.Errorf("sample failed before close: %w", err)
					}
					return
				}
				successes.Add(1)
			}
		}()
	}
	staged.Wait()
	// Stage actual Close calls behind the same barrier as second-phase Samples.
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-raceStart
			if err := o.Close(); err != nil {
				errs <- err
			}
		}()
	}
	close(closeStarted)
	close(raceStart)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if successes.Load() < 8 {
		t.Errorf("not all workers executed actual pre-close Samples: %d", successes.Load())
	}
	if _, err := o.Sample(); err == nil {
		t.Fatal("closed observer accepted Sample")
	}
	requireExactChain(t, f.cfg, baseline)
}

// requestReplacementVeth uses the exact public rtnetlink message helpers from
// pinned netlink. LinkAdd(LinkAttrs.Index) can request the HOST index, but Veth
// has no PeerIndex field. A peer ifinfomsg Index is necessary to deliberately
// reuse BOTH indices; silently accepting an auto-assigned peer weakens the test.
func requestReplacementVeth(old Config, peerName string, peerMAC net.HardwareAddr) error {
	mac, err := net.ParseMAC(old.MAC)
	if err != nil {
		return err
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(old.IfIndex)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(old.IfName)))
	req.AddData(nl.NewRtAttr(unix.IFLA_ADDRESS, mac))
	info := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	info.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("veth"))
	data := info.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	peer := data.AddRtAttr(nl.VETH_INFO_PEER, nil)
	peerMsg := nl.NewIfInfomsgChild(peer, unix.AF_UNSPEC)
	peerMsg.Index = int32(old.PeerIfIndex)
	peer.AddRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(peerName))
	peer.AddRtAttr(unix.IFLA_ADDRESS, peerMAC)
	req.AddData(info)
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func TestPrivilegedIfindexMACReuseRejectsOldAnchor(t *testing.T) {
	elf := requirePrivileged(t)
	f := newFixture(t)
	original, err := Open(f.cfg, elf)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	old := f.cfg
	peerName := f.peer.Attrs().Name
	peerMAC := append(net.HardwareAddr(nil), f.peer.Attrs().HardwareAddr...)
	if err := netlink.LinkDel(f.dev); err != nil {
		t.Fatal(err)
	}
	if err := requestReplacementVeth(old, peerName, peerMAC); err != nil {
		t.Fatalf("kernel must create actual requested host+peer index reuse; no skip/weak fallback: %v", err)
	}
	dev, err := netlink.LinkByName(old.IfName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dev) })
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Attrs().Index != old.IfIndex || dev.Attrs().HardwareAddr.String() != old.MAC ||
		dev.Attrs().ParentIndex != old.PeerIfIndex || peer.Attrs().Index != old.PeerIfIndex {
		t.Fatalf("fixture did not recreate same scalar incarnation: host=%+v peer=%+v", dev.Attrs(), peer.Attrs())
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}
	// Reuse the exact old program ID too. The distinguishing authority must be
	// the kernel link incarnation, not an unrelated program/name/MAC change.
	at, err := old.attachType()
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := link.AttachTCX(link.TCXOptions{Interface: old.IfIndex, Program: f.prog,
		Attach: at, Anchor: link.Tail()})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	ri, err := replacement.Info()
	if err != nil {
		t.Fatal(err)
	}
	if uint32(ri.ID) == old.CiliumLinkID {
		t.Fatal("old retained fixture FD must prevent old link ID reuse")
	}
	_, replacementBaseline, err := query(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Sample(); err == nil {
		t.Fatal("old live observer accepted replacement interface")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	requireExactChain(t, old, replacementBaseline)
	if stale, err := Open(old, elf); err == nil {
		_ = stale.Close()
		t.Fatal("old config accepted same ifindex/MAC/name/peer/program replacement")
	}
	requireExactChain(t, old, replacementBaseline)
	fresh := old
	fresh.PodUID = "fixture-replacement-explicit-requalification"
	fresh.CiliumLinkID = uint32(ri.ID)
	approved, err := Open(fresh, elf)
	if err != nil {
		t.Fatalf("explicit new anchor should qualify: %v", err)
	}
	if err := approved.Close(); err != nil {
		t.Fatal(err)
	}
	requireExactChain(t, fresh, replacementBaseline)
}

func directionalFixture(t *testing.T, direction string) fixture {
	t.Helper()
	f := newFixture(t)
	if direction == "ingress" {
		return f
	}
	if direction != "egress" {
		t.Fatal("unsupported direction")
	}
	if err := f.policy.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cil_fixture_eg", Type: ebpf.SchedCLS,
		AttachType: ebpf.AttachTCXEgress, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	policy, err := link.AttachTCX(link.TCXOptions{Interface: f.cfg.IfIndex, Program: p,
		Attach: ebpf.AttachTCXEgress, Anchor: link.Tail()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = policy.Close() })
	info, err := policy.Info()
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Direction = "egress"
	f.cfg.CiliumLinkID = uint32(info.ID)
	f.cfg.CiliumProgramID = uint32(info.Program)
	f.policy = policy
	f.prog = p
	return f
}

func TestPrivilegedIngressEgressActualPacketCounters(t *testing.T) {
	elf := requirePrivileged(t)
	for _, direction := range []string{"ingress", "egress"} {
		t.Run(direction, func(t *testing.T) {
			f := directionalFixture(t, direction)
			_, baseline, err := query(f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			o, err := Open(f.cfg, elf)
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			before, err := o.Sample()
			if err != nil {
				t.Fatal(err)
			}
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
			const sent = 50
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
					t.Fatalf("%s actual packet counters insufficient: before=%+v after=%+v", direction, before, after)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			requireExactChain(t, f.cfg, baseline)
		})
	}
}
