# CMTC opt-in TCX observer proposal

Status: proposal only. No repository changes, build, kernel attach or cluster mutation performed by this agent. The primary must review, compile and execute every acceptance test below. This is an observation increment, never an mTLS/enforcement or Protected increment.

## Actual source and lab context

- CMTC `/Users/olasumbo/gitRepos/clustermest-trust-controller`, module `github.com/ephico2real2/clustermesh-trust-controller`, Go 1.26.0; existing `cmd/cmtc/main.go` creates controller-runtime controller/inventory modes. `config/default/workloads.yaml` deliberately keeps `cmtc-node-agent` nonroot and unprivileged. Preserve it.
- Cilium `/private/tmp/cilium-ztunnel-authorization-runtime`, HEAD `a23b8479cae4052eff591484e58e3d9b7adc44f8`, dirty `pkg/ztunnel/membership/state.go` and `state_test.go` as observed during proposal. This branch's actual `pkg/datapath/loader/tcx.go:59` calls `link.AttachTCX(TCXOptions{..., Anchor: link.Tail()})` and pins Cilium's links. Never update, unpin or replace them.
- Cilium vendor contains `github.com/cilium/ebpf v0.22.0` (requires Go >=1.25), `github.com/vishvananda/netlink v1.3.2-0.20261015184244-3fdd74264153`, `github.com/vishvananda/netns v0.0.5` and x/sys. Pin first two dependencies in CMTC; x/sys already required v0.40.0. Source interfaces: `vendor/github.com/cilium/ebpf/link/tcx.go`, `anchor.go`, `query.go`, `link.go`, `link_other.go`; netlink `handle_linux.go`, `filter_linux.go`, `link.go`.
- Parent reports owned labs `cmtc-a` / `cmtc-b`, Linux ARM64 Colima kernel 6.8.0-117, veth plus Cilium tail-anchored TCX. Independently verify the exact node selected. Never substitute another lab/provider.
- Tokensave on CMTC served main because current feat/end-to-end-enforcement branch untracked. Cilium external checkout is uninitialized. Used read-only current source fallback, not stale graph bodies.

## Scope and placement

First increment: a separate `cmd/cmtc-bpf-observer` binary and separately applied privileged DaemonSet. Operator grants no enforcement semantics. Attach only a manually audited host-side veth belonging to an explicitly owned disposable Pod, with configured immutable cluster/node/Pod UID/netns/interface expectation. Do not use a Pod informer to imply first-packet capture. No production attachment discovery, default-interface attach, netns switching, netkit, legacy TC fallback, interface changes, TC qdisc changes, redirect, DENY, packet payload capture, packet marking, TLS parsing, policy decisions or automatic reattachment.

Cilium may return terminal TCX_PASS/DROP/REDIRECT. An observer after Cilium's tail can see zero traffic. Put our observer immediately BEFORE the expected first Cilium link, returning TCX_NEXT unconditionally. Preserve the order, link IDs and program IDs of every pre-existing link, including the Cilium tail anchor. Metric means **packets entering the selected TCX hook before Cilium verdict**, not requests/connections/denials/TLS handshakes.

Ifindex, MAC, name and netns inode checks alone do not eliminate reuse races. Require the exact expected Cilium TCX link ID, open it and retain its FD, verify its program ID/name, require it is first in the queried chain, and attach using `link.BeforeLink(heldLink)` plus query revision. A device replaced during the check cannot contain this same held kernel link. The kernel must reject attachment if the anchor is absent from the target hook. Never silently retry by name or new ifindex. Strict post-attach query must contain exactly own observer then untouched baseline chain. A concurrent Cilium regeneration is a stop-and-requalify event, not a reason to mutate its link or re-enroll automatically.

No pins: maps/programs/link live only through our process FDs; close own link before collection. Each configured interface direction gets a separate private collection/map. On crash/kernel FD release, only our observer detaches; Cilium remains. This deliberately lacks durable enforcement and must not serve as a future DENY design shortcut. Future enforcement requires CNI admission/kernel hold and durable Required state before Pod release, attested workload/cluster binding, authorization freshness and restart/recovery barriers.

## Proposed source: `internal/datapath/bpf/observer.c`

This tiny ABI declaration uses only the stable first field of __sk_buff and BTF-style map declaration; no CO-RE, helper wrapper library, generated vmlinux.h or CGO. clang emits BPF ELF; Go embeds or loads the built ELF, never invokes a compiler at runtime.

```c
// SPDX-License-Identifier: Apache-2.0
// Observe only. Return TCX_NEXT for every packet and every error.
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct __sk_buff { __u32 len; };
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define TCX_NEXT (-1)
struct counters { __u64 packets; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} observed SEC(".maps");
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
SEC("tcx/ingress")
int cmtc_observe(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct counters *c = bpf_map_lookup_elem(&observed, &key);
    if (c) {
        // Atomic protects same-CPU reentrancy too; no packet data is modified.
        __sync_fetch_and_add(&c->packets, 1);
        __sync_fetch_and_add(&c->bytes, skb->len);
    }
    return TCX_NEXT;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";
```

Build with `clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/observer.c -o internal/datapath/observer_bpfel.o` inside Podman Linux ARM64 builder. `tcx/ingress` provides the loader hint; explicitly set `ProgramSpec.AttachType` according to chosen direction before load so one program body supports either hook.

## Proposed source: `internal/datapath/observer_linux.go`

Complete minimal loader implementation below. It intentionally has no Kubernetes client and no auto-discovery. Config is frozen at process startup. Collection ELF bytes should be embedded by the binary (`//go:embed observer_bpfel.o`) after the deterministic BPF compilation step; the argument exists to make tests inject a fixture. No generated object is checked into a Go-only build accidentally; build Make target generates it first.

```go
//go:build linux

package datapath

import (
    "bytes"
    "errors"
    "fmt"
    "os"
    "reflect"
    "strings"
    "sync"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/vishvananda/netlink"
    "golang.org/x/sys/unix"
)

type Config struct {
    Cluster string `json:"cluster"`
    Node string `json:"node"`
    PodUID string `json:"podUID"`
    NetNSInode uint64 `json:"netNSInode"`
    IfIndex int `json:"ifIndex"`
    IfName string `json:"ifName"`
    MAC string `json:"mac"`
    PeerIfIndex int `json:"peerIfIndex"`
    Direction string `json:"direction"`
    CiliumLinkID uint32 `json:"ciliumLinkID"`
    CiliumProgramID uint32 `json:"ciliumProgramID"`
}

type Count struct { Packets uint64; Bytes uint64 }
type attachment struct { Program uint32; Link uint32 }

type Observer struct {
    mu sync.Mutex
    cfg Config
    ns *os.File
    nl *netlink.Handle
    anchor link.Link
    owned link.Link
    coll *ebpf.Collection
    counters *ebpf.Map
    expected []attachment
    cpus int
    closed bool
}

func (c Config) attachType() (ebpf.AttachType, error) {
    switch c.Direction {
    case "ingress": return ebpf.AttachTCXIngress, nil
    case "egress": return ebpf.AttachTCXEgress, nil
    default: return 0, errors.New("direction must be ingress or egress")
    }
}

func (c Config) Validate() error {
    if c.Cluster == "" || c.Node == "" || c.PodUID == "" ||
        c.NetNSInode == 0 || c.IfIndex <= 0 || c.IfName == "" ||
        c.MAC == "" || c.PeerIfIndex <= 0 || c.CiliumLinkID == 0 ||
        c.CiliumProgramID == 0 {
        return errors.New("explicit cluster/node/Pod UID and full interface/anchor incarnation required")
    }
    _, err := c.attachType()
    return err
}

func inode(f *os.File) (uint64, error) {
    var st unix.Stat_t
    if err := unix.Fstat(int(f.Fd()), &st); err != nil { return 0, err }
    return st.Ino, nil
}

// Verify current thread namespace, not process leader's namespace. This binary
// must never call setns; hostNetwork selects the host namespace at exec time.
func (o *Observer) checkNamespace() error {
    f, err := os.Open("/proc/thread-self/ns/net")
    if err != nil { return err }
    defer f.Close()
    got, err := inode(f)
    if err != nil { return err }
    if got != o.cfg.NetNSInode { return fmt.Errorf("network namespace mismatch: got %d", got) }
    held, err := inode(o.ns)
    if err != nil { return err }
    if held != got { return errors.New("held namespace changed") }
    return nil
}

func (o *Observer) checkDevice() error {
    if err := o.checkNamespace(); err != nil { return err }
    dev, err := o.nl.LinkByIndex(o.cfg.IfIndex)
    if err != nil { return err }
    a := dev.Attrs()
    if dev.Type() != "veth" { return fmt.Errorf("only explicit host veth supported, got %s", dev.Type()) }
    if a.Name != o.cfg.IfName || a.HardwareAddr.String() != o.cfg.MAC ||
        a.ParentIndex != o.cfg.PeerIfIndex {
        return errors.New("interface incarnation attributes changed")
    }
    // No legacy fallback, and do not mix with legacy filters in either direction.
    for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
        fs, err := o.nl.FilterList(dev, parent)
        if err != nil { return fmt.Errorf("legacy TC inspection: %w", err) }
        if len(fs) != 0 { return errors.New("legacy TC filters present; refusing observer") }
    }
    return nil
}

func query(c Config) (*link.QueryResult, []attachment, error) {
    at, err := c.attachType()
    if err != nil { return nil, nil, err }
    q, err := link.QueryPrograms(link.QueryOptions{Target:c.IfIndex, Attach:at})
    if err != nil { return nil, nil, fmt.Errorf("TCX required, no fallback: %w", err) }
    if q.Revision == 0 { return nil, nil, errors.New("TCX revision/link identity unavailable") }
    ids := make([]attachment, 0, len(q.Programs))
    for _, p := range q.Programs {
        id, ok := p.LinkID()
        if !ok { return nil, nil, errors.New("TCX attachment lacks kernel link identity") }
        ids = append(ids, attachment{uint32(p.ID), uint32(id)})
    }
    return q, ids, nil
}

func Open(c Config, elf []byte) (_ *Observer, retErr error) {
    if err := c.Validate(); err != nil { return nil, err }
    o := &Observer{cfg:c}
    defer func() { if retErr != nil { _ = o.Close() } }()
    var err error
    o.ns, err = os.Open("/proc/thread-self/ns/net")
    if err != nil { return nil, err }
    if err := o.checkNamespace(); err != nil { return nil, err }
    o.nl, err = netlink.NewHandle(unix.NETLINK_ROUTE)
    if err != nil { return nil, err }
    if err := o.checkDevice(); err != nil { return nil, err }
    // Opening the exact old link prevents its numeric ID being reused. Never
    // discover a replacement anchor if this one becomes defunct.
    o.anchor, err = link.NewFromID(link.ID(c.CiliumLinkID))
    if err != nil { return nil, err }
    ai, err := o.anchor.Info()
    if err != nil { return nil, err }
    at, _ := c.attachType()
    ti := ai.TCX()
    if ti == nil || ti.Ifindex != uint32(c.IfIndex) || uint32(ti.AttachType) != uint32(at) ||
        uint32(ai.Program) != c.CiliumProgramID {
        return nil, errors.New("configured Cilium anchor does not match device/direction/program")
    }
    ap, err := ebpf.NewProgramFromID(ai.Program)
    if err != nil { return nil, err }
    pi, infoErr := ap.Info()
    _ = ap.Close()
    if infoErr != nil { return nil, infoErr }
    if !strings.HasPrefix(pi.Name, "cil_") {
        return nil, errors.New("anchor is not a Cilium program")
    }
    // Program name is an ownership sanity check, NOT cryptographic proof.
    // Admission/config is restricted to audited owned disposable Pods.
    q, before, err := query(c)
    if err != nil { return nil, err }
    if len(before) == 0 || before[0] != (attachment{c.CiliumProgramID,c.CiliumLinkID}) {
        return nil, errors.New("configured Cilium link must be first in baseline TCX chain")
    }
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
    if err != nil { return nil, err }
    ps := spec.Programs["cmtc_observe"]
    if ps == nil { return nil, errors.New("observer program missing from ELF") }
    ps.AttachType = at
    o.coll, err = ebpf.NewCollection(spec)
    if err != nil { return nil, fmt.Errorf("load observer: %w", err) }
    o.counters = o.coll.Maps["observed"]
    if o.counters == nil { return nil, errors.New("observer counter map missing") }
    prog := o.coll.Programs["cmtc_observe"]
    o.owned, err = link.AttachTCX(link.TCXOptions{
        Interface:c.IfIndex, Program:prog, Attach:at,
        Anchor:link.BeforeLink(o.anchor), ExpectedRevision:q.Revision,
    })
    if err != nil { return nil, fmt.Errorf("attach against exact baseline: %w", err) }
    oi, err := o.owned.Info()
    if err != nil { return nil, err }
    o.expected = append([]attachment{{uint32(oi.Program),uint32(oi.ID)}}, before...)
    o.cpus, err = ebpf.PossibleCPU()
    if err != nil { return nil, err }
    if err := o.verify(); err != nil { return nil, err }
    return o, nil
}

func (o *Observer) verify() error {
    if o.closed { return errors.New("observer is closed") }
    if err := o.checkDevice(); err != nil { return err }
    _, now, err := query(o.cfg)
    if err != nil { return err }
    if !reflect.DeepEqual(o.expected, now) {
        return errors.New("TCX chain changed; stop and explicitly requalify")
    }
    return nil
}

// Sample returns only kernel packet/byte counts. It is never a policy or
// workload security assertion. On error caller must clear readiness and Close.
func (o *Observer) Sample() (Count, error) {
    o.mu.Lock()
    defer o.mu.Unlock()
    if err := o.verify(); err != nil { return Count{}, err }
    values := make([]Count, o.cpus)
    if err := o.counters.Lookup(uint32(0), &values); err != nil { return Count{}, err }
    var total Count
    for _, c := range values { total.Packets += c.Packets; total.Bytes += c.Bytes }
    return total, nil
}

func (o *Observer) Close() error {
    o.mu.Lock()
    defer o.mu.Unlock()
    if o.closed { return nil }
    o.closed = true
    var errs []error
    if o.owned != nil { errs = append(errs, o.owned.Close()) }
    // Never Unpin, update or close-through another owner's path.
    if o.coll != nil { o.coll.Close() }
    if o.anchor != nil { errs = append(errs, o.anchor.Close()) }
    if o.nl != nil { errs = append(errs, o.nl.Close()) }
    if o.ns != nil { errs = append(errs, o.ns.Close()) }
    return errors.Join(errs...)
}
```

Implementation notes to review before acceptance:
- Current netlink veth LinkAttrs.ParentIndex is obtained through IFLA_LINK. Verify it is populated for the host veth in this lab before setting `peerIfIndex`; if not, explicitly add rtnetlink peer-index decoding, do not treat zero as a wildcard.
- Every `o.anchor.Close()` closes only our duplicate FD. Cilium's pinned link remains alive. Never call anchor.Unpin or anchor.Update.
- `Sample` takes the observer mutex. `Open` only calls the private verify method to avoid lock recursion. Named return error makes cleanup fire on every failure.
- QueryPrograms can fail under a concurrent chain resize; treat any such error as unavailable and detach own observer. No unsafe retries.
- The checkDevice->attach race is fenced by the held-link relative anchor plus ExpectedRevision. A chain mutation immediately after verify can still happen; periodic checks expose that uncertainty. This is acceptable only for an observe-only, explicitly scoped experimental collector.

## Proposed binary glue: `cmd/cmtc-bpf-observer/main.go`

Use existing CMTC zap/logr integration, not a second logging framework. Add a bounded Prometheus custom collector using kernel totals and `MustNewConstMetric(... CounterValue ...)`; never call counter.Add(total) on each poll. Suggested bounded series: `cmtc_datapath_observer_packets_total{cluster,node,direction}`, bytes counterpart and `cmtc_datapath_observer_ready{cluster,node,direction}`. One configured interface per node per direction; do not label Pod UID, interface, remote IP or error text. Structured lifecycle logs may include the explicit test Pod UID and config generation.

The minimal lifecycle body below is complete given the small HTTP metric wrapper described next. Prefer implementing HTTP with existing controller-runtime metrics if that keeps the existing logger/registry convention; do NOT turn the current Observe node mode privileged.

```go
//go:build linux
package main

import (
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type observation struct {
    sync.RWMutex
    count datapath.Count
    ready bool
    packets, bytes, available *prometheus.Desc
}
func (s *observation) Describe(ch chan<- *prometheus.Desc) {
    ch<-s.packets; ch<-s.bytes; ch<-s.available
}
func (s *observation) Collect(ch chan<- prometheus.Metric) {
    s.RLock(); defer s.RUnlock()
    r := 0.0
    if s.ready { r=1 }
    ch<-prometheus.MustNewConstMetric(s.available,prometheus.GaugeValue,r)
    // No stale samples are emitted after attachment uncertainty.
    if !s.ready { return }
    ch<-prometheus.MustNewConstMetric(s.packets,prometheus.CounterValue,float64(s.count.Packets))
    ch<-prometheus.MustNewConstMetric(s.bytes,prometheus.CounterValue,float64(s.count.Bytes))
}
func main() {
    if err:=run(); err!=nil { ctrl.Log.Error(err,"observe-only datapath stopped"); os.Exit(1) }
}
func run() error {
    var cfgPath, addr, elfPath, healthCheck string
    flag.StringVar(&cfgPath,"config","","Required immutable node-specific JSON config")
    flag.StringVar(&elfPath,"elf","/usr/share/cmtc/observer_bpfel.o","Immutable packaged BPF ELF")
    flag.StringVar(&addr,"listen","127.0.0.1:18082","Node-local observer metric/health listener")
    flag.StringVar(&healthCheck,"health-check","","Probe only: ready or live")
    opts:=zap.Options{Development:false}; opts.BindFlags(flag.CommandLine); flag.Parse()
    ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
    if healthCheck!="" {
        path:="/readyz"
        if healthCheck=="live" {path="/healthz"} else if healthCheck!="ready" {return errors.New("invalid probe kind")}
        client:=&http.Client{Timeout:2*time.Second}
        resp,err:=client.Get("http://127.0.0.1:18082"+path)
        if err!=nil{return err};defer resp.Body.Close()
        if resp.StatusCode!=http.StatusOK{return fmt.Errorf("probe returned %s",resp.Status)}
        return nil
    }
    f,err:=os.Open(cfgPath); if err!=nil{return err}; defer f.Close()
    dec:=json.NewDecoder(f); dec.DisallowUnknownFields()
    var c datapath.Config
    if err:=dec.Decode(&c);err!=nil{return err}
    if c.Node!=os.Getenv("NODE_NAME") || c.Cluster!=os.Getenv("CLUSTER_NAME") {
        return errors.New("node or cluster differs from explicit deployment ownership")
    }
    if err:=c.Validate();err!=nil{return err}
    elf,err:=os.ReadFile(elfPath);if err!=nil{return err}
    log:=ctrl.Log.WithName("datapath-observer")
    log.Info("starting observe-only datapath","cluster",c.Cluster,"node",c.Node,
        "podUID",c.PodUID,"ifIndex",c.IfIndex,"direction",c.Direction,"enforcementAvailable",false)
    started:=time.Now()
    o,err:=datapath.Open(c,elf)
    if err!=nil {log.Error(err,"attachment rejected","stage","attach","attempt",1,"elapsed",time.Since(started));return err}
    defer o.Close()
    labels:=prometheus.Labels{"cluster":c.Cluster,"node":c.Node,"direction":c.Direction}
    state:=&observation{
        packets:prometheus.NewDesc("cmtc_datapath_observer_packets_total","Packets at selected TCX hook before Cilium verdict; not requests or mTLS proof.",nil,labels),
        bytes:prometheus.NewDesc("cmtc_datapath_observer_bytes_total","skb bytes at selected TCX hook before Cilium verdict.",nil,labels),
        available:prometheus.NewDesc("cmtc_datapath_observer_ready","Observed attachment matches frozen test interface and baseline chain.",nil,labels),
    }
    reg:=prometheus.NewRegistry(); if err:=reg.Register(state);err!=nil{return err}
    mux:=http.NewServeMux();mux.Handle("/metrics",promhttp.HandlerFor(reg,promhttp.HandlerOpts{}))
    mux.HandleFunc("/readyz",func(w http.ResponseWriter,r *http.Request){
        state.RLock();ok:=state.ready;state.RUnlock()
        if !ok {http.Error(w,"observer unavailable",http.StatusServiceUnavailable);return};w.WriteHeader(http.StatusOK)
    })
    mux.HandleFunc("/healthz",func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusOK)})
    srv:=&http.Server{Addr:addr,Handler:mux,ReadHeaderTimeout:5*time.Second}
    errs:=make(chan error,1)
    go func(){err:=srv.ListenAndServe();if !errors.Is(err,http.ErrServerClosed){errs<-err}}()
    defer func(){ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel();_ = srv.Shutdown(ctx)}()
    ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM,syscall.SIGINT);defer cancel()
    ticker:=time.NewTicker(time.Second);defer ticker.Stop()
    for {
        count,err:=o.Sample()
        state.Lock();state.ready=err==nil;state.count=count;state.Unlock()
        if err!=nil {return fmt.Errorf("observer lifecycle verification failed: %w",err)}
        select {
        case <-ctx.Done():return nil
        case err:=<-errs:return err
        case <-ticker.C:
        }
    }
}
```

Use image filesystem read-only for ELF; for stronger artifact integrity embed it instead of the configurable ELF path. Do not add retries which rediscover another interface. Report attempt=1 attach rejection, then require explicit operator investigation/new config. An observation-only crash may restart with same config only if the exact original anchor remains; otherwise anchor ID checks reject it.

## Separately opt-in DaemonSet: `config/experimental/datapath-observer.yaml`

Apply only AFTER host-node audit and node-label opt-in, one node initially. The quoted image placeholder must be rendered to the exact locally built digest by the primary; this is not a runnable floating-image example. `CLUSTER_NAME` must be replaced with cmtc-a or cmtc-b and host netns inode/Pod UID/anchor IDs filled in per-node JSON ConfigMap. The ConfigMap must be immutable, unique name per audited run. Do not include it in config/default/kustomization.yaml.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cmtc-bpf-observer
  namespace: cmtc-system
spec:
  selector:
    matchLabels: {app.kubernetes.io/name: cmtc-bpf-observer}
  template:
    metadata:
      labels: {app.kubernetes.io/name: cmtc-bpf-observer}
    spec:
      hostNetwork: true
      automountServiceAccountToken: false
      nodeSelector: {security.cmtc.io/bpf-observer-lab: "true"}
      tolerations: [{operator: Exists}]
      terminationGracePeriodSeconds: 10
      containers:
        - name: observer
          image: IMAGE_WITH_VERIFIED_SHA_DIGEST
          command: [/cmtc-bpf-observer]
          args: ["--config=/config/$(NODE_NAME).json", "--listen=127.0.0.1:18082"]
          env:
            - name: NODE_NAME
              valueFrom: {fieldRef: {fieldPath: spec.nodeName}}
            - {name: CLUSTER_NAME, value: CLUSTER_NAME}
          securityContext:
            privileged: true
            runAsUser: 0
            readOnlyRootFilesystem: true
          resources:
            requests: {cpu: 10m, memory: 32Mi}
            limits: {cpu: 200m, memory: 128Mi}
          readinessProbe: {exec: {command: [/cmtc-bpf-observer, "--health-check=ready"]}}
          livenessProbe: {exec: {command: [/cmtc-bpf-observer, "--health-check=live"]}}
          volumeMounts: [{name: config, mountPath: /config, readOnly: true}]
      volumes:
        - name: config
          configMap: {name: cmtc-bpf-observer-RUN_ID}
```

No hostPID, host root filesystem mount, bpffs mount or service-account token needed; hostNetwork is enough for local route-netlink and TCX attach. Privileged is an explicit lab-only convenience for initial BPF qualification. Before production, eliminate this DS by porting into Cilium Hive endpoint lifecycle and apply least privileges there. HostNetwork bypasses the existing pod NetworkPolicy's normal assumptions, so metrics/health bind to 127.0.0.1:18082 and the packaged binary itself performs exec probes. Use node-local curl/exec/port-forward for evidence; do not expose this on all node interfaces without an explicit tested node-firewall decision. Config validation deliberately precedes attach and receives no Kubernetes RBAC grants.

## Tests required before acceptance

Pure tests must exercise actual production helper interfaces, not copied logic. Factor `query`/device/anchor operations behind a narrow injectable backend if needed; keep returned immutable baseline comparable. Unit tests:
1. Config missing every critical field, unknown direction, zero anchor/program/index/inode rejected.
2. Actual C ELF program-test-run (privileged): packet -> action uint32(0xffffffff), private counters +1, bytes += packet length, packet bytes unchanged. Repeat with no map state available only if injection can remove map safely; never weaken core attach to test it.
3. No Cilium link/incorrect link ID/incorrect program/incorrect device name/MAC/peer inode rejected before AttachTCX; no fallback calls.
4. Legacy filters in either direction, netkit and non-veth rejected. Query unsupported/revision0/missing link IDs rejected.
5. Attach expectedrevision conflict -> close private collection; Cilium IDs and order unchanged. Anchor disappearing -> attach fails, never discover new anchor.
6. Any partial Open error closes all opened private FDs. Close twice safe. Concurrent Sample/Close passes race. Counter sum is per-CPU sum and is not added repeatedly to Prometheus.
7. Query postcondition different from own+baseline -> own link removed, foreign IDs/order intact. Verify failure drops availability and stops emission of cached counts.
8. New process private map starts at0; old unpinned observer disappears on SIGKILL; baseline remains. Restart same anchor allowed, replacement Pod/interface anchor denied until explicit requalification.

Privileged runtime with actual Linux 6.8 and actual owned cmtc-a/b Cilium fork:
- Audit both directions with `bpftool net -j`, `bpftool link show -j`, `tc -j filter show dev <host-veth> ingress/egress`, `ip -d -j link show`. Record namespace inode from node shell, complete source SHA/diff, ELF SHA256, Go binary version, image ID, runtime image ID, Cilium image ID and Pod UID.
- Record baseline Cilium link/program IDs and chain order; configure exact first link.
- Create disposable explicitly named workload pair, pin client/server to different nodes, app TCP 8080 plus31337 and ICMP. Confirm pre-observer reachability. Start observer, send known paced load, require positive counter delta and successful app responses. Do not require exact packet count for HTTP because retransmission, ARP and ACK/GRO/GSO affect packets/bytes; use controlled isolated UDP/ICMP fixture for tighter bounds with explicit offload caveats. TCX count is packet/skb events at this hook.
- Baseline Cilium allow test stays allowed; deliberately denied disposable traffic stays denied. Observer increments for both attempts as located pre-Cilium; do not interpret delta as delivered packets. Verify deny independently using actual Cilium policy verdicts and application failure.
- Stop observer, verify exactly original IDs/order, no extra maps/pins, traffic behavior unchanged. SIGKILL observer and verify same detach semantics. Restart original config and exercise recover; recreate workload/interface, keep old config, require startup rejection and zero attach on replacement interface.
- Cilium restart/load change: observer must detect chain change and exit; re-audit anchor manually. Delayed detection is an observation readiness limitation, never a security hold.
- Test explicit wrong namespace inode and unsupported/noTCX in isolated disposable Podman namespace. For unsupported kernel, mock QueryPrograms error exercises unit negative path but does not count as actual old-kernel qualification. No TC legacy qdisc added to live Cilium endpoint; test legacy filter rejection on isolated privileged veth fixture only.
- Run both clusters, exact ARM64 image transfer via Podman save and existing kind provider, no CI. Capture metric queries, lifecycle logs and screenshot only after real load. Preserve failures.

## Production port seam

After this observation increment works, port hook/counter ownership into enhanced Cilium's native endpoint creation/deletion and loader transaction. Cilium should manage its program sequence itself, not CMTC inserting around its policy indefinitely. A later enforcement program must not be derived by replacing TCX_NEXT with DROP without an admission design; require durable Required state before first schedulable packet, CNI ACK barrier, endpoint incarnation binding, control-plane/platform exceptions, effective policy freshness and active-flow drain/recovery. This prototype establishes custom Go+eBPF build/load/evidence plumbing only.

## Concrete table-driven pure tests: `internal/datapath/observer_linux_test.go`

These are intentionally only configuration tests; do not count them as kernel/attach qualification.

```go
//go:build linux
package datapath

import "testing"

func validConfig() Config {
    return Config{Cluster:"cmtc-a",Node:"cmtc-a-worker",PodUID:"explicit-fixture-uid",
        NetNSInode:4026531992,IfIndex:12,IfName:"lxcfixture",MAC:"02:00:00:00:00:01",
        PeerIfIndex:13,Direction:"ingress",CiliumLinkID:100,CiliumProgramID:200}
}
func TestValidateConfig(t *testing.T) {
    tests:=[]struct{name string;mutate func(*Config)}{
        {"cluster",func(c *Config){c.Cluster=""}},
        {"node",func(c *Config){c.Node=""}},
        {"pod",func(c *Config){c.PodUID=""}},
        {"netns",func(c *Config){c.NetNSInode=0}},
        {"ifindex",func(c *Config){c.IfIndex=0}},
        {"ifname",func(c *Config){c.IfName=""}},
        {"mac",func(c *Config){c.MAC=""}},
        {"peer",func(c *Config){c.PeerIfIndex=0}},
        {"anchor",func(c *Config){c.CiliumLinkID=0}},
        {"program",func(c *Config){c.CiliumProgramID=0}},
        {"direction",func(c *Config){c.Direction="netkit"}},
    }
    for _,tt:=range tests{t.Run(tt.name,func(t *testing.T){
        c:=validConfig();tt.mutate(&c)
        if err:=c.Validate();err==nil{t.Fatal("incomplete config accepted")}
    })}
    for _,direction:=range []string{"ingress","egress"}{
        c:=validConfig();c.Direction=direction
        if err:=c.Validate();err!=nil{t.Fatalf("valid %s config rejected: %v",direction,err)}
    }
}
func TestCloseZeroValue(t *testing.T){
    o:=&Observer{}
    if err:=o.Close();err!=nil{t.Fatal(err)}
    if err:=o.Close();err!=nil{t.Fatal(err)}
    if _,err:=o.Sample();err==nil{t.Fatal("closed observer reported available")}
}
```

Actual privileged tests must call `Open`/`Sample` and kill the real binary, not merely mock successful calls or skip unsupported setup. No test labels or execution results are claimed in this proposal. The primary should record a required privileged test target which fails if the test fixture is unavailable, separately from fast pure tests.
