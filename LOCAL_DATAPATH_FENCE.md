# Local eBPF fence: lab-only deny tool

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](docs/agile/DELIVERY_STATUS.md) and [documentation terms](DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

The eBPF fence is a **lab-only deny tool**. It drops every packet at the TCX hook of one explicitly selected,
disposable workload (`internal/datapath/bpf/fence.c:33` returns `TCX_DROP`). Use it only for deny-path tests.
It is not the production gate and never becomes a dynamic allow controller
([ADR-005](docs/architecture/adr/ADR-005.md), point 7).

**Current state (read 2026-10-25T23:07Z):** the fence is not deployed in `cmtc-a` or `cmtc-b`. The production
workload quarantine gate it prototyped now lives natively in the Cilium fork (`bpf/lib/ztunnel_admission.h`,
`pkg/endpoint/ztunnel_policy*.go`). Cilium owns packet enforcement; ztunnel owns workload TLS and authorization.
The observe-only programs of the CMTC DaemonSet form the separate eBPF measurement plane; read
[the DaemonSet guide](CMTC_DAEMONSET_IMPLEMENTATION.md).

The qualification and trial results below are **historical** (2026-10-24, CMTC source `69b8080a19`). They do not
qualify a newer build.

Cursor Grok 4.7 Extra High delivered the [original full proposal](docs/research/cursor/RESTORE_FENCE_IMPLEMENTATION.md). Independent review and primary qualification produced a smaller implementation: [the C program](internal/datapath/bpf/fence.c), [Go lifecycle](internal/datapath/fence_linux.go), and [node CLI](cmd/cmtc-bpf-fence/main.go). The [review](docs/research/cursor/RESTORE_FENCE_PRIMARY_REVIEW.md) records the unsafe paths rejected from the proposal. The existing [packet observer](LOCAL_DATAPATH_OBSERVER.md) is separate and never drops traffic.

The fence always drops at its explicitly selected workload TCX hook. It has no allow, grant or lease map. It counts packets and skb bytes; those counters are neither HTTP requests nor TLS handshakes. It does not establish workload mTLS, authenticated identity or `Protected` status. It is outside default deployment.

## Persistence and ownership

Only a fully validated, committed pin set establishes persistence across process death. The program, accounting map, frozen identity map, exact TCX link and frozen commit map live in a private bpffs directory. Ordinary files cannot be stored in bpffs: the exclusive lock lives in a separate private ordinary-filesystem directory. The full binding includes cluster/node, Namespace UID, Pod UID, audited network namespace inode, interface/MAC/peer and native Cilium anchor IDs.

Adoption checks the actual program, map and link IDs, compatible ELF/program tag, map associations, frozen metadata and exact native chain. Failure never unpins quarantine. `ReleaseProcess` closes process handles while retaining committed pins. `RetireDefunctFence` refuses a live device: it requires the exact old link to report `Ifindex == 0`, then removes only the validated private pin set. An unknown kernel result cannot authorize cleanup. No API removes live quarantine.

The install-to-pin window is still open: `BPF_LINK_CREATE` and `BPF_OBJ_PIN` are separate syscalls. Killing the installer between them can remove an unpinned link. The CLI retains an uncommitted live FD while possible, reports NotReady and logs the fault; this cannot survive SIGKILL. Partial transactions remain blocked for audited recovery. Defunct retirement is conservative but not crash-resumable after its first unlink. Host reboot persistence of the fence is not tested. First-packet admission, native restore and authenticated release belong to the native Cilium gate, not to this lab tool.

## Local qualification (historical, 2026-10-24)

The complete ARM64 profile passed **40 distinct top-level tests and 96 subtests, zero failures/skips**, with Go race/vet and clang `-O2 -Wall -Werror`. The profile includes all CMTC Go packages plus actual kernel cases; duplicate test executions across profiles are counted once. The packaged ELF/CLI also pass all seven new kernel cases. Actual native-ingress attachment now also passes on disposable clients in both clusters: 84 attempts, 36 baseline/recovery HTTP successes and 48 denials, zero cleanup errors.

Real kernel cases cover both ingress and egress: unchanged packet bytes with unconditional DROP, arbitrary port bytes/non-IP, UDP socket delivery before installation and denial afterward, suppression of the following program, twelve transaction fault boundaries, seven corrupted/reused ownership cases, foreign anchor FD release, actual installer SIGKILL and denial **before adoption**, defunct cleanup, and occupied CLI listener rejection before attachment. A held map FD in the crash test cannot keep a TCX link alive.

Two failed runs are retained: an ordinary test fixture initially lacked explicit 0700 directories; egress raw sends then returned `ENOBUFS` after TCX_DROP. The corrected harness accepts that error only on egress with exact immediate per-frame accounting in the attached fence map, receiving-socket timeout and no follower execution. Baseline sends must succeed. A timeout or socket error alone cannot pass the denial assertion.

Builder configuration: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529` (Go 1.27.3, clang 21.1.8, ARM64), using the existing task-owned rootful Podman service. Tests run in disposable private network/mount namespaces, never kind-node or host networking. The normal build connection remains rootless and unchanged.

```sh
# Export this committed source into a task-owned /private/tmp directory first.
# Use the private rootful test socket described in LOCAL_DATAPATH_OBSERVER.md.
podman --url ssh://olasumbo@127.0.0.1:49691/tmp/cmtc-observer-rootful/podman.sock \
  --identity /Users/olasumbo/.colima/_lima/_config/user run --rm \
  --privileged --platform linux/arm64 --cpus 2 --memory 4g \
  -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 \
  -e GOCACHE=/cache -e GOMODCACHE=/modcache -e CMTC_BPF_TEST_PRIVATE_NETNS=1 \
  -v /private/tmp/cmtc-fence-20261024/source:/workspace \
  -v /private/tmp/cmtc-observer-go-cache:/cache \
  -v /private/tmp/cmtc-observer-mod-cache:/modcache -w /workspace \
  f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  sh scripts/lab/qualify-datapath.sh
```

At this checkpoint CI, branch pushes and registry publishing were deferred, and the Cilium ClusterMesh/ztunnel compatibility guard was closed. (Cilium `37d5fce0f7` later replaced that guard with capability validation.) Source commit: `69b8080a1924f91755863e75536aa49ec6657319`. Local ARM64 image `localhost/cmtc-bpf-fence:deny-69b8080a19`, configuration ID `cff9baf4459bd56551e794738afb5ecc011974e4cbb1c17dd57928423f66757e`, is archive-loaded on all four nodes. Packaged ELF SHA-256 is `4bd46a3699aec7741309feb9bded2fbc4efa3e3e4f46112b437878245dab3634`; packaged CLI SHA-256 is `5c5ce185c9f00fa7d34a0cbd09cf2f6507286283bac8e7bb91ee12da32add408`. The opt-in DaemonSet trial is complete; all task-owned clients/DaemonSets/roots/labels are cleaned and no fence remains attached. [Build commands](docs/evidence/datapath-fence/build-fence.sh), [packaged tests](docs/evidence/datapath-fence/packaged-kernel.log) and [image metadata](docs/evidence/datapath-fence/image.json) record this checkpoint.


## Both-cluster native-ingress trial (historical, 2026-10-24)

[Measured summary](docs/evidence/datapath-fence/summary.json), [full integration ledger](docs/evidence/datapath-fence/integration.json), [HTTP and structured lifecycle logs](docs/evidence/datapath-fence/lab-output/) record the exact image trial. Each cluster tested TCP 80/8080/31337 against both existing local and remote backends, SIGKILL/restart/adoption, daemon absence with persistent denial, same-key bad configuration rejection, original workload deletion, stale original configuration against a new Pod UID, exact defunct retirement and replacement traffic recovery. Actual private kernel counter deltas accompany the denials. The native policy/host link audit passes after final cleanup.

This fixture attaches native workload TCX **ingress only**. The proposed egress trial correctly failed its anchor check because there is no native egress TCX attachment; no dummy anchor was installed. Both hooks pass isolated kernel tests, but the live destination policy-tail-call path remains outside this standalone fence. The native Cilium core must guard that path as well; that native gate now exists in the fork. This fence trial was never complete all-path workload enforcement.

Three diagnostic runs remain: scratch mount targets under /sys failed before program startup; bpftool returned 255 while printing a valid exact detached-link record; the egress anchor was absent. The corrected container mounts retain private host bpffs at /cmtc-pins and ordinary locks at /cmtc-locks. Detached inspection checks the exact link/program/type/hook data and the Go retirement command independently confirms kernel Ifindex 0. [Exact dead-fence recovery](docs/evidence/datapath-fence/exact-defunct-recovery.json) retired the second run's retained pins with zero cleanup errors; unknown/incomplete records are never raw-unlinked.

```sh
venv/bin/python scripts/lab/test-fence.py --directions ingress \
  --image localhost/cmtc-bpf-fence:deny-69b8080a19 \
  --image-id sha256:cff9baf4459bd56551e794738afb5ecc011974e4cbb1c17dd57928423f66757e \
  --expected-revision 69b8080a1924f91755863e75536aa49ec6657319 \
  --out /private/tmp/UNIQUE_FENCE_TRIAL_DIRECTORY
```

The image must already be archive-loaded into the two owned labs. The harness creates fresh run-owned workload namespaces and refuses existing opt-in DaemonSets/labels. The original Observe DaemonSet remains unprivileged and unchanged. No registry/CI action is performed.
