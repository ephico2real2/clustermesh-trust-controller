# Local persistent deny-fence experiment

Cursor Grok 4.7 Extra High delivered the [original full proposal](docs/research/cursor/RESTORE_FENCE_IMPLEMENTATION.md). Independent review and primary qualification produced a smaller implementation: [the C program](internal/datapath/bpf/fence.c), [Go lifecycle](internal/datapath/fence_linux.go), and [node CLI](cmd/cmtc-bpf-fence/main.go). The [review](docs/research/cursor/RESTORE_FENCE_PRIMARY_REVIEW.md) records the unsafe paths rejected from the proposal. The existing [packet observer](LOCAL_DATAPATH_OBSERVER.md) is separate and never drops traffic.

This experiment always drops at its explicitly selected workload TCX hook. It has no allow, grant or lease map. It counts packets and skb bytes; those counters are neither HTTP requests nor TLS handshakes. It does not establish workload mTLS, authenticated identity or `Protected` status. It is outside default deployment.

## Persistence and ownership

Only a fully validated, committed pin set establishes persistence across process death. The program, accounting map, frozen identity map, exact TCX link and frozen commit map live in a private bpffs directory. Ordinary files cannot be stored in bpffs: the exclusive lock lives in a separate private ordinary-filesystem directory. The full binding includes cluster/node, Namespace UID, Pod UID, audited network namespace inode, interface/MAC/peer and native Cilium anchor IDs.

Adoption checks the actual program, map and link IDs, compatible ELF/program tag, map associations, frozen metadata and exact native chain. Failure never unpins quarantine. `ReleaseProcess` closes process handles while retaining committed pins. `RetireDefunctFence` refuses a live device: it requires the exact old link to report `Ifindex == 0`, then removes only the validated private pin set. An unknown kernel result cannot authorize cleanup. No API removes live quarantine.

The install-to-pin window is still open: `BPF_LINK_CREATE` and `BPF_OBJ_PIN` are separate syscalls. Killing the installer between them can remove an unpinned link. The CLI retains an uncommitted live FD while possible, reports NotReady and logs the fault; this cannot survive SIGKILL. Partial transactions remain blocked for audited recovery. Defunct retirement is conservative but not crash-resumable after its first unlink. Host reboot persistence, first-packet admission, native Cilium restore, migration of old forwarding programs and authenticated release remain required work.

## Actual local qualification

The complete ARM64 profile passed **40 distinct top-level tests and 96 subtests, zero failures/skips**, with Go race/vet and clang `-O2 -Wall -Werror`. The profile includes all CMTC Go packages plus actual kernel cases; duplicate test executions across profiles are counted once. The image/deployment acceptance gate remains pending until recorded below.

Real kernel cases cover both ingress and egress: unchanged packet bytes with unconditional DROP, arbitrary port bytes/non-IP, UDP socket delivery before installation and denial afterward, suppression of the following program, twelve transaction fault boundaries, seven corrupted/reused ownership cases, foreign anchor FD release, actual installer SIGKILL and denial **before adoption**, defunct cleanup, and occupied CLI listener rejection before attachment. A held map FD in the crash test cannot keep a TCX link alive.

Two failed runs are retained: an ordinary test fixture initially lacked explicit0700 directories; egress raw sends then returned `ENOBUFS` after TCX_DROP. The corrected harness accepts that error only on egress with exact immediate per-frame accounting in the attached fence map, receiving-socket timeout and no follower execution. Baseline sends must succeed. A timeout or socket error alone cannot pass the denial assertion.

Builder configuration: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529` (Go1.27.3, clang21.1.8, ARM64), using the existing task-owned rootful Podman service. Tests run in disposable private network/mount namespaces, never kind-node or host networking. The normal build connection remains rootless and unchanged.

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

The endpoint/identity handoff remains in [DELIVERY_STATUS.md](docs/agile/DELIVERY_STATUS.md). CI, branch pushes and registry publishing remain deferred. The ClusterMesh/ztunnel compatibility guard stays closed. No live workload fence image has been deployed at this checkpoint.
