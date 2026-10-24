# Persistent deny fence: primary review

Cursor Grok 4.7 Extra High supplied the [complete proposal](RESTORE_FENCE_IMPLEMENTATION.md). The primary did not accept it wholesale. The reviewed implementation is a smaller deny-only experiment: `internal/datapath/bpf/fence.c`, `internal/datapath/fence_linux.go` and `cmd/cmtc-bpf-fence`. It contains no grant, lease or allow interface.

This document records review, not completed deployment. The current evidence and exact image state belong in [DELIVERY_STATUS.md](../../agile/DELIVERY_STATUS.md). CI and publication remain deferred.

The primary replaced the custom byte reader with `bytes.NewReader`, checks the exact pin set on each sample, explicitly creates private test roots, and is qualifying actual egress-drop send semantics. A successful zero-selected compile check was only a compilation preflight, never kernel evidence. The original kernel failure logs are retained locally.

The guarantee begins after a complete pin transaction is validated. Attaching a link and pinning it are separate syscalls: the intervening crash window remains open. Host reboot, first-packet/CNI admission, native restore, authenticated allow, remote workload identity, policy and workload mTLS remain separate required gates. No `Protected` condition follows from this experiment.

## Go lifecycle review (proposal author)

# Grok restore-fence proposal — Go lifecycle correction

Status: proposal only. No source/runtime changes by this reviewer. Files are gofmt-parsed; they have NOT passed compilation, unit execution, privileged kernel tests, exact-image deployment, or packet qualification. A host Linux cross-compile attempt stopped before compilation because the sandbox could not write the host dependency/build cache. The primary owns qualification using the existing Podman toolchain.

## Copy-ready files

- `internal/datapath/fence_linux.go`: deny-only loader/adoption/defunct-retirement API.
- `internal/datapath/fence_linux_test.go`: Linux ordinary filesystem/config tests (6 top-level tests).
- `internal/datapath/fence_failure_privileged_test.go`: real-kernel transaction boundary, corruption/reuse, and foreign-FD lifetime tests (3 top-level tests, 12 boundary subcases, 7 corruption/reuse subcases).
- `cmd/cmtc-bpf-fence/main.go`: loopback metrics/health, explicit node/cluster binding, strict bounded JSON, adopt-before-install, defunct-only maintenance command. Primary plans to replace its private byteReader with standard bytes.NewReader; this is recommended.
- `cmd/cmtc-bpf-fence/main_test.go`: strict config and fresh quarantine readiness (2 top-level tests).

Combine with C-agent `/private/tmp/cmtc-fence-kernel-review/fence.c` and `fence_kernel_privileged_test.go`. That test file owns the package's only TestMain and actual SIGKILL child. Our privileged tests reuse its actual UDP/follower/private-bpffs helpers and the existing observer fixture helpers; copy all together. They must run inside an owned disposable private network namespace, root, CMTC_BPF_TEST_PRIVATE_NETNS=1, with CMTC_FENCE_ELF naming the freshly built deny-only ELF. Do not skip kernel prerequisites or infer a pass from zero selected cases.

## Why the original design cannot be accepted unchanged

1. An ordinary fsynced identity.json file cannot be created in bpffs. The replacement stores frozen identity and commit BPF Array maps. Only the external lock belongs on an ordinary filesystem.
2. Adoption errors must never call retirement or unpin any object. The replacement closes only independently opened process FDs on failure; pins and live deny remain untouched.
3. A caller must not remove a live required fence by supplying an allow/lease or --retire flag. There is no grant map or writer in the deny-only ELF/loader. The only retirement API requires the exact old held kernel TCX link positively reports Ifindex==0. Unknown errors, missing pins, changed metadata and a new device at an old numeric index never authorize unpinning.
4. A mutable binding map plus a mutable decision map cannot provide one coherent authorization generation. The first slice removes both; it always drops. A future production permit protocol needs independently reviewed freshness, identity, atomicity, epoch and kernel enforcement.
5. Kernel program tags changed with Linux6.18. Use ebpf v0.22 ProgramSpec.Compatible, validate actual program/map/link IDs, frozen metadata, ELF/config digests, epoch, attach hook, exact baseline order, and actual map associations.
6. Do not retain the foreign Cilium link FD for the process lifetime. Open it only through AttachTCX and close on every success/error path. The independent test closes the original unpinned fixture anchor and verifies it disappears, leaving our deny present but NotReady.

## Ownership and pin transaction

The caller explicitly provisions an existing private0700 bpffs PinRoot and private0700 ordinary LockRoot. This loader does not mount filesystems, make privileged global directories, change native policy, or touch Cilium's pin tree. The full SHA256 directory key binds cluster/node/namespaceUID/PodUID/direction. The full config digest additionally binds netns inode, interface/index/MAC/peer, exact Cilium anchor IDs and pin/lock paths. Reusing a Pod name is irrelevant; replacing the namespace UID or Pod UID cannot adopt the old fence. A restarted sandbox for the same Pod UID addresses the same ownership record and fails full incarnation validation until the exact old defunct record is separately retired.

All absolute parent components are opened using O_NOFOLLOW directory traversal; roots/child/lock use held FDs with inode/mode/euid revalidation. The external flock is exclusive and nonblocking. Its file is0600, regular, zero length, owned by current euid and single-link. Lock files are deliberately not unlinked: unlinking a flock file can let another owner acquire an independent replacement inode. Namespace/runtime provisioning must not delete the LockRoot until all owners exit. Root/mount privileges can defeat any userspace path model; this prototype does not claim to resist a hostile same-root actor.

Pin order: accounted → program → frozen identity → TCX attach → link pin → frozen commit map pin. Commit includes the exact link ID, identity map ID and random install epoch. Identity binds config/ELF/baseline hashes, program/map IDs and actual kernel tag. User telemetry updates are frozen; the BPF program can still count. All named pin files are private0600. A committed adoption requires exactly the five known entries. Periodic Account reopens and verifies their kernel IDs so keeping an old FD cannot hide a pin replacement.

Failure before attach leaves a forensic partial directory, closes process FDs, and never overwrites/removes the record. Failure after attach returns the live partial handle. A pinned partial can release process FDs without detaching, while a live unpinned partial refuses ReleaseProcess. The CLI holds that FD NotReady and logs stage/attempt/elapsed/backoff/error until the owned fixture is removed. This is deliberately conservative; incomplete partial transactions require manual audited fixture recovery, not automatic adoption/cleanup.

## Hard security boundaries still OPEN

- BPF_LINK_CREATE → BPF_OBJ_PIN is not atomic. SIGKILL between them detaches the unpinned link when its last process FD closes. The guarantee begins only after the commit pin exists and full validation succeeds. Neither this helper nor its tests prove first-packet protection.
- Native Cilium endpoint/CNI admission, pre-restore deny before reactivation, replacement transition and durable Required intent handoff are not integrated. This prototype is only for audited disposable veths. No CMTC Protected/Fenced condition may be derived from it.
- Committed pinned deny survives controller process death, not a host reboot. Host reboot recovery requires native pre-restore enforcement.
- Deny-only quarantine supplies no authenticated workload traffic, remote discovery, SPIFFE verification, mTLS, authorization grants, HBONE or node encryption. All those delivery gates remain open.
- Config strings are explicit trusted lab ownership claims, not cryptographic proof of Kubernetes objects. This loader does not query Kubernetes or inspect a pod's sandbox FD.
- Exact chain preservation rejects legitimate native Cilium workload program updates too. Pins remain drop; readiness becomes false. A production loader transition protocol must explicitly handle native updates; do not weaken equality to mask drift.
- A defunct retirement that fails after its first unlink may leave a partial dead record. It cannot safely re-adopt as committed. No live attachment is removed, but crash-resumable retirement journaling is future work.
- install/adopt/retire are serialized only for trusted peers using the exact same LockRoot. The immutable config digest and revalidation reject accidental path changes; they do not constrain an independent privileged BPF writer.

## Test assertions

Ordinary tests reject missing namespace/Pod ownership, invalid paths, native pin roots, reserved platform devices, malformed MAC/direction, symlink parents, group-readable roots, changed root inode, hardlinked/nonempty/public lock, concurrent flock and replaced lock inode. Closed handles cannot become ready and ReleaseProcess is idempotent.

The kernel transaction tests inject errors after each of six real boundaries for ingress and egress. They require baseline UDP success, unchanged native chain before attachment, actual UDP loss after attachment, retained pins, exclusive ownership, refusal to close an unpinned live attachment, and successful recovery only at the fully committed final boundary. Adoption tests replace frozen metadata using internally consistent new map IDs but corrupted binding/commit values; they also test extra pins, namespace/Pod reuse, interface and anchor reuse. They require failed Account/adoption/retirement to preserve the native/deny chain and real UDP loss. The foreign-anchor test ensures a transient Cilium FD was not retained.

The C-agent suite separately verifies always-drop packet invariance across arbitrary port numbers/non-IP, no execution of the following synthetic program after deny, actual UDP delivery suppression, and an actual child SIGKILL while handles/lock remain held. Check counters and deny BEFORE adopting after crash. Synthetic Cilium-named fixture anchors demonstrate TCX behavior only, not native Cilium production integration.

## Qualification next

Primary should inspect the code, compile all three packages using the actual Go/module versions, run meaningful race/unit/vet/lint and the full required rootful private-netns kernel tests on both hooks, and reproduce each injected failure. The CLI lifecycle also needs exact-image testing: listener collision before attachment, strict config/env rejection, fresh/unfresh readiness, graceful process-FD release preserving pins, real SIGKILL + adoption and stale config rejection. No DS installation or image publication is authorized by this review. Keep local-first/CI-deferred constraints and preserve cmtc-a/b and native security guards.

Primary's first actual ordinary rootful race run exposed a test-fixture mode error: Go1.27 t.TempDir leaves are not guaranteed0700 in this environment. Primary is explicitly chmod'ing owned PinRoot/LockRoot fixture directories0700 before opening; preserve loader validation unchanged. The companion C-agent fixtureFenceConfig LockRoot needs the same explicit chmod. This was an executed fixture failure, not a kernel fence failure; later results belong to the primary's evidence ledger.


## Independent C and packet-test review (proposal author)

# Independent C/kernel review of the Grok restore-fence proposal

Reviewed full `docs/research/cursor/RESTORE_FENCE_IMPLEMENTATION.md` and actual current observer interfaces at CMTC root HEAD70429264be4c746fcee4281c9e3fe7d89b2d8376. Proposal only: no root/source edits, builds, kernel attaches, cluster operations, CI or publication. Primary reports observer prototypeb193 qualified in both labs, all25 top-level/49sub/9kernel tests0skip and actual120attempts80allow40nativeDENY plus84logger/cleanup checks; these are parent evidence, not executions by this reviewer. Labs currently have no observer DS, no ztunnel, Cilium8b ready with ClusterMesh guard closed.

## Decision agreed with primary and Go reviewer

Use a **DENY-ONLY first persistent slice**. No grant/lease/binding/verdict/generation/deadline maps, test-only writer or test lease ELF. `fence.c` has one PerCPUArray `accounted`, keyu32 value{packetsu64,bytesu64}, max_entries1; `cmtc_fence` SchedCLS always returns TCX_DROP2, irrespective of map content/lookup success. It does not rewrite packets or parse ports. Selected TCX hook + validated pinned-link incarnation, not a user-writable ifindex string in a grant map, binds this program to a device.

The standalone pinned hook is a bounded quarantine experiment. It does not wire CNI admission, close pre-restore kernel gaps, establish identities/authorization/mTLS, or qualify Protected. No production native Cilium guard is implemented by these files. No all-node workload enforcement deployment is proposed; test only disposable explicitly audited fixtures.

## Findings in the original proposal

1. **The original __sk_buff.ifindex offset40 is correct.** Compared with Cilium's actual `bpf/include/linux/bpf.h:6076`; ingress_ifindex is36, ifindex40. Do not invent an ABI bug here. The deny-only replacement needs only offset0 len and avoids unused hand-copied fields. `skb->ifindex` selects current TCX device, not a cryptographic Pod/namespace/cluster identity.
2. **Mutable ARRAY records do not form coherent authorization.** The original binding and decision are separate multi-field ARRAY elements updated in place without BPF spinlock/BPF_F_LOCK or an immutable/COW publication design. A packet can observe mixed updates. Generation is hardcoded1, so it is not durable incarnation authority. Both records plus ifindex can be spoofed by any authorized writer; matching them proves no SVID/cluster identity. A future grant needs separately reviewed authenticated provider and atomic publication/revocation semantics; do not add it to this quarantine slice.
3. **A future-expiring test lease is a real kernel grant.** One-hour test grants survive process death until deadline or adoption. `now < expires_ns` accepts UINT64_MAX, with no TTL cap, reserved-field validation or issuer provenance. An unexported Go method in a normal .go file is not a test-only build boundary. 'Production never calls it' does not remove the grant semantics from the ELF. These paths are removed entirely, not renamed.
4. **Adoption failure must not detach quarantine.** Original mismatched config calls retireDir, removing protection because of a typo, changed MAC or misleading input. A renamed/MAC-changed live device is still the same quarantined kernel netdevice and must stay denied. Never derive cleanup authority from config mismatch. Go reviewer provides exact map/program/link provenance, frozen metadata, complete-commit validation and defunct-only retirement; use that implementation rather than original code.
5. **The original program's two-map names don't establish provenance.** A pin called guard is not proof the attached program references that map. Adoption must verify program compatibility/hash, map IDs/schema and exact TCX link identity, not trust a JSON claim. Ordinary identity.json storage under bpffs is invalid; Go reviewer replaces it with frozen metadata maps. Shared observer ErrClosed redeclaration also prevents compiling the unrefined proposal; use ErrFenceClosed.
6. **Original crash test does not crash the installing process.** It gracefully ReleaseProcess first and creates another process which also releases FDs before being killed. A sleeping process with no ownership proves little. New TestMain branch creates actual pins+link, retains Fence/FDs/cross-process lock through runtime.KeepAlive until actual SIGKILL, and checks real denial BEFORE Adopt can repair anything.
7. **A nonempty chain is not a persistent fence.** Require the exact own+original baseline program/link order and actual packet denial after death. The original expired/malformed tests sometimes check only 'passed did not increase'; packets which never reach the hook pass that assertion. Require positive baseline delivery, post-fence drop counters, unchanged following-program marker counter, and actual UDP socket timeout.
8. **AF_PACKET receive taps can precede ingress TCX.** A raw tap seeing a frame cannot be used as post-fence application delivery. Tests send real raw Ethernet/IPv4/UDP frames but receive through actual UDP sockets. Filtered follower runs behind fence and counts only a unique marker. Baseline success must precede denial. Fixture source IP is deliberately not locally assigned, and an owned /32 reverse route prevents accept_local/rp_filter defaults from masquerading as fence denial. No sysctls changed.
9. **Both hooks need real tests.** Egress raw frames are sent on selected host veth; ingress frames on peer. Changing cfg.Direction on an ingress-bound fixture is not an egress qualification. New tests use actual correct attach types, direction-specific follower and both-direction UDP delivery/drop. The C program-test-run covers multiple destination-port bytes/unknown ethertype but is explicitly not TCP application evidence.
10. **Name prefixes are not workload ownership.** A lxc* health/ingress veth needs real endpoint labels/UID ownership exclusion; kind eth0 is also veth. Go reviewer strengthens exact direction-specific Cilium entry name validation, but a manually configured fake Pod UID is not Kubernetes proof. Primary must audit actual disposable Pod endpoint/netns/namespaceUID before any live lab test. Do not use this CLI as automatic enrollment.

## Supplied files and exact interfaces

- `fence.c` -> proposed `internal/datapath/bpf/fence.c`.
- `fence_kernel_privileged_test.go` -> proposed new `internal/datapath/fence_kernel_privileged_test.go`.

Tests use existing actual root helpers `fixture`, `directionalFixture`, `query`, `Count`. Go lifecycle peer agreed:

```
FenceConfig{Cluster,Node,NamespaceUID,PodUID,NetNSInode,IfIndex,IfName,MAC,
 PeerIfIndex,Direction,CiliumLinkID,CiliumProgramID,PinRoot,LockRoot}
InstallFence(c,elf) (*Fence,error)
AdoptFence(c,elf) (*Fence,error)
(*Fence).Account() (FenceCount,error) // DroppedPackets,DroppedBytes
(*Fence).ReleaseProcess() error
RetireDefunctFence(c,elf) error
```

PinRoot must already be private root-owned0700 bpffs; LockRoot ordinary root-owned0700 outside bpffs. Successful Install has complete validated pins+commit. No live retire API. Tests ReleaseProcess before RetireDefunct to avoid waiting on their own exclusive lock. Only after deleting owned veth should exact defunct retirement succeed; unknown Info/ENOLINK behavior is a failure to qualify, never destructive guessing.

Three actual test functions, each with ingress/egress subtests:

- `TestPrivilegedFenceVerifierAlwaysDropUnchanged`: actual kernel verifier+program-test-run, destination ports0/80/8080/31337/65535, unknown ethertype, packet unchanged, exact packet/byte counters; overwrite telemetry with max values and still DROP. No policy/authentication inference.
- `TestPrivilegedFenceUDPAndFollowerStopBothDirections`: actual UDP baseline succeeds and marker follower increments; install actual fence before exact anchor/revision; three real packets fail to reach UDP socket, follower stays unchanged, drop counter increases. This is C-level wire proof independent of filesystem/adoption correctness.
- `TestPrivilegedFencePinnedCrashDenyAndDefunctCleanup`: actual child Install owns FDs/lock, positive baseline -> deny -> SIGKILL -> exact chain persists -> real deny BEFORE Adopt -> live-retire rejection -> Adopt checks counters -> ReleaseProcess still denies -> delete owned veth -> defunct cleanup. A TestMain helper branches on private environment; merge with any existing TestMain, never define two.

`CMTC_FENCE_ELF` identifies the separately compiled deny-only ELF. Keep `CMTC_BPF_ELF` pointing to the observer ELF for existing observer tests. All tagged tests run together so neither ELF substitutes for the other.

## Primary qualification commands (not run by reviewer)

In the already authorized **rootful disposable Podman private mount AND network namespace**, never rootless uid-map0->501, never host networking or kind-node test fixture:

```
clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/fence.c -o /tmp/fence.o
export CMTC_FENCE_ELF=/tmp/fence.o
# Preserve observer CMTC_BPF_ELF and CMTC_BPF_OBSERVER_BIN from its build.
CMTC_BPF_TEST_PRIVATE_NETNS=1 go test -race -count=1 -tags=cmtc_bpf_privileged -v ./internal/datapath
# Include full unit/race/vet profile and inspect actual selected tests/zero skips.
```

Only gofmt syntax parsing was performed here. No successful compilation/verifier/packet behavior is asserted. Actual current Go lifecycle code must be integrated before tests compile; no hidden API stubs supplied.

## Remaining critical window

Persistence is asserted **after successful complete Install returns**. Kernel attach and filesystem pin are separate syscalls. SIGKILL between attach and pin can remove the new hook and expose the old Cilium program again; a later complete-commit map does not close that interval. Pinning maps before attachment cannot atomically pin an as-yet nonexistent TCX link. The Go reviewer explicitly retains partial state/FDs and refuses destructive cleanup, but process death still releases an unpinned link. This remains an open native CNI/restore/admission gate, not a prototype success case to hand-wave. Native Cilium default-deny instructions must be installed/verified before workload release; old pinned programs otherwise still forward. Persistent after-install quarantine is useful evidence, not first-packet protection.
