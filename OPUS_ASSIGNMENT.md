# CMTC ClusterMesh mTLS finalization — Opus 5.5 High

Use the explicitly requested Cursor model `claude-opus-5-5-high`.
Act as a principal Go, Rust, eBPF, Cilium, Kubernetes, SPIRE and observability engineer.
Audit our enhanced forks. Implement complete, reviewable fixes in the isolated branches below.
Produce real code, patches, tests and a precise qualification report. Do not stop at a plan.

## Objective

Deliver working code for the complete native path that enables node-level ztunnel safely in our two-cluster Cilium ClusterMesh. This is an implementation assignment, not a design-only review.
Applications use no sidecars. CMTC manages intent and trust; SPIRE attests and issues credentials;
Cilium owns native discovery, capture, policy and xDS; ztunnel performs workload TLS and authorization.
The primary layered target adds WireGuard or IPsec beneath workload TLS. HBONE-only is a control profile.

The final acceptance result must come from exact images and real bidirectional application traffic.
An API label, registration, SVID, xDS ACK, source-IP bit or map reference does not establish Protected.
A SPIFFE string is not cryptographic proof. No mock injection or CMTC-to-ztunnel shortcut may replace the native path.

## Isolated source and ownership

All four repositories have the new branch `feat/opus-mesh-mtls-finalization`.
Use these checkouts only for edits:

| Repository | Isolated checkout | Qualified starting source |
| --- | --- | --- |
| CMTC | `/private/tmp/cmtc-opus-final-20261025/cmtc` | `4a93ca32cf78df773fe5f2af9ac6ecf423ff76fd` |
| Cilium | `/private/tmp/cmtc-opus-final-20261025/cilium` | `07722a595a` (resolve full SHA before work) |
| ztunnel | `/private/tmp/cmtc-opus-final-20261025/ztunnel` | `75843515d549f7928d080801ac3f7e4344f572eb` |
| SPIRE | `/private/tmp/cmtc-opus-final-20261025/spire` | `28f6b8d84ade21c6accb32ba9689a3bdf64877ec` |

Their origin remotes are the corresponding `ephico2real2` forks. Upstream remains canonical.
Cilium is 51 commits ahead and zero behind fetched upstream/main; ztunnel is16/0 against upstream/master;
SPIRE is1/0 against upstream/main. Preserve the enhanced source and old branches.
Do not replace our fork with stock Cilium or redo features from an old release.

The primary is concurrently implementing and qualifying repeated CI screenshots during the real eight-stream load.
Do not modify `.github/`, `scripts/capture/`, `scripts/lab/load.sh` or `scripts/lab/capture.sh`.
Do not edit the primary checkouts. Do not push, merge, publish images or dispatch CI.
You may edit security code, tests, owned lab helpers, metrics implementation and documentation in the isolated trees.
Use minimal coherent changes. Preserve existing APIs unless a source-backed migration is necessary.
The primary reviews your patches and owns live deployment and final acceptance.

## Read first

Read CMTC's `AGENTS.md`, `docs/handover/CODEX_MASTER_PROMPT.md`, current delivery status, backlog,
`docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md`, `ARCHITECTURE_UPDATE.md`, `PKI_TRUST_FLOW.md`,
`SPIRE_REGISTRATION_WORKFLOW.md`, `SPIRE_REGISTRATION_DESIGN.md`, `LOCAL_IMAGE_BUILD.md` and source evidence.
The newer facts in this assignment supersede older status text.
Read the actual Go/Rust/BPF interfaces before proposing changes. Verify signatures and call sites.
Use CodeGraph only if a `.codegraph` index exists. Do not trust a TokenSave index serving another branch.

Review, enhance and refactor the ACTUAL proposed CMTC dashboards. The user explicitly rejected an assignment limited to reviewing dashboard rules. Read and edit the real dashboard sources and their generator. Use these diagram-kit skills as tools for that implementation:

- `/Users/olasumbo/gitRepos/diagram-kit/skill/dashboard/SKILL.md`
- `/Users/olasumbo/gitRepos/diagram-kit/skill/dashboard/COLLECTION.md`
- `/Users/olasumbo/gitRepos/diagram-kit/skill/visual/SKILL.md`

Required dashboard work:

1. Inventory every panel in `observability/dashboards/operations.json` and `workload-security.json` (locate their actual paths), the generator inputs, and the nine historical capability domains. Read the existing titles, PromQL, transformations, units, reductions, legends, thresholds, layout and descriptions.
2. For each panel, identify the user question, actual emitted metric or owning future story, and what the data proves. Produce `DASHBOARD_REVIEW.md` with keep/combine/rename/redesign decisions and the reason for each decision.
3. Implement the improved dashboards and generator changes in the isolated CMTC tree. Make one or two coherent dashboards that show operations, workload identity, mTLS, authorization, recovery, traffic and transport composition clearly. Preserve all historical capability coverage; do not delete planned security capabilities because their collectors are unfinished.
4. Choose charts based on metric semantics. Use trends for rates, tables for per-cluster/node state and failure details, counters with explicit time windows, and percentage charts only for mutually exclusive outcomes from one denominator. Keep TCP attempts, rejected connections, authenticated connections, requests and handshakes distinct.
5. Add or repair owning collectors and scrape/query integration when needed. Keep unimplemented capabilities visibly planned. Do not fabricate series or turn missing data into a healthy zero.
6. Test generated-file consistency, PromQL/metric contracts, label cardinality, filtering and absent/stale data. Provide the exact local load and both-theme screenshot acceptance steps for the primary. Screenshots must show actual relevant data, not decorative empty panels.
7. Preserve stable UIDs and links where practical. Document any migration. Deliver complete JSON/source/code changes, not only recommendations or a style audit.

Apply the dashboard workflow: emitted metric inventory, actual collection path, reader question,
metric type, truthful query/reduction/window, fixed Tableau colours and lower legends.
Preserve both consolidated dashboards and the nine historical capability domains.
Keep planned metrics visibly planned until the owning code and actual scrape/query evidence exist.
Attempts, policy rejections, TCP connections, TLS handshakes and HTTP requests are different quantities.
A percentage chart must partition one stated denominator. Avoid dual-endpoint double counting.
Use cluster/node labels and the existing Prometheus B-to-A remote-write path; no new counter aggregator.
Documentation diagrams are light-only. Grafana qualification still needs both themes after load.

## Current runtime and evidence

Persistent labs are only `cmtc-a` and `cmtc-b`, two nodes each, in Colima `cmtc-cilium`.
ClusterMesh and KVStoreMesh are ON. Applications pass36 local/cross-cluster Service/Pod-IP paths at TCP80/8080/31337.
Cilium runtime remains `4459d58ed3`; newer source is not deployed. CMTC runtime remains `f5fe9992da855a22660c07b141e19feee50310ba`.
SPIRE server/agents use `28f6b8d8`. Ztunnel, WireGuard and IPsec are OFF in the combined profile.
Do not create or recreate clusters, run up/down scripts, alter live Kubernetes resources or read live Secrets/kubeconfigs.
Keep all unrelated applications, signers, PVCs, host forwards and authority ledgers intact.
The primary will perform the reviewed live rollout and traffic qualification.

The corrected registrar experiment passed both clusters: exact target withdrawal with valid same-node controls,
reenrollment, same-name Pod replacement, server restart and exact cleanup. All124 host helper tests pass.
Its temporary third server container was removed; original templates are restored.
The helper lives inside the SPIRE server Pod and uses its private server Admin socket there.
It does not sign certificates or carry traffic. One permanent registrar owner is still undecided.
Compare enhancing Cilium's native registrar with retaining this helper; prevent duplicate broad registrations.
The persistent agent Admin group-permission migration was rejected by approval review and remains pending human approval.
Do not change agent DAC, expose Admin sockets to applications, or bypass that boundary.
The diagnostic UID1000/GID0 profile is not production proxy qualification.

The PKI chain is organization root -> explicitly approved cluster intermediate -> exact SPIRE signer -> workload SVID.
Do not trust every signer under a shared root. Keep the root private key outside clusters and evidence.
The public issuer-profile producer is live; its leases are at most30s and its approval expires2026-10-26T03:55:11Z.
Never reset the monotonic producer ledger or rollback floors to recover availability.

## Latest local source results

- Cilium `3985cc135a`: lost-ADD-ACK and queued-send recovery. Retains bounded exact history and pending consumers;
  only correlated native drain receipts retire ownership. Clean-checkout actual-etcd race/vet passed416 top-level/1713subtests.
- Cilium `c17af5304e`: test-only repository lock scopes and lockdebug logger setup; no weakened assertions/timeouts.
- Cilium `07722a595a`: actual loaded endpoint policy-map/tail-call/TCX reference checks. The real IPv4 kernel test passes,
  including compiled-out family, missing/replaced LPM pin, changed/deleted tail-call slots, extra TCX and recovery.
  The broad ARM64 race/vet profile passes475 top-level/1814subtests. One standalone upstream verifier benchmark is skipped;
  it is not counted as proof. Full affected lockdebug passes416/1713 with no failures or skips. Lint reports0 issues.
  IPv6 and dual-stack kernel qualification remain open. Point-in-time references do not prove mandatory capture.
- The previous Opus fixture pass provided two patches. Primary measured kernel map IDs and corrected two additional
  mistaken expectations: IPv4 policy slot11 references the endpoint LPM map only; continuation slot26 references
  the endpoint LPM and global policy ProgramArray, not the internal calls array. Keep those real observations.
- ztunnel `75843515d5`:518 library+20direct+30namespace tests plus2diagnostic cases pass, with fmt and strict Clippy.
  First SPIRE stream error ends its request. Source witness and stale idle/active HBONE drain controls are present.
- CMTC CI run40177163792 passed unit/build and deployed Observe lab, six-minute eight-stream load, measured results and screenshots.
  That baseline does not qualify combined workload mTLS.

Raw previous kernel logs: `/private/tmp/cmtc-policy-reachability-20261025/`.
Latest recovery logs: `/private/tmp/cmtc-lost-add-ack-20261025/`.
The earlier source-backed restore proposal is `/private/tmp/cmtc-persistent-restore-quarantine-proposal/README.md`.
Review it critically: it is incomplete code, not an accepted implementation.

## Required audit and implementation

Trace the complete native path and supply implementation-ready fixes for every open dependency:

1. Authenticated remote workload discovery, atomic initial sync and ordered update/delete handling.
2. Cluster-bound identity, namespace/Pod/node incarnation, approved issuer and trust-domain provenance.
3. Mandatory all-application-port capture and fail-closed first-packet admission. Preserve native service/NAT/policy and platform traffic.
4. Durable Required intent and persistent restore quarantine before old pinned BPF can forward.
   A Go error cannot fence already attached programs. Old bytecode needs a staged upgrade.
   Process-epoch rotation alone leaves the crash-to-restart interval open; assess expiry/watchdog bounds explicitly.
   Never blindly use a map OpenOrCreate path that deletes/recreates existing deny state on ABI mismatch.
5. Effective policy compilation and native xDS delivery, exact challenge/version-bound ACKs and withholding on missing/stale/NACKed state.
6. Default-allow and raw outbound fallback risks, invalid/unenrolled identities, unknown protected destinations and all-port negative cases.
7. Exact ZDS owner, listener/flow/pool drain, pending sends, lost ACK, reconnect, restart, UID/IP reuse and idempotent recovery.
8. SPIRE registration source/expiry failure injection, signer rotation/revocation, duplicate writer prevention and production owner choice.
9. Workload TLS plus WireGuard/IPsec MTU, bypass, recovery and performance composition.
10. Metrics contracts across CMTC, daemonsets, Cilium and ztunnel. Review `observability/INVENTORY.md`, `METRICS.md`,
    `capabilities.json`, `metrics.json`, `build.py`, `validate.py`, Operations and Workload Security.
    Add truthful collectors at the owning boundary, bounded labels, scrape integration and query/negative tests.

Inspect our fork diff against upstream and improve unsafe code or unnecessary coupling.
Use Cilium's injected slog.Logger, standard logfields and Hive health/jobs. Preserve CMTC's controller logging integration.
Logs need component, stage, attempt, elapsed time, retry/deadline and public error; never log credentials or keys.
Keep retries bounded. Keep readiness, registration readback, credential validation, ACKs and Protected status distinct.
Do not enable the combined guard just to make an end-to-end test start.
Implement and test the prerequisites. Propose the exact opt-in activation/rollback transaction only when its gates exist.

## Build and test permissions

Use the MacBook host Podman CLI, explicit `linux/arm64`, connection `cmtc-ubuntu-build`.
Run at most one owned compiler/test/build container at a time, normally2CPUs/4GiB, preserving shared resources.
Go/clang builder: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529` (Go1.27.3/clang21).
Rust namespace builder: `def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f` (Rust1.90, iproute2/iptables).
Use isolated build targets for the new Rust worktree. Do not share an actively written target directory.
Go cache `/private/tmp/cilium-ztunnel-linux-go-cache` may be reused safely.
The task-owned rootful service is available through
`ssh://olasumbo@127.0.0.1:49691/tmp/cmtc-observer-rootful/podman.sock`, identity file
`/Users/olasumbo/.colima/_lima/_config/user`. Use that path as a CLI argument; never read its key contents.
Real BPF tests require disposable private netns and bpffs, never host networking or kind-node attachment.
Do not stop this shared task service or modify global sysctls. Do not prune shared storage or stop unrelated containers.
Use the existing qualified runner patterns, adapted to the isolated source path and unique task names.

You may build local images after affected tests pass. Record source/diff digest, toolchain, image config/digest and architecture.
No registry push, live deployment, permission migration or CI dispatch is delegated.
The primary will independently rerun critical cases, build/import exact images and perform live qualification.

## Required tests and deliverables

Write complete runnable code and tests against actual interfaces. Include positive, negative, restart and recovery cases.
Use real kernel programs/maps, sockets and credentials where needed. No skipped/zero-selected cases as proof.
Do not make tests pass by weakening assertions, hiding warnings, skipping failures, accepting arbitrary trust or faking metrics.
Separate fixture defects, source defects and unresolved runtime assumptions.

Write progress and final deliverables under `/private/tmp/cmtc-opus-final-20261025/review/`:

- `STATUS.md`: current dependency, changed files, test results and real blockers. Update after each coherent increment.
- `AUDIT.md`: exact source/call paths, findings, severity, alternatives, gotchas and evidence needed.
- `FINAL_REVIEW.md`: implemented increments, full test commands/counts, image pins if built, open gates and next action.
- `DASHBOARD_REVIEW.md`: panel-by-panel findings, implemented redesign/refactor decisions, metric ownership and real-data acceptance requirements.
- Complete per-repository patches and any source files not yet committed. No placeholder functions or abbreviated snippets.
- A reproducible local acceptance runner/manifest plan for both existing clusters, including safe rollback and exact cleanup.

The requested end state is actual bidirectional A-to-B and B-to-A workload mTLS through our enhanced Cilium and ztunnel forks, with effective denial and recovery and meaningful CMTC dashboards. Work through dependencies rather than stopping after a small patch. Provide runnable implementations and tests. If a live-only gate needs primary action, write the exact gate and continue independent implementation; do not report that gate as passed.

A final plan alone is insufficient. Implement what can be safely implemented in the isolated trees, test it locally,
and clearly identify anything that still prevents activation. The primary must not infer success from your report alone.
Use direct ASD-STE100-style sentences and consistent terms. Keep proposed behavior distinct from measured behavior.
