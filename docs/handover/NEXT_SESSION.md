# Current continuation checkpoint

## User-requested AI handoff — 2026-10-25T16:40Z

Read root [handover.md](../../handover.md) and [resume.md](../../resume.md) first. Both test
namespaces are now enrolled. Baseline requests passed36/36 from each cluster.
The first enrolled request failed in each cluster with curl56 and no HTTP200.
Strict xDS Address full-resync loops and connection draining are now captured.
B logs identify the HBONE path but do not establish completed mTLS traffic.
The temporary Opus writer was stopped for handoff; the new AI must claim the
single compiler/live lease before mutation. Preserve all existing branches,
Pod registrations, signer state and durable checkpoints. This supersedes older
runtime/ownership paragraphs below. The user's instruction to complete cmtc-b
was carried through enrollment, first traffic and evidence capture; its actual
positive-path failure remains open. See the full handover for exact next work.


## Live checkpoint — 2026-10-25T16:35Z

This checkpoint supersedes older runtime and ownership statements below.

- All four Cilium agents and all four node ztunnel Pods are Ready. Exact current
  agents/operators/API servers use Cilium51170b1239; proxies use ztunnel35a6c94.
  CMTC controller and node-agent images were rebuilt from96cbc9e and deployed in
  both clusters. The registrar image is built; its persistent helper is not yet deployed.
- The user explicitly approved hostPID on both Cilium agents. Shared host PID
  namespaces resolved the strict root-owned-proxy ZDS rejection. The UID/PID
  checks remain enforced. See [installation requirements](../../INSTALLATION_REQUIREMENTS.md) and
  [runtime evidence](../evidence/strict-zds-hostpid/README.md).
- ClusterMesh is **not fully healthy**: all agent status reads show0/1 remote
  clusters Ready, despite connected etcd and synchronized nodes/endpoints/
  identities/services. Membership lock timeouts and native ZDS ownership-busy
  endpoint regeneration errors remain open. Ready Pods do not qualify mTLS.
- Test apps now run on both nodes in cmtc-a; cmtc-b setup and real baseline/
  enrollment tests continue. Signers, private keys, checkpoints and existing apps
  are preserved. One-time proxy checkpoint bootstrap is disabled in both
  OnDelete templates after verified durable commits; existing proxies were not restarted.
- All four personal repository defaults were fast-forwarded to our current work:
  Cilium51170b1239, SPIRE0f8fe4d681, ztunnel35a6c94, CMTC96cbc9e.
  Every working branch/worktree remains. No canonical upstream merge occurred.
- Codex retains the sole operational compiler/live lease. Opus source resumption
  uses fresh retained logs and explicit ownership. No compiler or live writes
  transfer until the lease says so. The original runner must not be restarted.
- Read-only heartbeat `cmtc-logs-and-network-monitor` checks every five minutes.
  It reports meaningful failures/recovery and makes no cluster changes.

Next: fix actual membership/ZDS runtime errors, complete exact workload
registration and enrollment, test same-node then cross-node and both cross-cluster
directions on80/8080/31337. Preserve all security gates and record genuine
failures. Complete R7 effective source-egress and other open source gates; do not
replace them with permissive policy. Full cross-cluster workload mTLS is unproven.


Updated 2026-10-25. This checkpoint supersedes older current-state paragraphs in delivery history. The full end-to-end workload-mTLS mandate is active. A question, review, document or commit does not pause it. Read [the master prompt](CODEX_MASTER_PROMPT.md), [delivery status](../agile/DELIVERY_STATUS.md), [recovery receipt](OPUS_RECOVERY.md) and the security acceptance matrix.

## Actual quota and operational continuation

Claude has now actually hit its session limit; the CLI reports **11:30 a.m. America/Chicago**. The XHigh review did not return a completed result. Preserve its [partial session record](../research/cursor/OPUS_XHIGH_PARTIAL_REVIEW.md). Codex takes the sole operational compiler/live lease while Opus is unavailable; product implementation remains Opus-owned. The current agent and API-server rebuilds pass with unchanged source/image pins. User authorizes commit-all and merge-all into personal repository defaults, with **every working branch/worktree retained**. This supersedes the earlier no-merge/push boundary only for those merges; do not merge canonical upstream, force push, publish registries or dispatch manual CI. Continue actual deployment from verified current code; no mTLS claim yet. Read root resume-opus.md for the live handback and safe-runner requirements.

## Immediate local activation mandate

The user now explicitly directs Opus to **rebuild the current code, deploy it and enable mTLS now** on the owned lab. Codex queued the full mandate to the active Max implementation owner. Prioritize current-source host-Podman rebuild, exact-image deployment, concrete ztunnel activation and immediate real traffic; do not wait for optional reviews, dashboards, quota reset or CI. Keep one compiler/live writer and preserve the restricted Admin/socket and signer boundaries. Report actual positive/denied/failed paths; activation is not a Protected claim. Finish the requested root resume-opus.md as a concise checkpoint. The Claude quota has not been reached. No external publishing was requested.

## Mandate and ownership

Complete workload mTLS through our enhanced Cilium ClusterMesh path on both `cmtc-a` and `cmtc-b`. Use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change**. All implementation belongs to **Opus5.5**. Codex coordinates, maintains documentation and independently reviews source and evidence. Grok supplies adversarial proposals. Preserve one compiler and one live writer.

Opus5.5 Max owns the isolated Cilium, ztunnel, SPIRE and CMTC source, plus registrar, DaemonSet, metrics and dashboard implementation. Read `review/OWNERSHIP.json`, `BUILD_SLOT.json` and `LAB_OWNER.json` under `/private/tmp/cmtc-opus-final-20261025/`. Primary compilation and live writes remain disabled. Normal permission review remains enabled. Agent/Server Admin DAC migration is **not approved**. Use the separate restricted DelegatedIdentity-only listener. Preserve signers, root keys, unrelated applications and security gates.

The latest AGENTS instruction defers pushes that trigger CI, manual workflow dispatch and registry publication. Qualified local commits are allowed. Do not substitute Opus4.8 or another model. The refused Fable probe's substituted response is not used.

## Claude session window

The user reports the current Claude allowance will end soon and resume at **11:00 a.m. Central**. This is an expected reset, not verified quota state. The user explicitly clarifies that the limit has **not** been reached; continue work now. The checkpoint request is not a pause or instruction to wait until11. Codex queued a request for a durable source/live/test/next-command checkpoint at the next safe boundary. Preserve active tools and do not interrupt a compiler or rollout. On an actual rate limit, retain the exact error/reset time, avoid repeated retries or model substitution, and continue independent read-only review/documentation. The user has not paused the CMTC mandate. No new scheduled automation was created.

## Active implementation session

- CLI model: `claude-opus-5-5`; actual effort argument: `max`.
- Session: `c03d57db-e2bf-4848-ab73-3f2696a27d2f`.
- Runner: `/private/tmp/cmtc-claude-opus-20261025/run-live-max-owner.py`.
- Exec session: `79321`. Read `live-max-owner-pid` and verify the process before steering.
- Transcript: `live-max-owner-session.jsonl`; errors: `live-max-owner-stderr.log`; eventual completion: `live-max-owner-exit`.
- Append one complete user-message JSON record to `live-max-input-queue.jsonl` to steer without interrupting tools. `live-max-input-offset` records forwarded bytes. Verify replay and acknowledgment. Do not start another implementation writer.
- `live-max-owner-model-block.json`, if present, records a stopped model substitution. Do not accept fallback output as requested-model work.
- Current working status: `/private/tmp/cmtc-opus-final-20261025/review/STATUS-CLAUDE.md`. Raw logs and lab receipts: `/private/tmp/cmtc-claude-opus-20261025/`.

## Requested XHigh review

Codex completed the [Grok recommendation comparison](../research/cursor/GROK_RECOMMENDATION_REVIEW.md) and [open-gate review](../research/cursor/GROK_CURRENT_OPEN_GATES_REVIEW.md). The original report audits d040a4bc9a. The comparison freezes37d5fce0f7; it does not qualify newer membership changes.

The full package was sent to a separate **Opus5.5 XHigh read-only reviewer**, session `c0e51864-c536-41eb-8839-a34043c36e6e`. Actual init and assistant messages report `claude-opus-5-5`; its CLI argument is `--effort xhigh`. It has only Read/Glob/Grep and a model-substitution guard. Main Max retains all implementation/compiler/live ownership.

Review files: `/private/tmp/cmtc-grok-followup-20261025/opus-xhigh-{prompt.txt,command.json,session.jsonl,stderr.log}`. Read `opus-xhigh-exit` or `opus-xhigh-model-block.json` when present. The model receipt is in [review evidence](../evidence/grok-recommendation-review/opus-xhigh-receipt.json). This review is still in progress. On completion, independently inspect the answer, preserve the full report, and send accepted recommendations, full code and tests to the Max owner at a safe boundary. All new proposal code is UNRUN.

## Source checkpoints

All isolated trees are under `/private/tmp/cmtc-opus-final-20261025/`, branch `feat/opus-mesh-mtls-finalization`. Verify actual HEAD and dirty state before any work. Latest primary read found the Cilium and isolated CMTC trees clean.

| Source | Commit | Scope |
| --- | --- | --- |
| Cilium | `51170b123988cda86aaea1bef3ccd95d221b8bbb` | Dedicated membership etcd transport and scoped server users. Builds on remote projection92ce2b90d3, policy/releaseada009a5f0 and capability guard37d5fce0f7. |
| Cilium admission | `a74f13a688` | Zero-address rejection, retry, publication serialization and retirement. |
| SPIRE | `0f8fe4d6812c388be9ffd7b6d160e67b59163d95` | Separate DelegatedIdentity-only listener. |
| Ztunnel | `35a6c9403eb5c00b1b79aafe2851f423cd195540` | Preserved native proxy implementation. |
| Root CMTC registrar | `18c47cc` | Source-tested metric instrumentation; no live scrape yet. |

The four original recovery commits and backup are recorded in [OPUS_RECOVERY](OPUS_RECOVERY.md). Preserve them, old branches and failure logs. Root CMTC branch is `feat/end-to-end-enforcement`; inspect actual HEAD. Review documents and evidence were locally committed at1e62673 andee8e8df before this checkpoint update. No push occurred.

## Current runtime

Use kubeconfig `/private/tmp/cmtc-a-b-20261024.kubeconfig`, with explicit `kind-cmtc-a` and `kind-cmtc-b`. Never print its contents.

- A kube-system UID: `bb7182c7-de95-4e70-816a-a1400d755794`.
- B kube-system UID: `f2687af6-bd96-45a3-98a2-d1397a3ee244`.
- Colima `cmtc-cilium`: Ubuntu ARM64,8CPU/16GiB/90GiB. Preserve this runtime and existing applications.
- Primary API read: both Cilium DaemonSets use `localhost/cilium:dev-overlay-51170b1239`,2 ready each. Both ClusterMesh API-server Deployments use `localhost/cilium-clustermesh-apiserver:dev-overlay-51170b1239`,1 ready each. [Read receipt](../evidence/grok-recommendation-review/runtime-receipt.json). These are development overlays, not a complete Cilium release.
- The owner records36/36 plaintext HTTP connectivity after each API-server rollout. Opus also records agent canary endpoint/program checks; inspect actual logs before claiming their acceptance.
- SPIRE delegated agents0f8fe4d6 run on all four nodes. Both actual credential/rejection/withdrawal/restart matrices pass12/12. Existing Admin DAC is unchanged.
- KVStoreMesh is ON. The latest owner checkpoint has ztunnel, WireGuard and IPsec OFF. No workload-mTLS or Protected claim.
- Issuer-profile approval and SPIRE cluster CAs expire `2026-10-26T03:55:11Z`; output leases are at most30s. Preserve private state under `~/.local/share/cmtc-issuer-profile/live-a-b/`. Never reset floors or read protected root keys.

## Evidence and open failures

- Node binding:67 top-level/169 total race passes, zero skips/failures, vet0. Old-source semantic regression fails.
- C3 kernel:8 objects/72 leaf cases pass. Old-source zero-address failures and delayed-write red reproducer are retained. Corrected endpoint Go runs pass167/62 top-level with21 existing integration skips. Do not count wrapper exit0 over the earlier package panic as a pass.
- Broader37d source run:2,853 test passes/681 top-level,52 skips, race0/vet0. Skipped privileged cases are unqualified.
- SPIRE run3:321 passes/33 top-level, zero skip/fail, cross-platform vet/build0. Preserve run1 assertion failure and the independently reproduced set-group-ID defect fixed before rollout.
- Registrar:27 top-level/58 total Linux ARM64 race passes, zero skip/fail, vet0. No image/live-scrape qualification.
- R6 focused suites:280 passes/144 top-level with40 skips, then176/94 top-level withzero skips; race/vet0. Real etcd authorization and lease tests ran. The broader scripts still fail under race in runs13/14. Run15 passes16 cases without race and does not close that failure. [Independent receipt](../evidence/grok-recommendation-review/r6-test-receipt.json). Require a real clean-baseline reproduction or fix/race rerun before accepting an unchanged-upstream explanation.

## First unfinished delivery dependencies

1. Complete and qualify R6 agent membership credentials, origin readers and real publication. Do not point the general agent KVStore at ClusterMesh etcd. Do not use Admin credentials or ephemeral manual roles.
2. Close ADS client authentication: server-only loopback TLS allows a local host-network process to open a newer stream and supply ACKs. Bind release evidence to the actual authorized proxy. Keep this open until tested.
3. Deliver realized source-egress policy for cross-node and cross-cluster callers. Current effective ALLOW covers captured same-node sources only; other sources fail closed. Cluster-shared writer credentials also leave per-node provenance open.
4. Activate the exact qualified ztunnel image locally. First qualify a limited same-node path, then both clusters and cross-node/cross-cluster paths. Preserve all unmet security gates.
5. Test positives, plaintext/identity/policy negatives, stale/disconnected/NACKed state, restart, withdrawal and recovery. Cover Global Service and Pod IP with80/8080/31337, both directions. Record authenticated peers, effective policy, packets and exact image versions.
6. Close kernel/lifecycle gates: permanent update failure, initial capture/restore, endpoint-ID/IP reuse, old programs, probe/platform exceptions and original-tuple policy. The proposed kernel lease only bounds stale forwarding; it is not implemented or an approved SLA. CT_RELATED traces to selected ICMP errors, not demonstrated TCP payload bypass. Preserve PMTU and qualify real packet classification.
7. Fulfill live telemetry and update Grafana under representative load. Commit qualified increments and continue.

## Metrics, images and build environment

The two consolidated dashboards retain all nine historical domains. Contracts are in root `observability/metrics.json` and `capabilities.json`. Source-tested collectors are separate from deployed/collected/protected state. Grafana at http://127.0.0.1:13000 remains unchanged in the last independent query: both dashboards version4, six CMTC Observe targets, no native TLS/registrar series or ztunnel targets. Do not insert healthy zeros for absent exporters. Opus owns instrumentation and dashboard implementation.

The ztunnel rebuild now reports Clean at35a6c94; owner records configae3844096b58 and binary hash5a348cdb, using a refreshed private index. The earlier dce7654 image reporting Modified is superseded. Independently verify full provenance and running digest before acceptance; it is not yet live.

Use host Podman connection `cmtc-ubuntu-build`, explicit Linux ARM64 and bounded2CPU/4GiB. Preserve default connections and shared resources. Transfer archives into the existing Colima/kind runtime; verify loaded configuration IDs, architecture and actual running binary revisions.

- Go/clang image: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`.
- Rust namespace image: `def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f`.
- Go cache: `/private/tmp/cilium-ztunnel-linux-go-cache`; modules: `/private/tmp/cmtc-spire-go-modules`.
- Private rootful socket: `/tmp/cmtc-observer-rootful/podman.sock`. Preserve active tests. No global prune/sysctl changes.

## Authorship

Name our work as **CMTC-authored additions or modifications in our ephico2real2 forks**. Identify unchanged upstream components and reused APIs separately. Preserve the human Git author and upstream notices. Describe Opus/Codex/Grok assistance separately. Authorship, source tests, readiness and ACKs do not establish working workload mTLS.
