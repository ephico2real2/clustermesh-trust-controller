# Current continuation checkpoint

**Latest update:** Opus stopped on monthly spend limit; node-session exit1. Primary Codex owns source/compiler/lab continuation. Cursor Grok read-only node-port review runs in exec2734, logs `review/grok-node-session.jsonl`, confirmed Grok4.7ExtraHigh. Read [OPUS_RECOVERY.md](OPUS_RECOVERY.md) for the four committed clean recovery checkpoints and verified backup. The older process/lease details below are historical; do not resume them as active or wait for Opus. Latest user AGENTS defers CI/push-triggered runs. SPIRE role-before reproduces both gaps; role-after race17top/151sub andvet pass. First unfinished dependency: native node-name port plus incomplete C2 admission/recovery, then live integration on the two owned clusters.


Updated 2026-10-25. The full CMTC mandate remains active. The user warned about token limits. This is a continuation checkpoint, not completion or a pause.

## Cluster-first correction

The user requires Codex, Cursor and Claude to use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change**. Go components use explicit existing kind APIs where supported. Linux datapath work uses the Ubuntu toolchain and selected owned nodes. Coordinate one live writer. Application packaging follows a working integration path; final exact-image qualification remains required. All future delegations must carry this rule.

## Start here

Read `CODEX_MASTER_PROMPT.md`, this file and the latest sections of `docs/agile/DELIVERY_STATUS.md`. Preserve all dirty agent work. Do not restart the implementation or create replacement clusters.

The user explicitly authorized Claude Opus to use the existing kind contexts for immediate local API and integration tests. Read `docs/research/cursor/CLAUDE_LOCAL_CLUSTER_VALIDATION.md`. This replaces the original no-local-API restriction. It does not approve the previously rejected SPIRE Admin DAC migration.

## Primary repository

Path: `/Users/olasumbo/gitRepos/clustermest-trust-controller`.

Branch: `feat/end-to-end-enforcement`. Configured author: `ephico2real2`, `123043136+ephico2real2@users.noreply.github.com`. Origin uses the user's SSH fork.

- `c1e7501f1920f76ec45cc0f975a54a0550abb85f` is pushed. It delivers the compact dashboards, capture regression checks and real evidence. CI [40185013429](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40185013429) passed both jobs, image builds, loads and screenshots.
- `9ba49ec` is pushed. It records local cluster delegation and registration source-test evidence. Its `[skip ci]` marker avoids duplicate CI.
- `5ce3db378f72d90d4aba9e3829cba2dfe5850a80` is a **local source commit only**. It contains exactly four reviewed registrar files copied from the isolated tree after matching their base to the primary. Race tests pass 16 top-level tests and 28 subtests, plus vet. Build and qualify its exact registrar image before pushing this source commit. Later checkpoint documentation commits may follow it locally.

Qualified dashboard evidence is in `docs/evidence/dashboard-refactor/`. Registration evidence, exact patches, commands and failures are in `docs/evidence/registration-expiry/`. These reports distinguish source checks from runtime security.

## Claude process and source ownership

Claude Code uses canonical `claude-opus-5-5`, effort `high`, with normal automatic permission review. Do not use bypass mode.

Session: `c03d57db-e2bf-4848-ab73-3f2696a27d2f`.

Current runner: `/private/tmp/cmtc-claude-opus-20261025/run-live.py`. The earlier compiler runner completed cleanly.

Read `live-pid` to identify the current process; verify it before any signal. Current exec session is `20733`. Output is `live-session.jsonl`; errors are `live-stderr.log`; an eventual `live-exit` records completion. The old compiler process85032 exited0. Older `session.jsonl` and `cluster-session.jsonl` are retained transcripts, not the active stream.

The prior CLI turns exited cleanly at completed or idle test boundaries to receive user steering. Current instructions are in `CLUSTER_FIRST_CONTINUATION.md`. Opus acknowledged that it is not done and must find the shortest real live path. Do not start a second simultaneous writer in the same Claude session. For future steering, preserve source and wait for a safe test boundary before a controlled resume. Do not modify an executing runner: primary did that once and caused a wrapper failure; subsequent reruns passed.

All four isolated trees are under `/private/tmp/cmtc-opus-final-20261025/`, branch `feat/opus-mesh-mtls-finalization`:

| Tree | Current owner |
| --- | --- |
| cilium, ztunnel | Claude Code Opus |
| spire, CMTC security/registrar | Primary qualification of frozen Grok work |
| CMTC observability/capture/workflows | Primary |

Read `review/OWNERSHIP.json`, `BUILD_SLOT.json` and `LAB_OWNER.json` before work. **Primary owns the compiler now** for the two SPIRE role-expiry regressions. Claude can edit Cilium/ztunnel and use its live lab lease without overlapping compilation. A stale root `STATUS.md` previously confused the handoff; the live coordination file and `review/STATUS-CLAUDE.md` take precedence. Primary must not run another compiler/container test concurrently.

Claude owns live local test writes. Primary can inspect without mutation. Cursor Grok finished its turn; its old exec session54411 exited0. Do not assume it is still testing. Codex review agents have finished their proposals.

## Current Cilium run

Runner: `/private/tmp/cmtc-claude-opus-20261025/runners/cil-c1.sh 1`.

Logs: `/private/tmp/cmtc-claude-opus-20261025/logs/cil-c1-1/`.

Last observed: `bpf_lxc.o` compiles, dpgen reports no drift, full BPF permutations complete, and the selected BPF regression objects compile. Run1 later failed on a missing fixture logger; run2 failed on a runner log mount. Both diagnostics remain. Run3 passes stage A and stage B: 57 top-level/180 total Go tests pass, 21 pre-existing integration-dependent skips, vet passes, and 48 kernel subtests pass. Stage B uses the existing private rootful Podman service for real BPF PROG_RUN tests. Verify actual selected/passed/skipped counts. The prior broad endpoint run skipped21 integration cases; never report it as zero-skip proof.

The original deny-only patch reused sticky Required as a permanent packet drop. Claude is separating Required from quarantine and adding a mesh-only candidate and release receipt. This is **not qualified yet**.

Primary review findings are in `review/PRIMARY_BPF_ADMISSION_REVIEW.md`. Claude read that file in the current turn. Resolve and test these before active release or deployment:

- Missing own-map entries, partial address-family state and wrong endpoint ownership must fail closed for Required workloads.
- Unknown/world/CIDR identities must not turn protected mesh ranges into plaintext exceptions.
- DNS53 must target approved resolvers; it cannot exempt arbitrary workload port53. Host exceptions need explicit tests.
- Existing conntrack/plaintext flows must not bypass new enrollment or policy transitions.
- TCP15008 is a transport condition. It is not proof of authenticated HBONE. Preserve original application ingress and egress authorization.
- First-packet CNI ordering, restore, durable endpoint-ID recovery and old-program migration remain open.

Do not relax the compatibility guard based on port-predicate tests or ACKs alone. Continue implementation, not just another design report.

## Ztunnel source qualification

Base `75843515d549f7928d080801ac3f7e4344f572eb` plus dirty, frozen increments. The final full-2 run passes **533 library +20 direct +30 namespace +2 diagnostic tests**, zero failures/ignored, formatting and strict Clippy.

It covers original ZDS-UID source binding, source withdrawal/ABA transport cancellation, actual TLS handshake counters and success-duration histogram, pool reuse/recovery, and an active-session lifetime gauge. Read exact manifests and cumulative/increment patches in `/private/tmp/cmtc-claude-opus-20261025/COMPLETE_PATCHES/ztunnel/`. Primary reviewed core code but must independently recheck and qualify exact images/live scrape before activating planned metric contracts. No new ztunnel image or combined deployment is proven by these tests.

## SPIRE and registrar next work

Base SPIRE `28f6b8d84ade21c6accb32ba9689a3bdf64877ec`. The nine-file cache-expiry candidate is qualified across affected race tests and vet. One existing alias-record size assertion failed72→80 due to the added int64 expiry; it was corrected and the affected package rerun passed. Preserve the failed log.

Registrar code is committed locally at primary `5ce3db3`. The added mismatched-list-filter test failed before the fix and passed afterward. Images/live checks remain open.

A further read-only audit found two **additional unpatched grant boundaries**:

1. Dynamic server admin/downstream roles can use an expired registration for new RPCs until pruning.
2. A cached, expired local delegate grant can authorize new requests for a different current target during failed entry synchronization.

Read `review/PRIMARY_SPIRE_ISSUANCE_AUDIT.md`. It contains minimal production patches and complete negative/recovery tests. Primary has added and formatted the two proposed test files in isolated SPIRE; Both negative tests reproduced the authorization gaps in role-before(exit1). The two production checks are now applied and the full affected package race run is in progress as role-after:

- `pkg/server/api/middleware/authorization_expiry_test.go`
- `pkg/agent/api/delegatedidentity/v1/service_expiry_test.go`

The queued reproduction runner is `/private/tmp/cmtc-registration-expiry-20261025/run-role-expiry.py role-before`. Wait for the compiler lease. Reproduce the failures, apply reviewed fixes, run the affected package race tests and vet, then capture new source hashes/patches. Keep old nine-file evidence intact. Do not introduce a new agent-to-server dependency for a three-line expiry check. Existing certificates and in-flight request authorization remain separate from new role grants.

After these checks, build the exact SPIRE and registrar images with host Podman, then coordinate their local deployment and actual expiry/recovery checks with Claude's lab lease. Preserve signer state and approved public profiles. The registrar recipe is `build/Containerfile.spire-registrar`.

## Lab and build pins

Use only `cmtc-a` and `cmtc-b`, contexts `kind-cmtc-a` and `kind-cmtc-b`, kubeconfig `/private/tmp/cmtc-a-b-20261024.kubeconfig`. Never print its contents.

- A kube-system UID: `bb7182c7-de95-4e70-816a-a1400d755794`.
- B kube-system UID: `f2687af6-bd96-45a3-98a2-d1397a3ee244`.
- Colima profile `cmtc-cilium`: Ubuntu ARM64,8CPU/16GiB/90GiB. Preserve its provider and applications.
- Host Podman connection `cmtc-ubuntu-build`. Guest SSH loopback49691. Use explicit Linux ARM64 and bounded2CPU/4GiB builds.
- Go/clang builder: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`.
- Rust namespace builder: `def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f`.
- Shared Go cache `/private/tmp/cilium-ztunnel-linux-go-cache`; module cache `/private/tmp/cmtc-spire-go-modules`.
- Private rootful socket `/tmp/cmtc-observer-rootful/podman.sock`; preserve it while tests use it. Do not change global sysctls or prune shared storage.

KVStoreMesh is ON. Combined ztunnel/WireGuard/IPsec is OFF. Claude verified current API UIDs and image inventory. The only live changes in this interval were the qualified Grafana ConfigMap updates. Baseline applications remain available. Protected root keys stay outside clusters and evidence.

The public issuer-profile producer approval expires `2026-10-26T03:55:11Z`; leases are at most30seconds. Preserve its private ledger under `~/.local/share/cmtc-issuer-profile/live-a-b/`. Do not read or publish root private keys.

Grafana is at `http://127.0.0.1:13000`. Task-owned SSH capture forwards were exec23400, guest33000→Mac13000 and guest38080→Mac18081. Preserve unrelated forwards.

## First continuation actions

1. Check the active Claude transcript and Cilium stage exits.
2. Review actual code and test results; retain unresolved admission/security gates.
3. Obtain the compiler lease for the two new SPIRE role-expiry regressions and image work.
4. Finish exact-image local positive, rejection, restart and recovery qualification on both existing clusters.
5. Commit qualified increments under the user identity; push only after required local image/runtime checks. Continue the mandate.
