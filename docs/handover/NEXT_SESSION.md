# Current continuation checkpoint

Updated 2026-10-25. The full end-to-end workload-mTLS mandate is active. Questions, documentation and dashboard requests steer it; they do not pause it. Read [the master prompt](CODEX_MASTER_PROMPT.md), [delivery status](../agile/DELIVERY_STATUS.md), [recovery receipt](OPUS_RECOVERY.md) and the current security acceptance matrix.

## Current request

Complete native workload mTLS through the enhanced Cilium ClusterMesh path on both `cmtc-a` and `cmtc-b`. Test it immediately with real positive, plaintext-negative, policy-negative and recovery traffic. Fulfill the defined metrics through their actual component owners. The user permits Opus to improve instrumentation from first principles, with documented rationale and contract changes. The latest steering assigns ALL implementation code to Opus. Codex owns coordination, independent review, tests and evidence. Claude Fable5.1 High is requested for central complex design; its provider refused the probe and automatically substituted Opus4.8. That response is rejected as Fable work. The user explicitly forbids Opus4.8; no development was assigned to it.

All agents use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change**. Preserve existing labs, signers, applications and security gates. The latest AGENTS instruction defers CI and pushes that trigger CI, plus workflow dispatch and registry publication. Qualified local commits are allowed.

## Active external agents

Claude Code uses canonical `claude-opus-5-5`, effort `max`, normal automatic permission review, session `c03d57db-e2bf-4848-ab73-3f2696a27d2f`.

- Current runner: `/private/tmp/cmtc-claude-opus-20261025/run-live-max-owner.py`.
- Exec session: `79321`; read `live-max-owner-pid` and verify the actual process.
- Transcript: `live-max-owner-session.jsonl`; errors: `live-max-owner-stderr.log`; eventual completion: `live-max-owner-exit`.
- This runner uses documented streamed input. Append one complete user-message JSON record to `live-max-input-queue.jsonl` to deliver steering without interrupting tests. `live-max-input-offset` records sent bytes. Check the replay and Opus acknowledgment before claiming delivery. Never start a concurrent session writer.
- Latest message: `USER_OPUS_MAX.md`, followed by the max continuation in the input queue. Actual process arguments confirm `--model claude-opus-5-5 --effort max`; CLI/API metadata confirms Opus5.5 and Opus acknowledged max-effort sole implementation ownership. Use max for central changes across layers.
- The previous live-owner runner exited0 after an idle tool boundary: zero pending tool calls and zero active owned compiler containers. Preserve its transcript; no in-progress rollout was interrupted.
- `live-max-owner-model-block.json`, if present, records that the guard stopped a provider model substitution. Do not accept a fallback as requested-model work.
- Older `run-concurrency-registrar.py` completed exit0 after Go3/4 test containers ended. It is not active. Older logs remain diagnostics/evidence.
- Full registrar handoff: `review/REGISTRAR_METRICS_PRIMARY_TESTED.patch` and `REGISTRAR_METRICS_TEST_RESULT.json`. Opus reviewed and committed the seven source files at primary18c47cc, hash-matched to27 top-level/58 total Linux ARM64 race passes plus vet0. No registrar image or live scrape is qualified yet. Primary makes no implementation edits.

Cursor Grok's read-only remediation completed with exit0. Full report: `/private/tmp/cmtc-opus-final-20261025/review/GROK_REMEDIATION.md`. It contains complete production snippets, technical rationale and negative/recovery tests against Cilium `dbd2d32`. These proposals are not executed evidence. Opus is adapting the quarantine failure fix. Reuse the existing retained-node fix; do not reapply stale address-only binding code.

The Codex read-only native bootstrap proposal is `review/NATIVE_MESH_BOOTSTRAP_NEXT.md`, with four complete UNRUN Go files under `review/native-mesh-proposal/`. Opus has received them. The read-only registrar proposal is complete at `review/REGISTRAR_INSTRUMENTATION_PROPOSAL.md`. Primary applied/reviewed it before the ownership transfer and ran actual Linux race/vet. See [registrar metric evidence](../evidence/registrar-metrics/README.md). Opus now owns that source.

## Authorship in reports

The user requires explicit authorship attribution. Name our added features as **CMTC-authored additions or modifications in our ephico2real2 forks**. Identify unchanged upstream components and reused APIs separately. Keep the configured human Git author and existing upstream notices. Report Opus/Codex/Grok assistance separately. Include source and qualification status; authorship is not runtime protection evidence. See the delivery record's authorship table.

## Ownership

All four isolated trees are under `/private/tmp/cmtc-opus-final-20261025/`, branch `feat/opus-mesh-mtls-finalization`.

| Area | Current owner |
| --- | --- |
| Isolated Cilium/ztunnel implementation | Opus |
| Scoped SPIRE separate DelegatedIdentity listener and matching fixture | Opus |
| Compiler and live lab writes | Opus |
| All CMTC/registrar/DaemonSet/metric/dashboard implementation | Opus |
| Coordination, docs, independent review, tests and evidence | Codex primary |
| Grok | Read-only adversarial proposals; completed turn |

Read `review/OWNERSHIP.json`, `BUILD_SLOT.json` and `LAB_OWNER.json`. Their latest handoff fields supersede old ownership text. Coordinate one compiler and one live writer. Primary may inspect live state read-only. Do not overlap source edits.

The broader Agent/Server Admin DAC migration remains unapproved after automatic-review rejection. Keep existing Admin directory ownership, modes and mounts unchanged. The accepted scoped fix is a separate DelegatedIdentity-only listener. Add no DAC-bypass capability. The user asked about Admin access, then explicitly clarified that the question did not change the direction.

## Source and evidence

The four recovery commits preserve all earlier work:

- Cilium `a7ffbc8c85eeed89d7105704a643633c7d408118`.
- Ztunnel `35a6c9403eb5c00b1b79aafe2851f423cd195540`.
- SPIRE `ff52bdcd8d05f85f893221b604c3113cd47d57ed`.
- Isolated CMTC `7a133dc7449173b3e1a15dc6e3b32037ef2b1b91`.

Verified backup: `artifacts/recovery/opus-20261025T113157Z/`. Read [OPUS_RECOVERY](OPUS_RECOVERY.md) before recovery actions. Preserve source, failed logs and old branches.

Newer Cilium commits: `d040a4bc9a` adds native node-name binding and HBONE-only admission; `dbd2d32` fixes retained node-binding invalidation. The latter passes67 top-level/169 total race tests, zero failures/skips, plus vet. It is not deployed. Evidence is in [native-node-discovery](../evidence/native-node-discovery/README.md).

The full C2 profile passes120 top-level/345 total race cases, with21 pre-existing integration skips, plus vet, BPF build permutations, generated-config consistency and57 kernel leaf cases. Never count the skips as executed integration proof.

Ztunnel35a6 source qualification passes533 library+20 direct+30 namespace+2 diagnostic tests, zero failures/ignored, formatting and strict Clippy. It includes real TLS collectors and source-witness cancellation. No new proxy image is live.

SPIRE separate-listener run2 passes30 top-level/317 total race tests, zero failures/skips, Linux/Windows/Darwin vet and agent build. Logs: `/private/tmp/cmtc-claude-opus-20261025/logs/spire-delegated-2/`. This source is not yet deployed. Preserve run1's service-name assertion failure.

Root CMTC branch is `feat/end-to-end-enforcement`; last checkpoint HEAD `bf8abab` before the current local increment. Registrar source5ce3db3 passes16 top-level/28 subtests with race and vet; exact-image/live qualification remains open. Check actual HEAD and dirty files before edits.

## Runtime

Use kubeconfig `/private/tmp/cmtc-a-b-20261024.kubeconfig` with explicit `kind-cmtc-a` and `kind-cmtc-b`. Never print its contents.

- A kube-system UID: `bb7182c7-de95-4e70-816a-a1400d755794`.
- B kube-system UID: `f2687af6-bd96-45a3-98a2-d1397a3ee244`.
- Colima `cmtc-cilium`: Ubuntu ARM64,8CPU/16GiB/90GiB; preserve provider/apps.
- A now runs C3 development overlay `localhost/cilium:dev-overlay-a74f13a688` on both nodes; the canary logs verify both running agent revisions and the actual imported configuration prefixfc4a5a342b4f. The post-canary36-path baseline passes. Live loaded-program inspection remains incomplete after a parser error; no program conclusion follows from that failed probe.
- B runs the earlier d040 development overlay on both nodes, as later Opus version verification corrected. C3 is not yet qualified there. The original A canary attempt1 was a caught no-op; preserve its diagnostics. Agent overlays do not rebuild the operator/ClusterMesh server/chart.
- KVStoreMesh is ON. Ztunnel proxies, WireGuard and IPsec remain OFF. No workload-mTLS or Protected claim.
- Post-canary36-path traffic and exact loaded-BPF checks remain open unless newer logs prove completion.

Public issuer-profile approval expires `2026-10-26T03:55:11Z`; leases are at most30s. Preserve the private ledger under `~/.local/share/cmtc-issuer-profile/live-a-b/`. Never read or publish protected root keys.

## Metrics and dashboards

Primary contracts: `observability/metrics.json` and `capabilities.json`. Older isolated dashboard drafts are not authoritative. Both consolidated dashboards retain all nine original domains.

The live query at12:38:49Z returns205 CMTC names/1658series and six up CMTC targets. The full inventory groups181families. There are no ztunnel targets or native TLS series. The new contract maps native source-tested TLS families and selects destination once for handshakes, durations and active sessions. Identity failures count local verifier events. Live status stays planned. Twenty dashboard tests, reproducibility, static validation and real query validation pass. Evidence: [metrics instrumentation](../evidence/metrics-instrumentation/README.md). Source-tested is separate from deployed/collected/protected.

Grafana: http://127.0.0.1:13000. Preserve existing application/Prometheus forwards and task-owned SSH capture forwards (old exec23400 guest33000→Mac13000,38080→Mac18081).

## Build pins

Use host Podman connection `cmtc-ubuntu-build`, explicit Linux ARM64 and bounded2CPU/4GiB.

- Go/clang: `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`.
- Rust namespace image: `def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f`.
- Go cache `/private/tmp/cilium-ztunnel-linux-go-cache`; modules `/private/tmp/cmtc-spire-go-modules`.
- Private rootful socket `/tmp/cmtc-observer-rootful/podman.sock`; preserve active tests. No global prune/sysctl changes.

## First unfinished dependency

Review Opus's current source and actual test results. Finish zero-address and quarantine-write failures, native authority/remote Address/policy/release integration and the separate delegated listener. Recheck initial capture, restart, old programs and original-tuple authorization. Bounded regeneration cannot prove immediate denial if every kernel write fails. Keep that gap explicit.

Use both clusters, enable ztunnel when those gates are real, and immediately test local+A→B+B→A, Global Service/direct Pod IP and80/8080/31337. Include bad identity, unauthorized policy, plaintext, stale/disconnected control state and recovery. Record peer identity, effective policy, packets, exact image/version and real metrics. Finish with host Podman packaging and exact-image rechecks. Update this checkpoint from actual receipts and continue the mandate.
