# CMTC engineering handover

Checkpoint: **2026-10-25, approximately 16:40 UTC / 11:40 America/Chicago**.
Read [resume.md](resume.md) for the next actions. This document supersedes older
statements that ztunnel is disabled. The end-to-end security work is unfinished.

## Result at handover

Both clusters have the rebuilt Cilium agent, operator, ClusterMesh API server,
SPIRE node agents, CMTC controller/node agents and node ztunnel deployed.
All four Cilium agents and all four proxies were Ready after the PID namespace
fix. This is startup evidence, not successful workload-mTLS evidence.

| Check | Actual result |
| --- | --- |
| Baseline app matrix from A | 36/36 passed before test namespace enrollment |
| Baseline app matrix from B | 36/36 passed before test namespace enrollment |
| Test application placement | Server and client on each actual node in both clusters |
| Exact SPIRE test registration | Four Pod-bound entries per cluster, with readback |
| Namespace enrollment | `cmtc-live-mtls` enrolled in both clusters |
| First enrolled A request | Failed: curl56, connection reset, no HTTP200 |
| First enrolled B request | Failed: curl56, connection reset, no HTTP200 |
| B proxy traffic log | Identified source/destination and HBONE destination15008; connection drained during xDS resync |
| ClusterMesh agent status | 0/1 remote clusters Ready in both clusters |
| Remote resource inventory | etcd connected; nodes/endpoints/identities/services synchronized |
| Full cross-cluster workload mTLS | **Unproven** |
| WireGuard/IPsec composition | Disabled/unqualified |

The baseline matrices include local, cross-node, cross-cluster Pod IP and Global
Service paths on80/8080/31337. They ran before enrollment. Do not call these
72 successful requests encrypted tests. Each enrolled run stopped at its first
failed request; the remaining ports and remote encrypted paths have not passed.

## Repositories and source

| Repository | Active checkout | Source |
| --- | --- | --- |
| CMTC | `/Users/olasumbo/gitRepos/clustermest-trust-controller` | Branch `feat/end-to-end-enforcement`; this handover commit follows96cbc9e |
| Cilium | `/private/tmp/cmtc-opus-final-20261025/cilium` | `51170b123988cda86aaea1bef3ccd95d221b8bbb` |
| ztunnel | `/private/tmp/cmtc-opus-final-20261025/ztunnel` | `35a6c9403eb5c00b1b79aafe2851f423cd195540` |
| SPIRE | `/private/tmp/cmtc-opus-final-20261025/spire` | `0f8fe4d6812c388be9ffd7b6d160e67b59163d95` |
| Isolated CMTC recovery | `/private/tmp/cmtc-opus-final-20261025/cmtc` | `7a133dc7449173b3e1a15dc6e3b32037ef2b1b91`; older recovery, not current root |

All three fork feature branches are `feat/opus-mesh-mtls-finalization`.
They were clean when the temporary Opus session stopped. The isolated CMTC
recovery branch has the same name and was also clean. Verify this again.

The user authorized committing all work and merging personal defaults.
Cilium main51170b1239, SPIRE main0f8fe4d681, ztunnel master35a6c94 and CMTC
main96cbc9e were pushed by fast-forward. **All working branches and worktrees
were retained.** No canonical upstream repository was merged or force-pushed.
This handover commit need not already be on those default branches: inspect Git.
Registry publication and manual workflow dispatch remain separate and deferred.

## Owned environment

| Item | Value |
| --- | --- |
| Colima profile | `cmtc-cilium`, Ubuntu ARM64,8CPU/16GiB/90GiB |
| Build engine | MacBook host Podman, connection `cmtc-ubuntu-build` |
| kind runtime | Docker inside the existing Colima profile |
| Host Docker context | `colima-cmtc-cilium` |
| kind Docker socket | `unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock` |
| Kubeconfig | `/private/tmp/cmtc-a-b-20261024.kubeconfig`; do not print or commit it |
| Context A | `kind-cmtc-a` |
| Context B | `kind-cmtc-b` |
| A kube-system UID | `bb7182c7-de95-4e70-816a-a1400d755794` |
| B kube-system UID | `f2687af6-bd96-45a3-98a2-d1397a3ee244` |
| Grafana | `http://127.0.0.1:13000` |

Discover node names with `kubectl get nodes`. At this checkpoint each cluster
has `<cluster>-control-plane` and `<cluster>-worker`. Do not assume their IPs
survive runtime changes. Host tools are `/opt/homebrew/bin/kind` and
`/opt/homebrew/bin/kubectl`. Neither command was on the Colima guest's PATH in
the last check. Preserve the existing runtime, applications and signer state.

## Exact images built and deployed

The images target Linux ARM64. Configuration IDs are distinct from registry or
containerd manifest digests. Runtime receipts record actual Pod image IDs.

| Component | Image | Configuration ID |
| --- | --- | --- |
| Cilium agent | `localhost/cilium:dev-overlay-51170b1239` | `116405eeb61ad76ef1c2e852bf6a69ec0481849e1c02a800b0fce468a2384528` |
| ClusterMesh API server | `localhost/cilium-clustermesh-apiserver:dev-overlay-51170b1239` | `d32cc142a56a3ceee95da971821e93365dadda56b1e1183c8054048207ef1163` |
| Cilium operator | `localhost/cilium-operator:dev-overlay-51170b1239` | `15957d6ca19dc01bdfb4524a708e8794f685d3f8107690b29fd39857c9b9e2c0` |
| SPIRE agent | `localhost/cmtc-spire-agent:delegated-0f8fe4d681` | `2c98504d870dffe6a229bd4b057460297ee1a181207bcf34faeac992bb03ceb9` |
| Ztunnel | `localhost/cmtc-ztunnel:native-35a6c9403e` | `ae3844096b580049c05d8be6520491eb339a1b583a6d1143b3b50ca992c17df9` |
| CMTC controller/node agent | `localhost/cmtc:current-96cbc9eeca` | `c3c58b15143e347584dd2fbe0f20cb4224899dcb86be2c61e59162da21c281af` |
| Registrar, built only | `localhost/cmtc-spire-registrar:current-96cbc9eeca` | `dfdfda16f19d5301a0a90d840748f4c7076533b31a752eaf3fad9a21a8dad0d7` |

The proxy Pod spec uses the imported canonical OCI digest:

```text
localhost/cmtc-ztunnel@sha256:331dacf7becea658f9a8e1cf24d8edc5c4207cf43a00271792355903feb7a9b0
```

Cilium images are development overlays, not complete upstream release builds.
The existing SPIRE server/signers are preserved. The new registrar image has
not been installed as a persistent server sidecar. Manual exact registrations
currently support the fixture; they are not a finished lifecycle controller.

## Build and deployment procedure used

Retained operational files are under
`/private/tmp/cmtc-primary-operations-20261025`. Reviewed copies are committed in
[the activation evidence](docs/evidence/local-activation-20261025/README.md).
They record an already executed rollout. **Do not rerun them as one installation
script.** Several intentionally reject existing snapshots or old-image changes.

1. Freeze the source SHA and complete dirty-state record.
2. Build with host Podman on `cmtc-ubuntu-build`.
3. Set Linux ARM64 and bounded build resources explicitly.
4. Verify source version, image configuration ID and binary hash.
5. Export an archive into shared `/private/tmp`.
6. Load the archive into both existing kind clusters.
7. Verify the loaded content on all four nodes.
8. Patch only the owned resources with UID/resourceVersion preconditions.
9. Replace each agent one node at a time.
10. Verify the replacement Pod's image, PID namespace, readiness and logs.
11. Run real application checks.

The agent, API-server, SPIRE-agent and ztunnel build recipes are copied from the
previous owner with the operational lease guard updated. CMTC uses an exact
`git archive` source snapshot because the root Mac checkout was not visible in
the remote build VM. The first missing-go.mod failure is retained locally.
The compatible operator was rebuilt because the previous binary lacked
`--ztunnel-spire-external-exact-registrar`.

Docker-archive imports produced different synthetic manifest references on
different nodes despite matching configuration IDs. The proxy was re-exported
as an OCI archive and imported with a verified canonical manifest. Each node
received the same digest alias. Do not substitute an arbitrary import digest.

Read [local image build](LOCAL_IMAGE_BUILD.md) for general commands and
[Podman qualification](docs/development/PODMAN_LOCAL_VALIDATION.md) for controls.
The build recipes, public receipts and archive checks remain distinct from
traffic acceptance.

## Runtime configuration and requirements

### Strict ZDS process identity

The user explicitly approved `hostPID: true` on Cilium in both clusters.
Both node agents and node proxies now use the host PID namespace. This resolved
the rejection `strict ZDS drain requires a root-owned local proxy process`.
The root-owned peer check remains unchanged.

See [installation requirements](INSTALLATION_REQUIREMENTS.md) and the committed
manifest merge patch. Cilium chart51170b1239 has no agent hostPID value;
`--set hostPID=true` silently does nothing. A persistent fork-chart fix remains
open. Reapply and verify the explicit patch after a chart upgrade.

### Trust, transport and checkpoints

- Use the restricted SPIRE DelegatedIdentity-only listener. Existing Admin DAC
  migration remains false. Proxies do not receive SPIRE's original Admin socket.
- Agent flags enable ztunnel, SPIRE, required mTLS, effective-policy quarantine,
  remote membership and the external exact registrar.
- The operator uses the matching explicit external-exact-registrar flags. Its
  legacy broad registration path is disabled.
- Membership writers use dedicated etcd TLS credentials and configuration.
  The general Cilium KVStore remains disabled under CRD identity allocation.
  KVStoreMesh is enabled; those are different settings.
- Peer origin readers have cluster ID and public SPKI pins. Source configuration
  and credentials are mounted read-only. Do not replace them with Admin credentials.
- ADS/membership transport uses `kube-system/cmtc-public-root`. Workload issuer
  profiles use the separate organizational root. Do not mix those CA bundles.
- Node pins are `/etc/cmtc/ztunnel-issuer-pins/pins.json`.
- Durable proxy state is `/var/lib/cmtc/ztunnel-issuer-checkpoint`.
- Initial `ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP=true` was used only on virgin
  state. All four proxies logged durable profile commits. Both OnDelete
  templates now set bootstrap false for their next replacement. Existing
  proxies were not restarted for that template change.
- Never delete checkpoints, replay floors or bootstrap markers to force readiness.
- Issuer approval/SPIRE CA expiry is approximately `2026-10-26T03:55:11Z`.
  Output leases are at most30seconds. Check actual validity before resuming.
  Preserve `~/.local/share/cmtc-issuer-profile/live-a-b/` and signer state.

## Current test fixture and reproducible commands

The test runner is preserved at
`docs/evidence/local-activation-20261025/operations/live_mtls_fixture_proposal.py`.
Its initial proposal name is historical: create/register/enroll/probe/evidence
stages have now executed. It is an operational harness, not a qualified product
controller. Do not count a failed exec as a network denial.

| Item | Current value |
| --- | --- |
| Operational runner | `/private/tmp/cmtc-primary-operations-20261025/live_mtls_fixture_proposal.py` |
| Existing run ledger | `/private/tmp/cmtc-primary-operations-20261025/live-mtls-test` |
| Enrolled namespace | `cmtc-live-mtls` in both clusters |
| Unenrolled namespace | `cmtc-live-mtls-unauth` in both clusters |
| Owner label | `security.cmtc.io/test-owner=cmtc-primary-live-mtls-20261025` |
| A enrolled namespace UID | `35956b6e-e8d0-4ade-a4f2-82039c1ab34d` |
| B enrolled namespace UID | `7a3d942e-3e49-4ae3-8779-73de32ec91af` |
| Apps per cluster | Two nginx servers, two curl clients, two separate unenrolled clients |
| SPIFFE identities | `spiffe://<cluster>.mesh.example/ns/cmtc-live-mtls/sa/{mesh-client,rebel-base}` |

Continue against the existing ledger. Do not rerun create/register/enroll as
bootstrap; they intentionally reject duplicate or stale state. A probe example:

```bash
python3 /private/tmp/cmtc-primary-operations-20261025/live_mtls_fixture_proposal.py \
  probe --cluster cmtc-b \
  --out /private/tmp/cmtc-primary-operations-20261025/live-mtls-test \
  --scope first --expect allow --execute
```

Scopes include `same`, `crossnode`, `crosscluster`, `remote-global` and
`negative`. Fix the first positive path before treating later negative timeouts
as policy evidence. Removing the enrollment label does not clear the Required
datapath state. Preserve the fixture and its exact registrations during handoff.

## Open failures and source work

1. **Strict xDS resync loop.** Proxy logs reject Address updates with
   `strict xDS update requires full snapshot resync`. A rejects its request with
   `current xDS authorization snapshot unavailable`. B opens the HBONE path,
   then records `connection closed due to connection drain`. Capture and fix the
   native publisher/consumer lifecycle; do not disable freshness or policy checks.
2. **Membership lifecycle.** Logs include writer lock timeouts and
   `creating exact required membership: draining Pod membership cannot be reused`.
   Determine which are transient and which persist after correct recovery.
3. **Native ZDS ownership.** Existing system and application endpoint regeneration
   reports `native ADD ownership unavailable: native ZDS ownership is busy`.
   Ready Pods do not establish successful endpoint regeneration.
4. **Remote readiness.** All agents reported0/1 remote clusters Ready even with
   connected etcd and synchronized inventory. Trace the actual readiness gate.
5. **Persistent installation.** Add the hostPID requirement to the actual fork
   chart and assert strict/ordinary render behavior.
6. **R7 source-egress.** Current effective ALLOW delivery covers captured
   same-node sources. Realized cross-node/cross-cluster source-egress remains
   incomplete. A permissive replacement policy is not a fix.
7. **Other release gates.** ADS client authentication, per-node membership
   provenance, permanent kernel-map-write failure, capture/restore, old programs,
   endpoint/IP reuse, platform exceptions, trust rotation and layered encryption
   remain open. Keep the [security matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md).

Tests from earlier increments remain recorded in delivery status. The latest
operator build ran66 passing targeted race test events plus vet/build exit0.
The broader API-server script data race reproduced on clean upstream in2/2
runs; it remains open. No skipped or zero-selected test qualifies a gate.

## Observability

Latest committed Operations and Workload Security JSON was re-provisioned.
`observability/build.py --check` passed. Prometheus now also has the native
Cilium scrape job on9962 in both clusters. Existing ztunnel15020 and CMTC jobs
remain, with B remote-write to A. Prometheus configuration reloaded without a
TSDB restart. The new Opus layout redesign is not complete.

Public metrics and config dumps from the failed traffic runs are preserved.
Do not create successful-mTLS screenshots from these failures. Generate real
positive and negative load after repairing the path, verify PromQL, then capture
both Grafana themes. Follow the diagram-kit dashboard skill. Documentation
diagrams use light-theme images.

Read-only heartbeat `cmtc-logs-and-network-monitor` remains active every five
minutes. It does not deploy, compile or change resources. It should stay quiet
unless a meaningful failure or recovery occurs.

## Writer and process handoff

The original Claude Max session is
`c03d57db-e2bf-4848-ab73-3f2696a27d2f`, model `claude-opus-5-5`.
Its initial runner hit a quota limit. The resumed source-only run used fresh
`opus-resume-1635-run2.*` logs under the operational directory. Actual assistant
metadata confirmed Opus5.5. Codex stopped that task-owned source process for
this handoff; exit143, no fallback. No implementation diff was left in the four
isolated source worktrees at the checked boundary.

Do not restart the old `run-live-max-owner.py`: it truncates old logs and
replays its input queue from offset0. The first attempted new resume failed
because its prompt was consumed by a variadic directory flag. The corrected
run used `--` before the positional prompt. Preserve both attempts.

Ownership files are in `/private/tmp/cmtc-opus-final-20261025/review/`:
`OWNERSHIP.json`, `BUILD_SLOT.json`, `LAB_OWNER.json`. Before any mutation,
verify processes and set one compiler/live writer explicitly. Read-only
monitoring is separate. The [handoff release receipt](docs/evidence/local-activation-20261025/raw/handoff-release.json) records the final lease
state: both compiler and live writer are unassigned. Do not start a second reconciler, compiler or source owner.

Use Grok for adversarial proposals against an exact commit. Require rationale,
complete patches and deterministic negative/recovery tests. Opus adapts and
implements accepted source fixes; Codex independently checks evidence. The
latest XHigh review is incomplete; its partial output is not acceptance.

Preserve the user's author identity, personal fork origins, canonical upstream
remotes, working branches, unrelated applications and protected root keys.
Develop against the owned clusters before packaging the verified change.
