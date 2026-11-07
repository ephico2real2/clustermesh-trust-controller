# CMTC engineering handover

## Update 2026-10-27 17:05 UTC (Claude Code session b744973a)

- cert-manager auto-approves (approver-policy and `charts/cmtc-mesh-pki` removed, `10c9c0a`). AGENTS.md has a
  Simplicity rule: no unrequested components, gates or policy layers.
- cmtc-b Cilium adopted into Helm (`0130371`); Hubble on both clusters, Relay and UI in cmtc-a, 4/4 nodes
  ([evidence](docs/evidence/hubble-20261027/README.md)); both releases at revision 8, 0 drift; matrix 96/96, 36/36.
- Lab Prometheus now restarts when its configuration changes; the `hubble`, `hubble-relay` and `ztunnel` jobs are up.
- Open: the arbiter (`feat/approval-follows-cert-manager`) must take the SPIRE CA bound from SPIRE's `ca_ttl`, not the
  removed `<cluster>-spire-ca` policy (brief amendment 16:45Z); OB3 is reviewing it.

## Update 2026-10-27 13:50 UTC (Claude Code session b744973a)

Supersedes every update below where they differ. Exact image and source pins are in
[delivery status](docs/agile/DELIVERY_STATUS.md#deployed-images); they are not repeated here.

**Leases.** Compiler and live writer: Claude Code session b744973a (PID 52816),
`/private/tmp/cmtc-opus-final-20261025/review/{BUILD_SLOT,LAB_OWNER}.json`. A new session claims them only
after it verifies that this one has ended. No agent or background task is running (both stopped at 13:43Z).

**Traffic (traffic-qualified, 2026-10-27 11:12–11:14Z).** Workload mTLS works through ztunnel on both clusters:
same node, cross node, cross cluster, by Pod IP, per-Pod name and Global Service name. 95 of 96 allowed probes are
joined by client socket to a ztunnel mTLS connection with both SPIFFE identities; the 96th returned HTTP 200 from the
expected Pod and is joined by destination and time, because NAT gave its socket a new source port. 36 of 36
unregistered probes are dropped by Cilium at `bpf_lxc.c:2381`
([matrix-g6](docs/evidence/spire-intermediate-20261027/matrix-g6/README.md)). The cross-node and cross-cluster
authorization blocker of 2026-10-25 is closed (matrix 7, 2026-10-26). Not re-measured on the current images: DNS,
restart and reboot recovery. This is not a `Protected` claim.

**PKI (issue #34, deployed and traffic-qualified).**
- SPIRE on each cluster signs with a CA from `cert-manager/<cluster>-spire-intermediate`, under the mesh root, since
  10:52Z (cmtc-b) and 10:54Z (cmtc-a). It was moved on demand with
  [`scripts/lab/spire/local_authority.py rotate`](scripts/lab/spire/local_authority.py); SPIRE rotates on its own
  from there.
- cert-manager approves every request with its built-in approver (operator decision, 2026-10-27T16:25Z: trusted,
  access-gated clusters, no extra approval layer). approver-policy and `charts/cmtc-mesh-pki` were removed
  ([MESH_PKI.md](MESH_PKI.md), Approval).
- Issuer approval generation 6 (`cmtc-system/cmtc-issuer-approval-g6`) pins each cluster's intermediate and the mesh
  root. It expires **2026-11-25T10:26:41Z**. No renewal is automated. At expiry ztunnel refuses every workload
  handshake (fail closed). The operator removed the host-side renewal job at 12:21Z ("this is lab"): no stopgap for
  lab uptime.
- The intermediates (revision 1) renew on 2027-09-26 with `rotationPolicy: Always`, so with a new key. Generation 6
  pins the current key. Without an approval that carries both intermediates during the overlap, that renewal stops
  all workload mTLS within about one SPIRE CA lifetime (24 h).
- Record: [LOCAL_ISSUER_PROFILE.md, SPIRE intermediate mode](LOCAL_ISSUER_PROFILE.md#spire-intermediate-mode-issue-34).

**In progress: the CMTC controller as the arbiter of trust changes (operator decisions, 2026-10-27 12:34–12:38Z).**
- The CMTC controller owns the issuer approval lifecycle across the clusters: derive it from cert-manager's public
  objects, publish it, overlap old and new intermediates on renewal, retire the old one, renew before expiry. It does
  this in its reconcile or through a Job it owns. No host script, no CronJob that nobody owns.
- It is the single leader-elected arbiter. It orders each change with an explicit state machine and advances only on
  observed evidence. It must settle the six ordering races seen on these labs (listed in the brief).
- The CMTC node agent DaemonSet does the per-node steps (first, the root pins file that the Cilium agent and ztunnel
  read at startup) and reports per-node evidence to the controller through a Kubernetes object that only that node
  may write. A missing or stale report blocks a change.
- Brief, with every operator amendment: `/private/tmp/cmtc-opus-final-20261025/review/approval-reconciler/BRIEF.md`.
- Work-in-progress code: branch `feat/approval-follows-cert-manager` (local, not pushed), worktree
  `.claude/worktrees/agent-afc1333b13bfec87b`, commits `cda9c0d`, `bf18839` (ADR-012 draft), `177d1d8`. It adds the
  `IssuerApproval` and `NodeTrustReport` types, the approval planner (`internal/trustprofile/plan.go`), the controller
  pass (`internal/controller/issuer_approval.go`) and the node report (`internal/agent/trust_report.go`). It builds,
  and `go test` of trustprofile, controller and agent passes. It is **not reviewed**. Missing: the chart and RBAC,
  enforcement that a node writes only its own report, the cross-cluster path in running code (to be verified against
  ADR-012), and any fork change.

**Open items, in order.**
1. Review and finish the arbiter branch (independent review, then the missing parts), then qualify it on cmtc-b,
   then cmtc-a, under traffic. Due before 2026-11-25T10:26:41Z, or the lab fails closed.
2. Port the working configuration to Helm (#33): the Cilium agent's issuer-profile Role
   (`cmtc-system/cilium-ztunnel-issuer-profile`, lab-managed), the node pins file (written by a host script), and
   the controller's issuer flags (set by `publish_issuers.py`).
3. Re-measure DNS and recovery (agent, ztunnel, node restart) on the current images.
4. Earlier open gates: [delivery status, Open gates](docs/agile/DELIVERY_STATUS.md#open-gates).

**Repository.** `feat/end-to-end-enforcement` at `8d79b55`: `8ba1d97` and earlier are pushed; `8d79b55`
(observability v2, #37, not deployed) is local. The kubeconfig `/private/tmp/cmtc-a-b-20261024.kubeconfig` does not
survive a host restart.

## Update 2026-10-25 21:30 UTC (Claude Code session b744973a)

Supersedes the 17:50 update below where they differ.

**Running in both clusters** (all four nodes, verified by image ID):
Cilium agent `dev-overlay-bc2c9639c5` without `hostPID`; ztunnel
`localhost/cmtc-ztunnel@sha256:b27235a4b7ec…` (`a3afcb7`, config
`83bca098a88c…`); CMTC controller and node agent `current-46d01e91ce`;
operator and ClusterMesh API server `dev-overlay-0ed63bf906`.

**Fixed since 17:50 and deployed:**

| Fork | Commit | Change |
| --- | --- | --- |
| Cilium | `58f511dc4f`, `0732ac1bb7` | The membership registry alone owns the current ADS stream, and a stream's generation ends when it closes |
| Cilium | `091676e790` | One admission at a time per Pod UID |
| Cilium | `0ed63bf906` | ZDS peer authorized by UID 0 only; the agent no longer needs `hostPID` |
| Cilium | `bc2c9639c5` | A refused (NACKed) bound ADD is not uncertainty |
| ztunnel | `a3afcb7` | A snapshot omission completes the bound owner it drains |
| CMTC | `46d01e9` | Issuer-profile publication outlives a leader handover |
| CMTC | `6c31b8d` | Colima guest clock has a single owner |

The J2 stranding (workloads quarantined forever after an agent restart) is
cleared on the live cluster. Record:
[zds-ownership-rollout-20261025](docs/evidence/zds-ownership-rollout-20261025/README.md).

**Mission blocker (open, next work).** Same-node mTLS works (18/18 per
cluster); unregistered clients are refused. Cross-node, cross-cluster and
Global Service requests are denied by authorization after a verified HBONE
handshake: `effectivePolicyOwner.reconcile()` compiles each destination's plan
from local sources only. Remote source-egress delivery must be designed and
built.

**Other open items.** The source membership lock is freed by 25 s lease
expiry, not released (agent grace period 1 s). The OB3 review of
`bc2c9639c5`/`a3afcb7` was still running at rollout.

## Update 2026-10-25 17:50 UTC (Claude Code session b744973a)

This section supersedes the open-failure list below where they differ. The
16:40 record that follows is kept unchanged as history.

**Leases.** Compiler and live writer are held by Claude Code session
b744973a (PID 52816), claimed 17:20:30Z in
`/private/tmp/cmtc-opus-final-20261025/review/{BUILD_SLOT,LAB_OWNER}.json`.
The released handoff state is kept beside them as `*.handoff-released-*`.

**Root cause of the enrolled-request failures (demonstrated).** The two
halves of the native xDS protocol contradicted each other. The ztunnel strict
client accepted one initial snapshot per type, then tore the session down on
any later Address/Authorization delta (`src/xds/client.rs`, from `8106c02`).
The Cilium control plane publishes the compiled effective ALLOW and refreshed
Address evidence as deltas on the same stream, and releases quarantine only
from ACKs on that stream (`pkg/ztunnel/xds/effective_policy.go`). Each forced
reconnect began a new ADS generation and discarded those ACKs. Release was
unreachable; every endpoint change drained every connection.

**Fixed and deployed.**

| Fork | Commit | Change | Verification |
| --- | --- | --- | --- |
| ztunnel | `a75d885` | Strict sessions apply later Address/Authorization deltas in-session; NACK still revokes; reconnect backoff restarts after a complete snapshot | Linux ARM64 privileged: new tests pass; full lib 534/534 in one of three runs, 1-2 rotating failures in untouched timing tests that pass alone; fmt, clippy `-D warnings` clean |
| ztunnel image | `localhost/cmtc-ztunnel:native-a75d885ac9` | Config `sha256:7b8e2066e129…`, OCI manifest `sha256:fbe72eea…`, binary `051f2fb4…` | Same digest on all four nodes; all four proxies replaced one node at a time with exact delegate SPIRE entries; zero warn/error lines after start; ledger `review/ztunnel-rollout-a75d885.jsonl` |
| Cilium | `ef2c78cdc4` (source only, not deployed) | Policy-ownership observation takes the shared lock; concurrent regenerations no longer fail each other with "native ZDS ownership is busy" | `./pkg/ztunnel/zds` 141/141 race pass, 0 skip, vet clean |

After the ztunnel deployment the proxy accepted post-initial Address and
Authorization deltas (verified in its config dump). The first cmtc-a same-node
probe changed from curl 7 to an HBONE connection with verified identities on
both ends, then `No route to host`: the destination is still in Cilium
datapath quarantine. No CMTC eBPF prototype is deployed or loaded.

**Cilium lifecycle defects now being fixed (demonstrated with file:line).**

1. `pkg/ztunnel/membership/source_publisher.go:32,407-418`: the 5 s source
   membership refresh re-runs full CNI admission for every captured endpoint.
   That re-quarantines the endpoint and sends a new ZDS ADD every 5 s, so the
   release candidate never stays current.
2. `pkg/endpoint/ztunnel_policy_transition.go:105-150` with
   `pkg/ztunnel/admission/policy_transition.go:29-126`: any desired-policy or
   revision change on a captured Required endpoint starts a terminal drain;
   the incarnation can never be admitted again. A failed ownership observation
   also fences it terminally.
3. `pkg/ztunnel/zds`: after a ztunnel restart, retiring a deleted endpoint
   fails with "drain request does not belong to this proxy execution", keeps
   capture/uncertainty, and closes the ZDS connection.
4. `pkg/ztunnel/reconciler/reconciler.go:154-184`: one failing endpoint makes
   the namespace reconcile retry re-admit every endpoint in the namespace.

The cmtc-a fixture Pods were replaced (new UIDs, new exact SPIRE entries,
superseded entries deleted by exact ID, ledgers archived as
`cmtc-a-entries.superseded-*.json`) with
`review/live_mtls_fixture_runner.py replace`. cmtc-b still has the old,
terminally closed incarnations.

hostPID remains the explicitly approved interim requirement. Replacing it with
`SO_PEERPIDFD` peer verification (kernel 6.8 here supports it) is a tracked
follow-up that needs restart/drain qualification.

Checkpoint (history): **2026-10-25, approximately 16:40 UTC / 11:40 America/Chicago**.
Read [resume.md](resume.md) for the next actions. This document supersedes older
statements that ztunnel is disabled. The end-to-end security work is unfinished.

## Ultimate goal and acceptance

Deliver **working, fail-closed workload mTLS across Cilium ClusterMesh** using
our enhanced forks. Complete the existing agile stories and security gates.
The target is a maintained implementation with repeatable tests and evidence.
Starting the components is an intermediate step.

Applications keep ordinary TCP/HTTP interfaces. They have no per-Pod proxy
sidecars. Cilium captures traffic and supplies native workload discovery and
effective authorization through xDS. Node ztunnel performs workload TLS.
SPIRE attests workloads and issues cluster-bound identities. CMTC coordinates
trust intent, issuer approval and lifecycle observations. The experimental
registrar manages exact live workload registrations.

The required result includes these behaviors:

- Same-node, cross-node and cross-cluster workloads communicate with verified
  identities and effective authorization. Test A→B and B→A through Global
  Services and direct Pod IPs. Test80/8080/31337 without treating that sample as
  proof for every possible port.
- Required traffic cannot bypass capture or fall back to plaintext. Missing,
  unauthorized, stale or revoked identity/policy blocks admission. Active
  connections drain when their authority is withdrawn.
- Cluster-specific trust domains and approved certificate chains bind identity
  to the correct cluster. A matching SPIFFE string alone is insufficient.
- Replacement, namespace exclusion, certificate rotation, xDS disconnect/NACK,
  process restart and recovery preserve the security boundary.
- WireGuard or IPsec supplies the separately selected node transport layer.
  Workload TLS and transport encryption require separate evidence and a tested
  combined path. Ztunnel does not replace that transport requirement.
- The CMTC Go/eBPF DaemonSet is the permanent, observe-only per-node
  measurement plane (operator mandate 2026-10-25,
  [ADR-005](docs/architecture/adr/ADR-005.md)). It measures and never decides.
  Enforcement and the quarantine gate are native in the Cilium fork. The CMTC
  fence remains a lab qualification tool for deny-path tests.
- Real collectors fulfill the planned metric contracts. Operations and Workload
  Security dashboards show meaningful measured data. Preserve the nine original
  dashboard domains. Generate load before query checks and screenshots.

Acceptance requires the exact deployed fork images, verified peer identities,
effective allow/deny decisions, packet evidence, and deterministic failure and
recovery results. Preserve platform/API/DNS traffic and excluded workloads.
Never report `Protected` from a label, Pod readiness, certificate or ACK.
The public Observe-only API does not become Strict merely because this
experimental native path is enabled.

Use the [backlog](docs/agile/BACKLOG.md),
[target design](docs/architecture/END_TO_END_DESIGN.md) and
[security matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md).
The current resync failure is the first repair, not the ultimate objective.

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

These are our active personal repositories. Reuse their existing enhancements;
do not substitute stock upstream images or start again from an old release.

| Personal repository | Canonical upstream | Current working branch |
| --- | --- | --- |
| [CMTC](https://github.com/ephico2real2/clustermesh-trust-controller) | Our project | `feat/end-to-end-enforcement` |
| [Cilium fork](https://github.com/ephico2real2/cilium) | `cilium/cilium`, default `main` | `feat/opus-mesh-mtls-finalization` |
| [ztunnel fork](https://github.com/ephico2real2/ztunnel) | **`cilium/ztunnel`**, default `master` | `feat/opus-mesh-mtls-finalization` |
| [SPIRE fork](https://github.com/ephico2real2/spire) | `spiffe/spire`, default `main` | `feat/opus-mesh-mtls-finalization` |

`origin` uses the configured `ephico2real2` SSH identity. The verified fork URLs
are `git@github.com:ephico2real2/{cilium,ztunnel,spire}.git`. CMTC's remote is
`git@github.com:ephico2real2/clustermesh-trust-controller.git`. The local root
directory is spelled **`clustermest-trust-controller`**; the remote is spelled
**`clustermesh-trust-controller`**. Keep this distinction when locating files.

Use the existing SSH configuration and human Git author. Do not copy private
keys, replace credentials or point `origin` at a canonical upstream repository.
Inspect each checkout with `git remote -v`, `git branch --show-current`,
`git rev-parse HEAD` and `git status --short`. Verify current upstream ancestry
before any later authorized publication. Preserve old branches during a rebase
or port. No separate Hubble fork is needed for files owned by the Cilium chart.

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
The latest user-provided AGENTS instructions also defer new CI-triggering pushes.
The default-branch pushes above are completed history, not permission to bypass
the current local qualification boundary.

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

## Reach and test the cluster APIs from the MacBook

Use the host shell. Existing credentials in the owned kubeconfig already
provide API access. Do not print that file or export its credentials.

1. Enter the working repository.

```bash
cd /Users/olasumbo/gitRepos/clustermest-trust-controller
```

2. Select the existing kubeconfig for this shell.

```bash
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
```

3. Verify cluster A's API.

```bash
kubectl --context kind-cmtc-a cluster-info
kubectl --context kind-cmtc-a get --raw=/readyz
kubectl --context kind-cmtc-a get namespace kube-system -o jsonpath='{.metadata.uid}'
```

4. Verify cluster B's API.

```bash
kubectl --context kind-cmtc-b cluster-info
kubectl --context kind-cmtc-b get --raw=/readyz
kubectl --context kind-cmtc-b get namespace kube-system -o jsonpath='{.metadata.uid}'
```

Require `ok` and the exact UIDs in the environment table. Stop mutations on a
UID mismatch. Use explicit contexts; do not change a shared current-context.

The read-only host access check on2026-10-25, recorded at17:10UTC, returned
the following. Its [receipt](docs/evidence/local-activation-20261025/raw/api-access-check.json) contains no credentials:

| Context | Current API endpoint | Result |
| --- | --- | --- |
| `kind-cmtc-a` | `https://127.0.0.1:54193` | readyz `ok`, expected UID, two Ready nodes |
| `kind-cmtc-b` | `https://127.0.0.1:54247` | readyz `ok`, expected UID, two Ready nodes |

These ports are a snapshot. Discover them again with `cluster-info`; do not
hard-code them into product source. API readiness does not prove ClusterMesh
or workload-mTLS health.

5. Discover node names and addresses through each API.

```bash
kubectl --context kind-cmtc-a get nodes -o wide
kubectl --context kind-cmtc-b get nodes -o wide
```

Use returned names in test placement and registration. The application runner
currently expects the recorded two-node fixture names. Validate that assumption
before running it; generalize discovery before reusing it on another topology.

6. Inspect the existing application fixture.

```bash
kubectl --context kind-cmtc-a -n cmtc-live-mtls get pods -o wide
kubectl --context kind-cmtc-b -n cmtc-live-mtls get pods -o wide
```

### Develop against these APIs before packaging

Use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery →
package the verified change**. API connectivity above is already available;
do not build an application image merely to discover a controller integration
failure. Run suitable Go helpers directly from the MacBook with the explicit
kubeconfig and context. For client-go, use explicit loading rules and
`ConfigOverrides.CurrentContext`; do not rely on an ambient default context.
Check each command's actual flags before use. Setting `KUBECONFIG` does not
make an ordinary unit test an API integration test.

Do not start a second controller that writes resources already managed by a
running controller. Claim and coordinate the single writer first. Use the
existing run ledger for probes and record actual API/traffic results. Linux
datapath code needs the Ubuntu toolchain and selected owned nodes. A complete
matching binary/BPF set must be tested; a Mac build cannot qualify Linux BPF.
After the working path is verified, build with host Podman, import the exact
image, and repeat the affected tests.

### Reach Colima and the builder

For read-only VM inspection:

```bash
colima -p cmtc-cilium status
colima -p cmtc-cilium ssh
```

The VM runs Docker and the kind nodes. Host tools control it through the
existing Docker context:

```bash
docker --context colima-cmtc-cilium ps
```

Host kind commands must select that runtime explicitly:

```bash
DOCKER_HOST=unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock kind get clusters
```

For the separate build connection:

```bash
podman system connection list
podman --connection cmtc-ubuntu-build info
```

Do not change the default container connection. The MacBook API endpoints use
host loopback. `127.0.0.1` inside Colima or a build container names that different
network namespace; it does not automatically reach the MacBook API forward.
Prefer the verified host API path. If a Linux tool must call an API directly,
verify its route and certificate-valid endpoint before supplying a separately
scoped configuration. Never disable TLS verification to make that route work.
An authenticated API error and a sandbox/socket denial require different
diagnostics; do not recreate the clusters for either.

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
8. **Clock rejection observed by the monitor.** At16:49UTC, B's worker proxy
   rejected an issuer profile with `wall clock moved backwards`, closed admission
   and cancelled existing TLS I/O. At16:50:03UTC, host and VM clocks matched and
   VM NTP reported synchronized. This does not explain or disprove the prior
   rejection. Compare the verifier clock floor with profile timing. Do not reset
   checkpoints. Read the local receipt under
   `artifacts/local-monitor/20261025T164929Z/`.

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
