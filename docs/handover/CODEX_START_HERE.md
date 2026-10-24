# Codex continuation / session handover

## Dashboard consolidation — 2026-10-24

The user's latest requirement is to preserve all nine existing dashboard domains and original JSON files while combining their coverage into one or two meaningful pages. Commit `923fed1` restores the nine originals unchanged to `observability/dashboards/` and includes all original metric meanings in two provisioned pages: Operations and Workload Security. Future signals stay visible with `planned` titles and BLOCKED evidence; do not remove their panels or substitute successful zero values. The twelve native mTLS panels remain semantically unchanged inside Workload Security. See the root [dashboard guide](../../DASHBOARD_GUIDE.md), [metric contracts](../../observability/METRICS.md) and `capabilities.json`. The generator selects chart types from metric meanings and uses the user's Tableau/table style; validators verify original hashes, coverage and actual scoped queries. Default browser capture now has five cases (two pages in two themes plus remote app). Prior eleven-page CI results below are historical and remain valid for their recorded source. [Local dashboard evidence](https://github.com/ephico2real2/clustermesh-trust-controller/blob/87fb20341d62904d2536efc840b975a49458be23/2026-10-24T0558Z-cmtc-consolidated-dashboards/README.md) records source `5d1ddc1`, 18,000 baseline HTTP successes, 6,000 cross-node mTLS HTTP successes, 900 rejected unenrolled attempts, both themes, typed queries and preserved originals. That artifact does not itself qualify an AMD64 CI run.

## Latest continuation — 2026-10-23

User workflow requirement: finish the affected local tests, lint, image build and applicable load/screenshots before pushing changes that trigger CI or dispatching it. Use Podman from the MacBook host for subsequent image builds, with native Linux ARM64 or explicit target architecture as needed. The existing kind fixtures run in the dedicated Ubuntu Colima profile. Reproduce CI failures locally before rerunning.

The active SPIRE workload credential spike is local-only on `feat/spire-workload-mtls-spike` (CMTC) and `feat/ztunnel-spire-credentials` (Cilium). An isolated `cmtc-mtls` two-node cluster now has cert-manager-issued issuer/ADS chains, an external-root bootstrap whose root key is removed, healthy SPIRE and healthy ztunnel. SPIRE 1.15.5's UID 1000 could not write the inherited root-owned server socket hostPath; the fixture now uses a pod-local writable socket and consistent non-root server/sidecar identity. The [first cross-node positive trial](../development/SPIRE_SPIKE.md) passed 10/10 requests with verified workload SVID chains, actual TLS records and an absent HTTP canary. The unenrolled-source plaintext negative case returned HTTP 200, so CMTC-403 remains a failed security gate. Do not infer authorization or full end-to-end protection from this positive trial. [Issue #7](https://github.com/ephico2real2/clustermesh-trust-controller/issues/7) records the user's bounded retry, verified acknowledgment and structured logging requirements. The initial Cilium operator slice uses injected slog, Hive jobs/health, cancellable jittered backoff and an authenticated RPC response before initialization; its Podman race tests pass locally. Registration/proxy recovery gates, broader workload/negative tests and the issue's full acceptance remain open. Do not trigger CI for this slice before the local qualification passes.

[Cilium PR #6](https://github.com/ephico2real2/cilium/pull/6) implements Authorization resource transport at `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`: a typed Hive cache, atomic immutable batches, the existing Cilium delta engine, separate Address/Authorization ACK state, serialized gRPC writes and stream error cleanup. Local Ubuntu ARM64 and [AMD64 CI 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200) each passed 150 tests/subtests with the race detector, plus vet; CI also passed exact protobuf regeneration. [Immutable local wire evidence](https://github.com/ephico2real2/cilium/tree/4ba5fc1df930c6a062875628cfe3e090218cf96a/2026-10-24T0205Z_ztunnel_authorization_local-arm64) records the exact source/toolchain. This tests the real Go ADS handler over in-memory gRPC with fake policies. No effective-policy producer, remote discovery or persistent admission gate is enabled. ACK metrics cannot mark workloads Protected. The guard and Observe-only schema remain.

The new image baseline passed [local qualification](https://github.com/ephico2real2/clustermesh-trust-controller/tree/67c7f0c1dda7916cef9cf3ba29c149b23f9d731e/2026-10-24T0237Z_cmtc_authorization_images_local-arm64): 18,000/18,000 HTTP 200 responses, policy/RBAC and remote-only service checks, exact source/digest verification, eleven browser pages and six live Observe panels. Initial reuse required resetting only the six test fixture namespaces. The follow-up Cilium test-only head `cf34ab9ae795fa6f0e79fe86a30b0d21bb90185d` passed pinned lint, 150 race tests/subtests and vet locally before its push. CI run `40054147461` was cancelled to honor the user's local-first requirement; do not rerun it alongside the next feature-head run.

The PoC dashboard work is merged: [Cilium PR #5](https://github.com/ephico2real2/cilium/pull/5) at `8c4ff1b52e283b83e8d285decd5e73624e326a0c` and [CMTC PR #5](https://github.com/ephico2real2/clustermesh-trust-controller/pull/5) at `548ccc8ea4405211925e9f9701c1104f9553011f`. Hubble [CI 40050031206](https://github.com/ephico2real2/cilium/actions/runs/40050031206) passed 151,063/151,063 HTTP 200 responses and eleven browser cases; [local ARM64 evidence](https://github.com/ephico2real2/cilium/tree/b13bda7f2e4e30484b8caee2a7f02a180799c157/2026-10-24T0123Z_hubble_l7_by_app_local-macos-arm64) passed 151,200/151,200. CMTC [feature CI 40050113155](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40050113155) and [merged-main CI 40051394574](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40051394574) passed. The exact demo 37 [generator/example](../../examples/observability/hubble-l7-by-app/README.md) is pinned and regenerated in CI. Gateway source app can be empty despite populated namespace/workload; app All retains that series.

[CMTC PR #4](https://github.com/ephico2real2/clustermesh-trust-controller/pull/4) is merged at `90f6bc647a88a1c6b1b00fd0203a4b49f7537b83`. [Feature-head CI 40043884931](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40043884931) and [merged-main CI 40046157600](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40046157600) passed the GHCR-backed two-cluster lab. An independent native ARM64 MacBook run also passed: two kind clusters/four nodes, source-matched fork agent/operator/mesh API images, cert-manager ClusterMesh, policy/RBAC tests, and 18,000/18,000 HTTP 200 responses across three six-minute streams. [Immutable local evidence](https://github.com/ephico2real2/clustermesh-trust-controller/tree/18d063335fb130770003c915cb1bed1ee87528fc/2026-10-24T0033Z_cmtc_local-macos-arm64) includes screenshots, measured loads, runtime image/version proof and the required VM inotify adjustment. The local lab remains available in Colima profile `cmtc-cilium`; scripts run inside its Linux VM. See [CILIUM_IMAGES.md](../development/CILIUM_IMAGES.md) and [VALIDATION.md](../development/VALIDATION.md). This establishes the Observe/ClusterMesh baseline only.

[CMTC PR #1](https://github.com/ephico2real2/clustermesh-trust-controller/pull/1) and [PR #2](https://github.com/ephico2real2/clustermesh-trust-controller/pull/2) are merged into main. [Merged-main CI 40028165414](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40028165414) passed at `793c47bb967660f5843c925e79b58f286bf431cc`. This remains Observe/baseline validation.

The user authorized implementation, deployment and CI with screenshots, plus copying demo apps. [CMTC PR #2](https://github.com/ephico2real2/clustermesh-trust-controller/pull/2), branch `feat/cmtc-observe-lab`, adds the Observe API/controller/node-inventory build, deployment/RBAC, Go tests, two-cluster CI and Playwright evidence. [CI run 40020608206](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40020608206) passed at `f81b955948d33ad187ed6891aca7c348ec27197e`; read [VALIDATION.md](../development/VALIDATION.md) for the precise evidence and [OBSERVE_LAB.md](../development/OBSERVE_LAB.md) for operation. The operator cannot mutate namespace labels or read CA Secrets; `EnforcementVerified` stays Unknown. Cilium workload mTLS/dual encryption and SPIRE/rotation remain pending.

The user subsequently confirmed ztunnel workload mTLS **plus** WireGuard/IPsec node transport as the primary end-to-end target. This supersedes the earlier optional-transport framing for that profile; none/mTLS-off remain explicit test controls. [EXISTING_LAB_REVIEW.md](../research/EXISTING_LAB_REVIEW.md) reviews their `cilium-implementation-poc` at commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`, including cert-manager/Hubble/ClusterMesh, public trust bundles, the WG exercise and isolated ztunnel demo. Reuse the test foundation while adapting its root-copy bootstrap; its observability workflow starts with WG disabled and does not establish layered encryption. Keep existing PoC/fork work intact.

Start with [SOURCE_AUDIT.md](../research/SOURCE_AUDIT.md), [sources.lock.json](../research/sources.lock.json) and [IMPLEMENTATION_PLAN.md](../architecture/IMPLEMENTATION_PLAN.md). Cilium v1.20.4 is pinned to `beb276d2f38d4aadfda14710acf8d14a0f1ba723`; the source audit itself is static. [Design PR #1](https://github.com/ephico2real2/clustermesh-trust-controller/pull/1) is the stacked implementation's base. All nine ADRs remain Proposed; user authorization permits the Observe implementation and fork development, without establishing runtime protection.

The [Istio/Linkerd comparison](../research/MESH_MTLS_COMPARISON.md) and [Cilium contract](../architecture/CILIUM_ZTUNNEL_CONTRACT.md) define remote identity, destination L4 authorization and fail-closed admission requirements. [Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1), branch `feat/cmtc-ztunnel-authorization-protocol`, adds only the version-pinned authorization protobuf, generated Go bindings and wire/reproducibility tests. It was ported from the audited release to upstream main `3b6e980b3d4eaa5be4532602ccb2bd54d8540dc4`, with Go 1.27.1 generators, and is merged into the fork at `a035a5892526afa2235b690c62c2f004b72aa9ab`. The fork also includes upstream `e5967e950b8f10ae514c58787e80d8e0192c15fd`. [Merged-main protocol CI](https://github.com/ephico2real2/cilium/actions/runs/40033037552) passed; full source checks are linked in VALIDATION.md. Existing Hubble branches are separate. That initial patch supplied only bindings. The later PR #6 transport slice is described above; effective-policy production/workload references, remote discovery, packet admission, identity issuance/verifier binding and transport composition remain open. The compatibility guard is retained. Review [observability findings](../../observability/docs/SOURCE_AUDIT.md) before instrumenting dashboards.

[Cilium dashboard PR #2](https://github.com/ephico2real2/cilium/pull/2) is merged into the fork at `33ab097444ac942f10606e236678bf55f6a9d498`, with [real-load CI](https://github.com/ephico2real2/cilium/actions/runs/40032696185) and immutable screenshots/query results linked in VALIDATION.md. Upstream #48563 already fixed remote workload propagation. The remaining Gateway All-filter fix preserves workload labels; this reproducer uses an external client for missing source labels because pod clients can retain their namespace/workload. The fork-only [CI PR #3](https://github.com/ephico2real2/cilium/pull/3) is merged at `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`, including upstream `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`. [Combined-source CI 40035107452](https://github.com/ephico2real2/cilium/actions/runs/40035107452) passed seven browser cases and 151,120 HTTP 200 responses across three separately validated load streams at head `221d435ecce12fdf19efb4ca71026ff1c889317b`. The reusable workflow accepts exact source/baseline SHAs, checks real traffic before PNGs and retains raw diagnostics. Merge only owned-repo PRs when checks permit. Do not enable automatic upstream merging. Upstream submission requires the operator's review and own wording under Cilium's AI policy.

The development lab selects a fork image bundle through [CILIUM_IMAGES.md](../development/CILIUM_IMAGES.md) and `config/cilium-images.lock.json`: the original qualification used source `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`; the image-baseline branch advances all three components and the matching chart to `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`. The v1.20.4 audit remains historical. Local ARM64 and AMD64 builds are published. [Cilium publisher PR #4](https://github.com/ephico2real2/cilium/pull/4) is merged at `ae098cf0d9eda61c18fafb36ab0e1216fa058adc`; its [final publisher CI 40041922977](https://github.com/ephico2real2/cilium/actions/runs/40041922977) passed after granting the fork package Write access. All three two-platform digest indices were verified anonymously and consumed by the deployed CMTC tests above. Hubble metadata is part of the agent; the September CEP-only draft is superseded by upstream #48563. Relay/UI forks are only needed for changes to those components.

## Decisions from the design sessions
- Build a native Cilium ClusterMesh + ztunnel cross-cluster mTLS solution; no Linkerd/Istio.
- Use **Go** for CMTC Hub, controllers, node DaemonSet, admission and Cilium control-plane extensions; Cilium Hive/cell conventions inside Cilium, controller-runtime/client-go for standalone operator; C/eBPF only for necessary datapath modifications.
- Option A: protected organizational root CA, cluster-specific intermediates, SPIRE-issued workload X.509-SVIDs, cert-manager UpstreamAuthority integration and trust-manager for **public** trust bundle distribution. Never copy root private signing keys to clusters/namespaces.
- Hub-and-spoke controller plus node-level DaemonSet for pod/node inventory, config acknowledgments, readiness and latency telemetry. Cilium remains enforcement owner; evaluate Hive module vs separate agent.
- `NamespaceMTLSPolicy` reconciles native namespace label `io.cilium/mtls-enabled: "true"`. Support `AllEligible` and `MatchSelectors` modes, OR across selectors, AND within selector; examples `company.net/lob=alpha` OR `company.net/mnemonic=delta`.
- Explicit namespace exclusions override inclusions; protected Kubernetes/OpenShift system/control-plane/infrastructure namespaces never auto-enroll. Avoid breaking API, DNS, webhooks, kubelet, etc. Namespace exclusion is not permission to bypass protected destination security.
- Target HBONE mTLS with WireGuard, IPsec or no L3 encryption; also preserve normal ClusterMesh operation when mTLS off. No silent plaintext fallback. Cilium currently has incompatibilities to solve.
- All nine original Grafana domains and JSON definitions, consolidated into two live pages; Prometheus recording/alerting rules; metrics for enrollment, pods, trust, handshake latency, transport, platform safety, DaemonSet and controller health.
- Agile structure: initiative -> features -> epics -> stories -> subtasks; ADRs, DoR, DoD, security gates and architecture diagrams.

## Current status
- Use the user's configured SSH Git access and human identity. Cilium signoff validation requires their real email from existing Cilium history; do not use a noreply signoff there.
- `NamespaceMTLSPolicy` is a deployed Observe-only API. Its Strict rejection is intentional and tested, not a missing CRD prerequisite. Other proposed CRDs remain design-only.
- The current browser configuration captures five cases across two consolidated pages and the app. Operations uses real Observe telemetry; missing future domain signals are explicitly BLOCKED, not security test successes. Historical eleven-page runs below refer to the earlier layout.
- The Cilium fork has a protocol foundation; it does not yet enforce cross-cluster workload mTLS. No namespace may be marked Protected from its label or an xDS ACK alone.

## Next implementation tasks
1. Implement the effective Cilium policy producer for the typed Authorization cache and bind workload policy references to the correct UID/generation. Preserve application ports, explicit denies and finer pod-label restrictions; reject unsupported policy combinations. The transport lifecycle is implemented/tested, but does not enforce those semantics by itself.
2. Add authenticated, cluster-qualified remote workload discovery with UID/recreation/removal semantics. Keep ZDS/netns enrollment local.
3. Resolve cluster identity issuance and peer-verifier binding; common-root trust plus a display-only cluster ID cannot isolate same-name service accounts.
4. Implement persistent fail-closed admission for missing policies, startup, reconnect, NACK and revocation. The selected proxy currently skips missing references.
5. Qualify same-node, inter-node and cross-cluster mTLS, then separate WireGuard and IPsec composition profiles before revising the compatibility guard or enabling Strict.
6. Preserve platform traffic, real security-negative tests and packet/identity evidence. Screenshots support those assertions; they cannot replace them.

## Important unresolved risks
- Default-on vs metadata-only inclusion must be explicitly selected, not ambiguously combined.
- Cluster intermediate CA compromise could sign identities for another cluster without issuance restrictions and verifier binding.
- Label reconciliation alone cannot fail close during namespace/pod creation races.
- Current Cilium ztunnel/ClusterMesh, L4 policy and WireGuard/IPsec composition limitations need source-level changes and testing.
- TLS handshake success alone does not prove WireGuard/IPsec encryption; separate node-layer evidence is needed.
- OpenShift's default CNI is typically OVN-Kubernetes; Cilium support profile must be verified.
- Control-plane interoperability must preserve native API TLS and DNS UDP without blanket security bypass.


### Historical baseline screenshot and enforcement research

The user confirmed no application sidecars, retaining CMTC's DaemonSet and the
node-level ztunnel. The live experimental dashboard is
<http://127.0.0.1:13000/d/cmtc-spire-mtls-spike>. Its capture passed nine populated
panels under fresh five-minute load: 3,000/3,000 HTTP 200 through Service and
3,000/3,000 through Pod IP. Metrics are native TCP counters, not handshake or
protection gauges. The d8124529 Podman operator's actual SPIRE fault test produced
seven retries, no false ACK and an authenticated ACK after recovery. SPIRE was
restored healthy. [SPIRE_SPIKE.md](../development/SPIRE_SPIKE.md) records the pins.

[Issue #8](https://github.com/ephico2real2/clustermesh-trust-controller/issues/8)
and [PLAINTEXT_ENFORCEMENT.md](../research/PLAINTEXT_ENFORCEMENT.md) record the
plaintext bypass, Linkerd/Istio research and 30 local policy-path observations.
An explicit CNP/CCNP deny blocked direct port-80 HTTP while keeping mTLS working;
default-deny alone was reopened by a broad allow and admitted a local host path.
All temporary experiment policies/probes were removed. This is not complete
strict admission, general authorization or ClusterMesh qualification. The normal
Observe monitoring remains intact; Grafana's file provider now polls every 30s
so projected ConfigMap changes can appear without replacing its emptyDir data.

Local SPIRE/capture evidence is published on `ci-captures` at
[`ec770d2`](https://github.com/ephico2real2/clustermesh-trust-controller/blob/ec770d287ea3bd2b81f7f9140f46f401f9e48e47/2026-10-24T0423Z-local-spire-mtls-d8124529/README.md); this did not run or qualify GitHub Actions.


Authenticated-only implementation: Cilium local commit
`f052d1276b0fb1619809db0059fbbb7898c9cfae`, native GLOBAL DENY for absent verified
principals, no application-port predicate. Config/ADS race tests, vet, pinned lint
and chart checks pass. Its host-Podman ARM64 image config ID is
`0f3a6f60cbb61700e0760536bf7fe0cbe5678a26c2f0e968505ec962a519d8dc`.
The isolated cmtc-mtls Helm revision 5 runs that exact agent on both nodes, with
`ztunnel-require-mtls=true` and `mtls-policy-published` logs. Local qualification now passes 57 steady/post-restart path checks, 1,398 continuous restart probes with no unexpected HTTP, 6,000/6,000 authenticated HTTP 200 responses and 900/900 unauthenticated load attempts rejected.
`scripts/lab/mtls/qualify.py` retains every command/exit/output and rejects any
confounding CNP/CCNP/KNP. Do not infer complete protection from desired policy.

The user's Envoy alternative is filed as [EP10 epic spike #9](https://github.com/ephico2real2/clustermesh-trust-controller/issues/9).
The user requires real load plus Grafana PNGs and full output, following the PoC's
report/check/artifact/captures pattern; publish failed evidence as well as passes.


Latest authenticated-only evidence is [immutable at 1c192a5](https://github.com/ephico2real2/clustermesh-trust-controller/blob/1c192a5ee84fb5218cb1385fdd9c5bf45ca69e1a/2026-10-24T0509Z-local-authenticated-only-f052d127/README.md).
Grafana 12.2.0 has twelve populated panels in both themes, using the user's pinned
[diagram-kit dashboard skill](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/skill/dashboard/SKILL.md).
Headline totals use selected-range counter increases; DENY overlaps attempt
counters. A five-category pie partitions completed destination TCP records,
without summing source and destination reports. Actual query partitions total
100%, missing telemetry remains unavailable, all five labels/captions fit, and
live provisioned panels equal source. The full metric inventory, validator and
both-theme walk specs are under `examples/observability/ztunnel-spike/`.
The existing CI unit job runs the offline validator; no duplicate workflow added.
The captured historical load window is 1792817142251–1792817452353 ms; do not
represent it as continuously running traffic.

The combined f052 agent/d812 operator run reproduced six structured SPIRE retry
logs, no false authenticated ACK while unavailable, and ACK after restoration.
Both components recovered. Keep historical seven-retry evidence separate from
this run. Persistent missing-policy/first-packet admission, general destination
authorization, platform exceptions and ClusterMesh/transport composition remain
open. Do not enable Strict/Protected or close #7/#8 on these bounded passes.
