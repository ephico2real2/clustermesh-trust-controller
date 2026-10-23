# ClusterMesh Trust Controller

**Experimental Observe implementation; cross-cluster workload mTLS is not implemented.** Updated 2026-10-23.

CMTC proposes a Go operator for namespace enrollment, shared public trust and certificate rotation, with native Cilium enforcement. The primary target is ztunnel workload mTLS layered over WireGuard or IPsec node transport encryption, verified end to end across ClusterMesh. Preserve the protected organizational root, cluster intermediates, SPIRE/cert-manager Option A, trust-manager, platform safety, exclusion precedence, no silent downgrade and all nine Grafana dashboards. No Linkerd or Istio deployment is proposed.

## Start here

The [deployed Observe lab runbook](docs/development/OBSERVE_LAB.md) covers the Go controller, node inventory agent, real observation CRD/metrics, two-cluster Cilium/cert-manager CI deployment, reused [demo applications](examples/apps/README.md), test assertions and browser screenshots. Run `make test build` for local Go verification. CI deploys the actual image and preserves evidence before teardown.

[Deployed validation](docs/development/VALIDATION.md) records the passing two-cluster run and its eleven published browser captures, with the exact tested commit and remaining encryption limitations.

1. [Source audit and verified gaps](docs/research/SOURCE_AUDIT.md), pinned to Cilium **v1.20.4**, commit `beb276d2f38d4aadfda14710acf8d14a0f1ba723`.
2. [Incremental implementation and PR plan](docs/architecture/IMPLEMENTATION_PLAN.md).
3. [Threat model](docs/architecture/THREAT_MODEL.md) and [nine proposed ADRs](docs/architecture/adr/ADR-001.md).
4. [Target architecture](docs/architecture/END_TO_END_DESIGN.md), [security test matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md), [backlog](docs/agile/BACKLOG.md) and [stories](docs/agile/stories.csv).
5. [Observability audit](observability/docs/SOURCE_AUDIT.md) and [handover](docs/handover/CODEX_START_HERE.md).

Existing test foundation: the [Cilium lab review](docs/research/EXISTING_LAB_REVIEW.md) pins the user's working PoC, identifies reusable topology/cert-manager/observability patterns, and records its separate ztunnel experiment and required PKI/transport adaptations.

## Current constraints

The pinned Cilium source rejects ztunnel with ClusterMesh. Its xDS workload stream uses local endpoint resources and sends no authorization policies. The proxy already has an L4 authorization engine; the missing integration includes remote identity records, real policy delivery and fail-closed admission. The [Istio/Linkerd comparison](docs/research/MESH_MTLS_COMPARISON.md) and [Cilium integration contract](docs/architecture/CILIUM_ZTUNNEL_CONTRACT.md) specify the adaptation and version-specific traps. The chart selects one encryption type; HBONE over WireGuard/IPsec remains a research target.

Existing SPIRE enrollment support should be evaluated before adding an adapter. Cilium's ztunnel dependency is Rust and has Istio origins; [ADR-001](docs/architecture/adr/ADR-001.md) records the dependency boundary for review.

Namespace labels and enrollment acknowledgments cannot establish `Protected`. The current API supports `enforcement.mode: Observe` only: it evaluates namespace metadata, reports counts/status and inventories local pods. Namespace RBAC is read-only, Strict is rejected, and enforcement stays Unknown. The [Observe sample](config/samples/namespace-mtls-policy.yaml) is deployable with the CRD; `*.target.yaml` and ClusterMeshTrust remain future API proposals.

Nine domain dashboards remain partly proposed; CI provisions them alongside a separate live evaluation dashboard, validates actual selection/inventory metrics and captures the pages. SPIRE workload issuance, trust rotation, live enrollment and the Cilium cross-cluster/dual-encryption changes remain pending. No private CA keys belong in this repository or in bundle distribution.

Repository: [ephico2real2/clustermesh-trust-controller](https://github.com/ephico2real2/clustermesh-trust-controller).
