# ClusterMesh Trust Controller

**Design only; no deployment or cross-cluster mTLS implementation.** Source review: 2026-10-23.

CMTC proposes a Go operator for namespace enrollment, shared public trust and certificate rotation, with native Cilium enforcement. Preserve the protected organizational root, cluster intermediates, SPIRE/cert-manager Option A, trust-manager, platform safety, exclusion precedence, optional WireGuard/IPsec, no silent downgrade and all nine Grafana dashboards. No Linkerd or Istio deployment is proposed.

## Start here

1. [Source audit and verified gaps](docs/research/SOURCE_AUDIT.md), pinned to Cilium **v1.20.4**, commit `beb276d2f38d4aadfda14710acf8d14a0f1ba723`.
2. [Incremental implementation and PR plan](docs/architecture/IMPLEMENTATION_PLAN.md).
3. [Threat model](docs/architecture/THREAT_MODEL.md) and [nine proposed ADRs](docs/architecture/adr/ADR-001.md).
4. [Target architecture](docs/architecture/END_TO_END_DESIGN.md), [security test matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md), [backlog](docs/agile/BACKLOG.md) and [stories](docs/agile/stories.csv).
5. [Observability audit](observability/docs/SOURCE_AUDIT.md) and [handover](docs/handover/CODEX_START_HERE.md).

## Current constraints

The pinned Cilium source rejects ztunnel with ClusterMesh. Its xDS workload stream uses local endpoint resources and does not implement authorization policy. The chart selects one encryption type; HBONE over WireGuard/IPsec remains a research target. See the source audit for immutable citations and evidence limits.

Existing SPIRE enrollment support should be evaluated before adding an adapter. Cilium's ztunnel dependency is Rust and has Istio origins; [ADR-001](docs/architecture/adr/ADR-001.md) records the dependency boundary for review.

Namespace labels and enrollment acknowledgments cannot establish `Protected`. A Go module, executable controllers/DaemonSet, generated CRDs, CI, instrumentation and runtime security tests remain unimplemented. The sample APIs and nine dashboard JSON files are scaffolding. No private CA keys belong in this repository or in bundle distribution.

Repository: [ephico2real2/clustermesh-trust-controller](https://github.com/ephico2real2/clustermesh-trust-controller).
