# Verification queue — 2026-10-23

Baseline: [Cilium v1.20.4 source audit](SOURCE_AUDIT.md), [immutable pins](sources.lock.json). “Static reviewed” is not runtime validation. The [implementation plan](../architecture/IMPLEMENTATION_PLAN.md) defines acceptance and dependencies.

| Topic | Evidence collected | Remaining verification | Owner component / stories |
|---|---|---|---|
| Release pin | Tag/commit/tree recorded; exact source retrieved | Build/test environment and image provenance; no production support declared | Cilium / CMTC-001 |
| ClusterMesh + ztunnel | Static guard verified (V01) | Complete remote export→xDS trace, capabilities and secure guard transition | Cilium / CMTC-001,401 |
| Enrollment | Exact label, StateDB derivation, local ZDS/netns lifecycle (V02/V03) | Startup/relabel/delete races, UID binding, fail-closed packet gate and stable observation API | Cilium + CMTC / CMTC-503,507,202,203 |
| Remote SPIFFE identity | Local xDS mapping and existing operator SPIRE registration reviewed (V04–V08) | Cluster-qualified identity/keys, authenticated provenance, same-name collision and foreign-intermediate denial | Cilium + SPIRE / CMTC-105,401,402 |
| Authorization/service routing | Empty xDS authorization and socket-LB assumption verified (V07) | Original application tuple and peer identity through eBPF/LB/reverse NAT; Global Services and denial tests | Cilium / CMTC-403,404 |
| Option A | SPIRE cert-manager intermediate-signing reference exists; built-in CA path distinguished (V08/V09) | Pin deployed dependencies/issuer; external CA attestation, SVID delivery, root isolation, intermediate restrictions and real consumer reload/rotation | SPIRE + issuer + trust-manager + CMTC / CMTC-101..105 |
| Proxy dependency | Chart default image and separate Rust source tag recorded (V11) | Image/source provenance, dependency approval against no-Istio requirement, workload CA behavior | Cilium ztunnel / CMTC-003 |
| Encryption modes | Exclusive chart branches and TCP iptables redirection reviewed (V10) | WireGuard/XFRM/eBPF trace, flag validation, strict encryption, MTU/MSS, marks and captures for both layers | Cilium / CMTC-301..305 |
| Platform safety | Missing-netns skip and non-enrolled endpoint limitation recorded | Inventory/classification, API/DNS TCP+UDP/webhook/kubelet/ingress/OAuth/etcd, Cilium-enabled OpenShift/SCC/hosted-control-plane and upgrade/recovery tests | CMTC + platform / CMTC-601..606 |
| Metrics/dashboards | All nine JSON dashboards/rules/monitors reviewed; native collector candidates (V12) | Exporters, live names/labels, histogram buckets, per-cluster views, no-data semantics, promtool fixtures and Grafana imports | CMTC + Cilium / CMTC-701..706 |
| Architecture/release | Nine ADRs reviewed; threat model and gated plan drafted | Explicit architecture/security approval, residual risks, evidence ownership and recovery qualification | CMTC-002,003,802..805 |

Reference foundation: [existing lab review](EXISTING_LAB_REVIEW.md), pinned to `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`. Reproduce its topology and existing ztunnel/policy failures on the CMTC baseline; adapt root signing-key replication to Option A. The lab's 1.20.2-derived Hubble patch, control-plane certificates, optional connectivity step and evidence-printing reports cannot substitute for cross-cluster workload identity, both encryption layers and mandatory security assertions.

Official reference entry points (floating documentation; do not use as immutable implementation evidence):

- [Cilium ClusterMesh](https://docs.cilium.io/en/stable/network/clustermesh/)
- [Cilium ztunnel](https://docs.cilium.io/en/stable/security/network/encryption-ztunnel/)
- [WireGuard](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/) and [IPsec](https://docs.cilium.io/en/stable/security/network/encryption-ipsec/)
- [SPIRE](https://spiffe.io/docs/latest/spire-about/)
- [trust-manager](https://cert-manager.io/docs/trust/trust-manager/) and [cert-manager](https://cert-manager.io/docs/)
- [OpenShift](https://docs.redhat.com/en/documentation/openshift_container_platform/)
