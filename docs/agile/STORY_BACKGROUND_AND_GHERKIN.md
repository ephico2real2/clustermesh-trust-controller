# Story background and executable acceptance scenarios

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

## CMTC-501 / 505 — Metadata-driven namespace enrollment
**As a** platform engineer, **I want** CMTC to use existing LOB/mnemonic namespace labels, **so that** groups of application namespaces automatically enroll without per-namespace work.

Given `selectionMode=MatchSelectors` and a namespace with `company.net/lob=alpha`, when reconciled, then `io.cilium/mtls-enabled: "true"` is applied. Given `company.net/mnemonic=delta`, the same occurs. Given neither label, it is not selected. Given both conditions within one selector, AND semantics apply. In `AllEligible`, all eligible application namespaces enroll regardless of business labels. Namespace creation/recreation, relabeling and GitOps drift are tested.

## CMTC-502 / 506 — Exclusions
**As a** security owner, **I want** explicit exclusions to override selectors, **so that** exceptions are deterministic and auditable.

Given namespace `legacy-payments` matches inclusion and exclusion, when reconciled, then CMTC removes its managed enrollment label, emits a reason, and does not authorize traffic to protected namespaces. Unauthorized users cannot grant exclusions or alter reserved labels.

## CMTC-503 — Pod protection
**As an** SRE, **I want** actual per-pod protection readiness, **so that** labels cannot conceal a plaintext bypass.

Given an enrolled namespace with a new pod and missing SPIRE/ztunnel readiness, when the pod sends traffic, then protected traffic is denied by Cilium and the pod remains `PendingEnforcement`; when all prerequisites become ready, the pod is `Protected` after verified datapath state.

## CMTC-101..105 — Shared trust and rotation
**As a** PKI operator, **I want** a common trusted root with separate cluster intermediates, **so that** workloads authenticate across clusters without copying root signing keys.

Given old Root A, when Root B is introduced, then all clusters acknowledge actual trust consumption before issuance switches; all SVIDs rotate and probes pass before Root A retires. Partitioned clusters block unsafe retirement; emergency compromise uses a separate response procedure.

## CMTC-105 — Cluster identity issuance boundaries

**As a** security owner, **I want** workload identities bound to their issuing cluster and attested workload, **so that** another cluster cannot impersonate a same-name workload.

`mesh.example.com` in the [proposed ClusterMeshTrust sample](../../config/samples/clustermesh-trust.yaml) is an example **SPIFFE trust domain**: it names the security realm that issues workload identities. Applications can use any DNS name or application port; the trust domain does not select their DNS suffix or port. Application authorization still determines which connections are allowed.

For example, an `orders` workload could have this certificate identity:

```text
spiffe://mesh.example.com/ns/orders/sa/api
         └ trust domain     └ namespace / service account
```

It is an identity namespace for a trusted group. Actual trust comes from verified certificates and trusted CA bundles; matching that string alone does not establish trust. See [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/).

If two clusters share that domain and both have namespace `orders` and service account `api`, this format gives them the **same identity**. The namespace/service-account path alone has no cluster component. CMTC therefore needs either cluster-specific trust domains with explicit trust between them, or another cryptographically verified cluster binding. A display-only cluster label or common root with unconstrained intermediates does not establish that boundary. The [Cilium/ztunnel identity contract](../architecture/CILIUM_ZTUNNEL_CONTRACT.md#identity-decision) records the scheme now used in the lab; this clarification does not approve it as final.

Acceptance scenarios to implement and qualify locally before CI:

1. **Legitimate peer:** Given an explicitly trusted peer cluster and its attested `orders/api` workload, when its SVID and issuer chain are verified and policy allows the connection, then cross-cluster mTLS succeeds with the expected cluster-qualified peer identity. Exercise application DNS names unrelated to the trust domain and multiple application ports.
2. **Same-name collision:** Given clusters A and B both contain `orders/api`, when B authenticates, then it cannot satisfy a policy that permits only A's workload. Reproduce the identical-URI ambiguity of a shared-domain namespace/service-account-only baseline; the selected design must reject impersonation rather than infer cluster origin from that URI or discovery metadata.
3. **Issuer boundary:** Given a certificate whose URI claims B's identity but whose signer is authorized only for A, when presented to the verifier, then it is rejected even if both chains reach a shared trusted root. Also reject a matching URI signed by an untrusted issuer, an untrusted domain and a certificate without a valid chain.
4. **Issuance boundary:** Given an attested workload in A, when it requests B's identity or another workload's namespace/service account, then issuance is denied. Reusing a namespace or Pod name after deletion cannot reuse stale attestation or UID provenance.
5. **Failure and recovery:** Given missing, stale or removed peer trust/issuer constraints, when a new connection is attempted, then it fails closed. After verified trust is restored, legitimate traffic recovers without accepting the impersonation cases.
6. **Evidence:** Retain source/image pins, public certificate chains, expected and observed identities, request outcomes and bounded rejection/status telemetry. Correlate records with authenticated cluster/workload provenance; exclude private keys and tokens. Metrics, labels and successful configuration acknowledgments alone cannot establish identity isolation or Protected status.

**Status (2026-10-25): In progress.** The lab uses cluster-specific trust domains (`cmtc-a.mesh.example`, `cmtc-b.mesh.example`), and our ztunnel fork verifies each peer against the exact approved signer of its trust domain. Scenario 1 passes as traffic outcomes (cross-cluster allow paths, both directions); per-connection peer-identity evidence is not recorded. Scenarios 2–5 have not run live. These are acceptance requirements, not claims of qualified cluster isolation. Our Cilium fork replaced the blanket ClusterMesh/ztunnel rejection with a capability check; that check is not a substitute for these scenarios.

## CMTC-301..305 / 401..404 — Native encryption and authorization
**As a** Cilium maintainer, **I want** remote SPIFFE identity, HBONE and L4 policy to work across ClusterMesh, **so that** workloads remain authenticated and authorized with optional WireGuard/IPsec.

Given transport none/WireGuard/IPsec, when protected TCP connects, then remote identity and policy are verified and the expected transport is independently observed. Unknown identity, unauthorized L4 flows and lost required encryption fail closed. Mixed unsupported modes are rejected.

## CMTC-601..606 — Platform safety
**As a** Kubernetes/OpenShift administrator, **I want** system namespaces guarded, **so that** enabling mTLS does not break cluster operations.

Given platform-protected namespaces, when selectors match, then they remain unenrolled. During canary rollout, API/DNS/webhook/kubelet/ingress/operator probes pass; failures stop progression and rollback is marked successful only after datapath recovery is verified.

## CMTC-701.. — Observability
**As an** SRE, **I want** coverage, latency, CA, authentication, transport and control-plane dashboards, **so that** I can distinguish missing data from healthy zero-error behavior.

Given instrumented CMTC/Cilium metrics, when a failure occurs, then Prometheus alerts and Grafana reflect it with bounded labels and drilldown logs. PromQL is validated against actual metric samples; no sample dashboard data is represented as production telemetry.

## Universal Definition of Done
Code/design review, unit and integration tests, negative security tests, metrics and dashboards validated, source version pinned, ADR updated, recovery documented, platform health preserved, CI green, no unauthorized plaintext fallback. Stories needing Cilium changes cannot be closed by operator-only behavior.
