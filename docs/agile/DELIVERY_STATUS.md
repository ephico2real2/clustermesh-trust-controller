# End-to-end local delivery status

Active mandate: October 24, 2026. Complete the full CMTC implementation autonomously through the canonical stories in [BACKLOG.md](BACKLOG.md) and [stories.csv](stories.csv). Complete each story locally first. CI is deferred at the user's request; local commits do not imply a passed story.

The existing Podman MacBook builder and Ubuntu Colima kind runtime remain separate. Preserve unrelated applications, both Observe clusters and the isolated mTLS fixture. Root signing keys stay outside clusters and evidence. No application sidecars are added; CMTC remains a lightweight Go control plane and node agent, Cilium owns capture/policy, and node ztunnel performs TLS.

| Delivery dependency | Stories | Current evidence / work remaining |
| --- | --- | --- |
| Baseline and intent | CMTC-001/002, 501/505/506/507, 202/702/802 | Pinned-source audit, Observe CRD/controller, selector precedence, read-only RBAC, UID recreation, node inventory and two-cluster tests exist. Live enrollment, full platform qualification and protection remain open. |
| Local identity and startup | CMTC-101, 403 | SPIRE/cert-manager workload SVIDs, native authenticated-only policy, six retry/ACK observations, 57 path checks, 1,398 restart probes, fresh 6,000 authenticated HTTP successes and 900 rejected unenrolled attempts demonstrated locally. Proxy policy loss and capture/creation admission are the active gaps. |
| Effective authorization | CMTC-403/404 | Authorization delta transport is implemented. Implement effective policy production, workload-bound required references, original application tuple and finer label restrictions; qualify missing/removal/NACK/reconnect behavior. |
| Remote identity and trust boundary | CMTC-105/401/402 | Implement authenticated cluster-qualified records, lifecycle/UID provenance and cluster-bound SVID verification. Same-name foreign-cluster/issuer impersonation must fail. Keep the ClusterMesh guard until the supported profile passes. |
| Trust lifecycle | CMTC-102/103/104, 204 | Implement public bundles, actual consumer generation/digest ACK, overlap/switch/drain/retirement, partition blocking and separate emergency revocation tests. |
| Enrollment and observation | CMTC-201/203, 502/503/504/508 | Implement authenticated fresh node observations and safe owned label reconciliation only after mandatory admission and platform gates. Labels and ACKs cannot produce Protected by themselves. |
| Node transport | CMTC-301..305 | Trace and implement independent workload TLS plus WireGuard, then IPsec. Missing required-layer keys/state must block traffic; validate both layers on the same flow with packets and kernel state. |
| Platform and rollout | CMTC-601..606 | Qualify API, DNS UDP/TCP, webhooks, kubelet, ingress and recovery, then the actual supported OpenShift profile. No blanket bypass or unsupported-platform claim. |
| Observability and release | CMTC-701..706, 801..805 | Two consolidated pages preserve all nine original definitions and planned signals. Implement remaining metrics/rules as their owning stories land; finish packaging, resilience and release gates. Dashboards are not the project endpoint. |

## Active CMTC-403 local increment

- Cilium source checkout: `/private/tmp/cilium-ztunnel-authorization-runtime`, local `feat/ztunnel-spire-credentials`, starting at `f052d1276b0fb1619809db0059fbbb7898c9cfae`. The fetched upstream main is already an ancestor of this branch.
- Proxy source checkout: `/private/tmp/cmtc-ztunnel-enforcement`, local `feat/persistent-inbound-mtls`, starting at the exact deployed Cilium ztunnel source `5bb9cf256b10a209ae9bc0624ddfbf27dbc439de`.
- Add an immutable process authentication requirement at the shared inbound authorization check, independent of dynamic policy cache state. Explicitly required missing policies must reject even authenticated callers; valid identity does not override DENY.
- Test compatibility mode, broad ALLOW, missing policy, arrival/removal, empty cache, multiple application ports, restart/reconnect and real authenticated/unenrolled paths. Build and deploy the exact proxy image with host Podman before recording runtime acceptance.
- Trace the Cilium CNI/endpoint enrollment ordering separately. Its EndpointCreated callback currently logs enrollment errors, which cannot establish a mandatory first-packet gate.
- Record command outputs, source/build identity, failures, requests, native policy verdicts and applicable packet/log evidence. Keep the story open until its full acceptance matrix is satisfied.
