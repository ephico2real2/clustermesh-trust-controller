# CMTC architecture update

Status: current runtime, qualified experiments and open gates, revised 2026-10-25 (23:10Z state).

Workload mTLS between `cmtc-a` and `cmtc-b` now runs on our Cilium, ztunnel and SPIRE forks. The allow paths pass in
both directions. DNS from enrolled Pods, recovery, policy denial, transport encryption and per-connection identity
evidence are still open, so no workload is `Protected`. This update connects the retained proposals to that state.
An SVID is a SPIFFE workload credential.

Use [delivery status](docs/agile/DELIVERY_STATUS.md) for exact source and image pins, and the
[test matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md) for results and gates.

## What changed

| Earlier proposal or baseline | Accepted change | Current limit |
| --- | --- | --- |
| A direct-root verifier accepted only a root that directly signed SPIRE's CA. | Verify the explicitly approved cluster intermediate and pin the exact SPIRE signer. | A shared root or matching trust-domain string alone grants no trust. |
| The first PKI proposal reused existing ClusterMesh issuer resources. | Use isolated SPIRE CA resources. Preserve ClusterMesh PKI. | Root private keys stay outside clusters and evidence. |
| Cilium's reviewed registrar selects namespace and service-account names. | Test exact Pod, node and daemon incarnations with bounded entry lifetimes and verified readback. | The separate registrar remains an experiment and is not deployed. Its permanent owner is undecided. |
| The diagnostic client could swallow SPIRE stream errors. | Stop on the first error. A fresh request must prove recovery. | Credential delivery does not prove traffic protection. |
| The proxy would share the SPIRE agent Admin socket. | A DelegatedIdentity-only agent socket in our SPIRE fork; ztunnel uses it. | The agent Admin socket is unchanged and not shared. |
| Upstream Cilium rejects ClusterMesh with ztunnel. | A capability check in our Cilium fork: strict mTLS, SPIRE CA, effective-policy quarantine, authenticated remote membership and issuer-profile pins are all required. | Passing the check is startup validation, not traffic qualification. |
| A destination compiled ALLOW rules from callers on its own node only. | Each source publishes its realized egress; the destination admits external callers after lease, trust-domain, capture, decode, subject and ipcache checks ([ADR-010](docs/architecture/adr/ADR-010.md)). | The ADR-010 review findings are open. |
| The CMTC DaemonSet eBPF was a temporary prototype to port into Cilium. | The CMTC DaemonSet eBPF is the permanent, observe-only measurement plane ([ADR-005](docs/architecture/adr/ADR-005.md)). The quarantine gate is native in Cilium. | The measurement loader is not built; no eBPF observer or fence is deployed. |
| Older runners targeted the removed `cmtc-mtls` cluster. | `scripts/lab/mtls/namespace_transition.py` and `cni_postdelete.py` exit before argument parsing. The cluster runners `qualify.py:138`, `load.py:55`, `policy_absence.py:105` and `cni_admission.sh:15` refuse any context but `kind-cmtc-mtls`. `bootstrap.sh` still creates `cmtc-mtls` when it is absent. | Use `cmtc-a` and `cmtc-b`. Do not recreate the retired fixture for normal testing. |

The initial and revised Cursor PKI files remain [historical design inputs](docs/research/cursor/README.md#retained-pki-proposals).
Their embedded commands are not current runbooks.

## Current PKI and credential path

![Two-cluster PKI with isolated approved cluster CAs and exact SPIRE signers; ztunnel uses a DelegatedIdentity-only agent socket](docs/diagrams/architecture-update/current-pki.light.png)

*Solid boxes show deployed PKI mechanisms. Certificate authority relationships do not represent application traffic.*

```text
Private host:
  Organization root key -> sign each approved cluster CA CSR.

Each cluster, cmtc-a and cmtc-b:
  Approved cluster CA -> cert-manager signs SPIRE server CA.
  SPIRE verifies node and workload attestation.
  The exact SPIRE signer issues workload SVIDs.
  Trust domain: cmtc-a.mesh.example or cmtc-b.mesh.example.
  Ztunnel fetches delegated SVIDs through the DelegatedIdentity-only agent socket.
  Existing ClusterMesh PKI remains separate.

A valid SVID does not by itself prove protected traffic.
```

The hierarchy has four certificate levels:
organization root, approved cluster intermediate, exact SPIRE signing CA and workload SVID.
The verifier accepts that approved chain.
It rejects an unapproved signer and certificates issued by that signer.
See [PKI trust flow](PKI_TRUST_FLOW.md) for the verification order and stale-flow controls.

CMTC publishes approved **public** cluster, trust-domain and issuer information.
Its output has short leases and monotonic authority state.
This publication does not attest a Pod or grant traffic.
SPIRE performs attestation and credential issuance.

## Exact registration experiment

The experimental Go registrar runs inside the SPIRE server Pod when it is deployed.
It uses the server's private Admin socket there.
It does not distribute that socket to applications or node proxies.
It neither signs certificates nor carries application traffic.

The helper checks approved cluster, namespace, service-account, node and daemon incarnations.
Its leaf entries select the current Pod UID and node name.
It removes obsolete owned entries and verifies stored material by readback.
A failed pass clears readiness and attempts bounded withdrawal.
Entry expiry, SVID expiry and connection drain remain separate controls.

**Historical trial (2026-10-25, registrar `e39928bc4f`, diagnostic `75843515d5`).**
The corrected eighth two-cluster trial passed target credential withdrawal with valid same-node controls.
Reenrollment, Pod replacement, server restart and exact cleanup also passed.
All 124 host helper tests passed.
The application continuity test passed all 36 paths.
These results establish registration and credential behavior for those images; they do not establish protected
traffic. [Retained runtime evidence](docs/evidence/exact-spire-registration/summary.json).

**Current.** The registrar is not deployed. Cilium's legacy namespace/service-account registration is switched off
(`ztunnel-spire-external-exact-registrar=true`). The live fixture's exact entries were written by the operational
fixture runner. Read the [illustrated registration comparison](SPIRE_REGISTRATION_WORKFLOW.md) and the
[ownership decision](SPIRE_REGISTRATION_DESIGN.md). The permanent choice remains open: enhance Cilium's registrar or
keep the separate helper. Use one authoritative registration writer when that choice is made.

## Native enforcement path

![Cilium capture and policy plus node ztunnel workload TLS, deployed in both clusters; transport encryption and recovery remain open](docs/diagrams/architecture-update/target-enforcement.light.png)

*Solid boxes and arrows run in both clusters. The dashed box is the proposed WireGuard or IPsec layer. Allow paths
pass; the open gates are listed below the figure.*

```text
Control inputs in each cluster:
  CMTC -> approved public issuer profile.
  SPIRE -> attested workload credentials.
  Cilium (our fork) -> native workload discovery, capture, quarantine, effective policy and xDS.

Deployed traffic path:
  Application A -> Cilium capture (quarantine until release)
    -> node ztunnel A -> HBONE workload TLS
    -> node ztunnel B -> Cilium-compiled ALLOW rules -> Application B.
  Tested in both directions, same node, cross node and cross cluster.

Separate transport layer (proposed):
  The primary target requires WireGuard or IPsec beneath workload TLS.
  Neither is configured. HBONE-only operation is the control profile running today.
```

No application sidecars are required.
Ztunnel is the node workload-TLS component.
The CMTC DaemonSet's eBPF programs are the permanent per-node measurement plane ([ADR-005](docs/architecture/adr/ADR-005.md)).
They observe only, and they do not encrypt traffic.
Packet enforcement and the quarantine gate belong to the enhanced Cilium datapath.
The eBPF fence is a lab qualification tool.

**Result, 2026-10-25, 23:00–23:10Z** ([evidence](docs/evidence/g1-destination-sources/README.md)):

| From | Same node | Cross node | Cross cluster (Pod IP) | Global Service by ClusterIP | Global Service by name | Unregistered caller |
| --- | --- | --- | --- | --- | --- | --- |
| cmtc-a | 6/6 allowed | 6/6 allowed | 12/12 allowed | 6/6 allowed | Fail: DNS timeout | 6/6 no response |
| cmtc-b | 6/6 allowed | 6/6 allowed | 12/12 allowed | 6/6 allowed | Fail: DNS timeout | 6/6 no response |

Mandatory capture must cover application TCP ports without a fixed application-port list.
It must preserve native service translation, network policy and platform traffic.
A source-IP receipt or map reference alone cannot prove this coverage.

## Kernel and recovery source work (historical)

- **Kernel policy-map fixture (2026-10-25).** The first kernel attempts failed: the static test header shadowed
  Cilium's generated node header, the minimal Hive lacked map-size providers, and one map had zero capacity. Cilium
  source `07722a595a` passed the seventh attempt, for IPv4 only
  ([evidence](docs/evidence/native-policy-map-reachability/README.md)). IPv6/dual-stack, persistent restore
  quarantine, mandatory all-port capture and exact-image recovery remain open.
- **Lost-ACK recovery (2026-10-25).** Committed as Cilium `3985cc135a`. Its actual-etcd race profile passed 416
  top-level tests and 1,713 subtests, with vet. The lockdebug profile passed 40 tests and 74 subtests. The broader
  lockdebug attempt found an unchanged upstream recursive-lock test; its failure is retained in
  [the evidence](docs/evidence/native-lost-add-ack/summary.json). Live F1 lost-ACK recovery on the deployed build has
  not run.

## Remaining acceptance gates

1. Fix DNS from enrolled Pods (diagnosed: the HBONE-only egress gate drops plaintext UDP/53 to CoreDNS); then test
   the Global Service by name.
2. Run recovery on the deployed build: agent restart, ztunnel restart, node reboot, drain and F1 lost-ACK.
3. Fix the ADR-010 review findings (compromised-agent reader invalidation, lease expiry at receipt, 30 s egress
   narrowing, plan-fatal bounds).
4. Traffic-test denial by policy: a source whose egress denies the destination, and port narrowing.
5. Correlate each allowed request with verified peer certificates.
6. Qualify workload TLS with WireGuard or IPsec as a separate composition test.

Registration source-failure and expiry injection remain open.
Production registrar ownership remains a separate decision.
Keep [the security matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md) as the acceptance contract.

## Diagram sources

Use [the diagram-kit source](docs/diagrams/architecture-update/source.html).
Generate only light-theme images for this guide.
The kit check validates layout without producing dark image files.

```sh
~/.local/share/diagram-kit/.venv/bin/diagram-render --check \
  docs/diagrams/architecture-update/source.html
~/.local/share/diagram-kit/.venv/bin/python \
  scripts/capture/render_light_diagrams.py \
  docs/diagrams/architecture-update/source.html \
  docs/diagrams/architecture-update current-pki,target-enforcement
```

Update the source, images and text twins together.
Inspect both light images after rendering.
For build and import steps, use [the local image guide](LOCAL_IMAGE_BUILD.md).
