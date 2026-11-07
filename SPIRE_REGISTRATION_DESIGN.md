# SPIRE registration design and current experiment

Status: experimental design change; production registration owner is undecided. Revised 2026-10-25.

**Current runtime (2026-10-25):**

- The registrar helper is **not deployed**. The SPIRE server Pod runs the server and the `register-agent-node` container, which confirms the SPIRE agent node entry.
- Cilium's legacy namespace/service-account registration is switched off in both clusters (`ztunnel-spire-external-exact-registrar=true` in `cilium-config`).
- The live fixture's exact workload entries were written by the operational fixture runner with `spire-server entry create`, outside the product.
- Ztunnel is enabled and fetches delegated SVIDs through a DelegatedIdentity-only SPIRE agent socket (our SPIRE fork, `0f8fe4d681`). The agent Admin socket is not shared with the proxy.

The bounded registration and credential trial below passed on 2026-10-25 for its exact images; it is a historical record.

The original design reuses Cilium's SPIRE enrollment.
The separate CMTC registrar was introduced later during local security qualification.
It is an experimental implementation, not an approved permanent architecture.
Its implementation and image build do not approve that architecture change.

The baseline remains reuse of Cilium's enrollment and inventory interfaces.
A production owner change requires a recorded design decision and passing acceptance tests.
The project must not acquire two independent registration owners by accident.

Read [the illustrated workflow comparison](SPIRE_REGISTRATION_WORKFLOW.md) for the existing Cilium path and the experiment.

## Why this helper was created

The immediate problem was registration precision and lifecycle control.
The reviewed Cilium registrar selected workloads mainly by namespace and service account.
The experiment needed exact current Pod and node binding before testing native credentials.
It also needed measurable withdrawal, retry, restart and cleanup behavior.

| Need | Experimental mechanism | Limit |
| --- | --- | --- |
| Avoid obsolete Pod entitlement | Include the exact Pod UID in selectors and the entry key. | A service-account SPIFFE identity can still be shared by authorized Pods. |
| Bind the current node and agent | Use the approved node UID and current SPIRE agent Pod UID in the parent alias. | Agent attestation and selector verification remain SPIRE responsibilities. |
| Control approval | Pin namespace, service-account and DaemonSet UIDs and images. | Approval pins are not all certificate fields or SPIRE selectors. |
| Detect failed enrollment | Read back the exact Entry and expose fresh readiness. | Readback does not prove SVID delivery or protected traffic. |
| Bound abandoned registration | Renew short-lived entries and withdraw owned rows. | Already-issued certificates and existing flows require separate controls. |
| Keep administrative access local | Use the private server Admin socket inside the SPIRE server Pod. | The helper still has powerful administrative authority inside that boundary. |

A separate Go helper made these checks independently testable during local development.
It avoided granting the server Admin socket to every node.
It did not replace SPIRE or create a new certificate authority.
SPIRE still performs attestation and certificate issuance.

This placement also adds a build, image, configuration and availability dependency.
The experiment must justify those costs before permanent adoption.
Enhancing Cilium's existing registrar could provide the same lifecycle checks without a second registration owner.
The tested mechanisms can inform that implementation.
A separate component is not required merely because we wrote one.

## Original baseline and later change

The [implementation plan](docs/architecture/IMPLEMENTATION_PLAN.md) states both reuse requirements:

- PR 3: reuse Cilium's Hive enrollment and ZDS inventory; do not copy its reconciler into CMTC.
- PR 4: reuse Cilium SPIRE namespace/service-account enrollment and prove ztunnel credential delivery.

[ADR-005](docs/architecture/adr/ADR-005.md) also identifies duplicate enrollment authority as a design risk.
These requirements remain the starting point for the production decision.

The reviewed Cilium fork already has an operator-side SPIRE client and namespace enrollment path.
Its default workload registration selects namespace and service account.
That registration does not contain the experimental helper's complete Pod and agent incarnation binding.
This is a source finding about the reviewed fork, not a claim about every Cilium version.

The later experiment tests exact registrations inside the SPIRE server Pod.
It adds Pod UID selection, node and agent incarnation binding, bounded entry lifetimes, and exact readback.
Server-local placement keeps the server Admin socket inside that Pod.
It also adds another image, controller, configuration, and registration authority boundary.
These costs require an explicit architecture decision.

The fork's experimental `externalExactRegistrar` switch disables its legacy SPIRE management and broad namespace registration.
The switch does not qualify the replacement registrar.
It must not enable a second writer for the same registrations.
The switch is on in both lab clusters; no permanent replacement writer is deployed.

## Component roles

| Component | Responsibility | Registration and traffic boundary |
| --- | --- | --- |
| CMTC operator | Evaluate namespace intent, exclusions, platform constraints, and available evidence. | A desired label does not prove enrollment or protection. |
| CMTC node DaemonSet | Collect node observations and run the observe-only eBPF measurement plane ([ADR-005](docs/architecture/adr/ADR-005.md)). | It is not the experimental registrar or a second TLS proxy. It never decides a verdict; production packet enforcement belongs in Cilium. |
| Cilium operator | Own the existing Cilium SPIRE enrollment path under the original baseline. | An enhanced native registrar remains a production option. Exact incarnation behavior still needs implementation and qualification. |
| Cilium node agent | Own endpoint lifecycle, capture, native policy, workload inventory, and delivery to ztunnel. | Capture and xDS acknowledgments remain separate from effective policy and protected traffic. |
| ztunnel | Fetch workload credentials and enforce authenticated workload transport and policy when enabled and qualified. | Native credential delivery does not establish TLS traffic or policy acceptance. |
| SPIRE server | Maintain registration entries and issue SVIDs through the configured trust hierarchy. | Its Admin API changes registration authority. Its private signing material remains inside its approved storage boundary. |
| SPIRE agent | Attest the local node and workload process, then serve permitted credentials. | Its delegated API checks the delegate caller separately from the target workload. |
| Experimental CMTC registrar | Reconcile exact, expiring registration entries through the server-local Admin API. | It runs in the SPIRE server Pod. It does not capture traffic, terminate TLS, or mark workloads `Protected`. |

An SVID is a SPIFFE verifiable identity document.
A registration entry states which attested selectors can obtain an identity.
A registration entry is not an issued SVID.

## Experimental image and placement

The registrar is a separate executable built from this repository.
It is not the existing CMTC node DaemonSet image.
It runs as an additional container in the SPIRE server Pod during the owned fixture.
This container shares the server's private UNIX-domain socket volume.
It uses Kubernetes reads and SPIRE registration RPCs.
The fixture does not export signing keys.

| Pin | Experimental value |
| --- | --- |
| CMTC source | `e39928bc4f79ad6da134e77583945c8e5e9d52bf` |
| Registrar image | `localhost/cmtc-spire-registrar@sha256:f1493a0145d6485d27e668c447c6addbbdafd8179ac7bdc9ee0ea8f000e2e7eb` |
| Image configuration | `1454f25c3d16c77cb9c2618b2cc34878d2e916d60f226cdc90d91259cd017524` |
| Platform | Linux ARM64; built with MacBook Podman |
| Executable | `/cmtc-spire-registrar` |
| Runtime identity | UID1000, GID1000; all Linux capabilities dropped |
| Server Admin socket | `/tmp/spire-server/private/api.sock` inside the SPIRE server Pod |
| Source implementation | [command](cmd/cmtc-spire-registrar/main.go), [planner](internal/spireregistrar/plan.go), [source checks](internal/spireregistrar/source.go), [registration RPCs](internal/spireregistrar/entries.go), [runner](internal/spireregistrar/runner.go) |
| Owned runtime fixture | [qualify_registrar.py](scripts/lab/spire/qualify_registrar.py) |

These pins are those of the 2026-10-25 trial. The helper container was removed after that trial; it does not run now.
Image availability never established runtime acceptance.
The retained [delivery status](docs/agile/DELIVERY_STATUS.md) records source tests and current runtime gates.

## Two different Admin sockets

| Endpoint | Location and caller | Authority and current state |
| --- | --- | --- |
| SPIRE server Admin socket | Private volume inside the server Pod; experimental registrar uses UID1000. | Changes server registration entries. It is not mounted into ordinary applications or the node proxy. |
| SPIRE agent Admin socket | Node-local agent endpoint, `1000:1000`, mode `0700` directory. The earlier native credential diagnostic used it as UID1000. | Serves Debug, Logger and DelegatedIdentity. Not shared with the production proxy. |
| SPIRE agent DelegatedIdentity-only socket | `/run/cmtc-spire/<cluster>/delegated`; the deployed ztunnel (UID0/GID1337) uses it. Our SPIRE fork, `0f8fe4d681`. | Serves only DelegatedIdentity. Kernel group membership permits the connection; `authorized_delegates` still authorizes each delegate. |
| SPIRE agent Workload socket | Separate agent endpoint for its normal Workload API. | It is distinct from the delegated Admin endpoint. Ordinary applications receive no new socket mounts in this experiment. |

A read-only socket mount still permits RPCs.
Filesystem permissions and SPIRE API authorization are separate checks.

The fixture prepares only a new, empty server socket `emptyDir`.
Kubernetes initially presents its directory as mode `2777` in this fixture.
The init container verifies the exact directory, its owner, and its empty contents.
It rejects a symbolic link.
It then tightens the mode to `0770` before SPIRE starts.
The init container uses UID0 and GID1000 with all Linux capabilities dropped.
It has a read-only root filesystem and disables privilege escalation.
The registrar then runs as UID1000.
The [socket dialer](internal/spireregistrar/socket_linux.go) checks directory and socket permissions and the server's UNIX peer UID.

This server-local initialization does not change the persistent node agent Admin directory.
An earlier proposal would have shared the agent Admin socket with the production UID0/GID1337 proxy.
Automatic approval review rejected it, and it was never applied.
It is superseded by the DelegatedIdentity-only socket above, which gives the proxy delegated credentials without Debug or Logger access.

## Exact registration binding

The helper requires explicit installation pins before it creates entries.
It uses the `kube-system` namespace UID as the local cluster incarnation pin.
It checks approved namespace and service-account UIDs.
It checks the SPIRE agent and delegate DaemonSet UIDs, container names, and pinned images.
It joins each workload to its node and that node's current SPIRE agent Pod.
It rejects ambiguous current agents on one node.
It rechecks source UIDs and resource versions during reconciliation.

The helper creates two entry forms:

| Entry | Binding |
| --- | --- |
| Agent alias | PSAT selectors for cluster name, agent namespace, agent service account, agent Pod UID, node name, and node UID. Its identity includes node UID and agent Pod UID. |
| Workload or delegate | Parent is the exact agent alias. Kubernetes selectors include namespace, service account, Pod UID, and node name. The workload identity uses its namespace and service account; the delegate identity uses `/ztunnel-proxy`. |

Namespace and service-account UIDs are approval and reconciliation pins.
They are not additional workload selectors in the SPIRE entry.
Pod UID is an explicit workload selector.
Node UID is bound through the PSAT agent alias.
Keep these mechanisms distinct when reviewing the identity boundary.

The registration ID includes installation, cluster, namespace, node, agent Pod, target Pod, and role.
A same-name replacement Pod therefore receives a different registration ID.
The helper requests a 120-second X.509 SVID lifetime.
Its entries expire after 90 seconds unless renewed.
An entry expiry does not shorten the lifetime of a previously issued certificate.

The helper reads back identity, selectors, authority fields, and expiry after writes.
It refuses conflicting bindings and foreign cleanup.
Its ownership hint selects its rows inside the trusted server Admin boundary.
That hint is not authorization against another malicious server administrator.

The runner uses a 20-second reconcile deadline and a 10-second retry delay.
Readiness requires a recent exact registration readback.
A failed pass clears readiness and attempts bounded withdrawal of owned rows.
Shutdown also attempts owned withdrawal.
Bounded entry expiry remains a recovery measure when deletion cannot complete.
These controls require runtime failure and restart evidence.

## Current withdrawal finding

The corrected eighth trial passes in both clusters. All four target Pods return explicit empty/unusable SVID responses while authorized same-node controls succeed before and after. Reenrollment, Pod replacement, server restart and exact cleanup pass. The final 36-path application test passes. [Actual output](docs/evidence/exact-spire-registration/summary.json) is retained. This proves the bounded credential lifecycle, not certificate revocation or traffic policy.

### Earlier failed trial

The seventh owned runtime trial created six exact entries per cluster.
These were two agent aliases, two delegates, and two workloads.
Real native SVID fetches passed before namespace enrollment removal.
After removal, exact server readback showed the four remaining non-workload entries.
This proved server registration withdrawal for the owned workloads.
It did not prove immediate agent-cache convergence or traffic revocation.

The trial remained unqualified.
On `cmtc-b`, two fresh requests first returned cached SVIDs.
The next request exceeded the native credential deadline.
The harness correctly rejected that timeout as denial evidence.
The retained report is `/private/tmp/cmtc-exact-registrar-runtime-seventh-20261025/report.json`.
It records `qualified: false` and `withdrawal failed for an unrelated reason`.

Source review found an error-handling defect in the ztunnel credential client.
The resolved Rust dependencies are `spire-api 0.3.9` and `spiffe 0.7.4`.
The SDK returns `EmptyResponse` when its response contains no usable default SVID.
The ztunnel client logged that stream error and continued waiting.
An explicit empty response could therefore become a timeout.
The same loop could accept a later certificate after an earlier stream error.

The tested source correction makes the first stream error terminate that credential request.
It preserves separate setup, empty-response, stream-end, and deadline errors.
Tests must reject an error followed by a certificate on the same stream.
Tests must allow recovery through a fresh, fully attested request.
The correction is committed at `75843515d549f7928d080801ac3f7e4344f572eb`. It passes 568 full-profile tests plus two diagnostic cases, formatting and strict Clippy. [Raw source evidence](docs/evidence/spire-stream-errors/summary.json) is retained. The deployed ztunnel build (`f221f29b59`) descends from that commit; no live stream-error test has run on it.
That seventh trial remains failed evidence. The corrected eighth trial has its own source, image, controls and passing result above.

The earlier interpretation of `PermissionDenied: no identity issued` also needs correction.
In the reviewed SPIRE delegated service, that error comes from delegate caller authorization.
It does not identify target workload withdrawal by itself.
An authorized delegate can instead receive an empty target SVID response.
The SPIRE service keeps that subscription open.
The SDK also uses `EmptyResponse` for a missing nested SVID object.
Describe this as an empty or unusable SVID response; do not invent a more specific wire result.

| Observation | Evidence meaning |
| --- | --- |
| Exact server entry absent | The server registration row is withdrawn. Agent state may still lag. |
| Fresh valid SVID | The target can still obtain a credential at that observation time. Record propagation and keep the gate open. |
| Explicit empty or unusable SVID response | The fetch supplied no usable credential. Verify a valid delegate control before attributing this to target withdrawal. |
| `PermissionDenied` for the delegate | The caller cannot use the delegated API. Investigate caller registration and authorization separately. |
| Timeout, unavailable service, or CRI failure | The observation failed or is inconclusive. It does not prove authorization denial. |
| Successful fresh fetch after reenrollment | Credential delivery recovered. It does not prove existing-flow revocation or TLS policy. |

Fresh requests may retry within a fixed propagation budget.
Each retry must recheck the same live workload and probe incarnations.
Command time and sleep time must remain inside that budget.
A timeout contributes no denial evidence, even if a later request supplies explicit evidence.

## Registration ownership options

| Option | Benefit | Required work and limitation |
| --- | --- | --- |
| Retain the experimental server-local helper | Reuses the implemented exact-entry checks and private server Admin placement. | Adds a separate CMTC image and authority owner. Complete runtime qualification and record explicit architecture approval before production adoption. |
| Enhance Cilium's native registrar | Preserves the original reuse direction and existing enrollment ownership. | Port and qualify exact Pod, namespace, service-account, node, and agent binding. Review bootstrap authority, expiry, withdrawal, restart, and migration. Existing broad entries cannot remain as an alternate entitlement. |
| Evaluate SPIRE controller-manager | Provides another candidate for investigation. | Capability, version, selectors, trust boundary, lifecycle, and deployment fit are unverified here. No compatibility or security claim is made. |

The native Cilium enhancement is the baseline option for production review.
The helper can remain a bounded experiment while that review proceeds.
A successful experiment supplies evidence for the decision; it does not select the owner automatically.
Any migration must define one authoritative writer and remove obsolete broad entitlement safely.

## Separate security gates

Exact Entry readback proves registration material at the server.
Native SVID validation proves a credential for the requested live process and approved signer.
TLS handshakes prove peer authentication for the measured connection.
Effective policy checks prove authorization for the measured workload and application port.
Packet captures prove transport behavior on the measured path.
Each result has its own source, image, identity, freshness, and failure conditions.

Registration removal stops future issuance after propagation.
It does not revoke an already-issued SVID automatically.
It does not close existing TLS, HBONE, or application streams automatically.
Certificate expiry, revocation information, pooled transports, active-flow drain, and reconnect rejection need separate tests.
No registration or credential result alone establishes `Protected`.

## Acceptance before closing this increment

- [ ] Record the production registration owner decision against the original Cilium reuse baseline.
- [ ] Prevent concurrent legacy and replacement writers or alternate broad entitlement.
- [x] Qualify the source stream correction with error-first, true-timeout, valid-response, process-release, and fresh-request recovery tests.
- [x] Build the exact corrected ARM64 diagnostic with host Podman and verify its source and image on all four nodes.
- [x] Prove target withdrawal with exact entry readback, stable workload UID, explicit credential evidence, and a valid delegate control.
- [x] Prove reenrollment, same-name Pod replacement and server restart in both clusters.
- [ ] Complete dedicated source-read failure and bounded-expiry fault injection.
- [x] Verify cleanup restores exact server templates, preserves signer and PVC identity, and removes only owned fixture objects and entries.
- [x] Give the production proxy delegated credentials without the agent Admin socket: DelegatedIdentity-only socket (SPIRE fork `0f8fe4d681`), deployed. The agent Admin migration is withdrawn.
- [ ] Keep TLS, effective policy, cross-cluster traffic, packet capture, and existing-flow revocation gates open until their own evidence passes. Allow-path traffic now passes; the others remain open ([test matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md)).
