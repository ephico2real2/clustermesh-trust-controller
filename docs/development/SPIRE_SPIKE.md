# Isolated SPIRE workload mTLS spike

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

**Historical record (2026-10-23 to 2026-10-24).** The isolated `cmtc-mtls` fixture is retired. Current work uses
`cmtc-a` and `cmtc-b`; read [delivery status](../agile/DELIVERY_STATUS.md) for current state.

This was CMTC-101's single-cluster, cross-node credential/traffic fixture. It does
not establish ClusterMesh compatibility, authorization, fail-closed protection,
WireGuard/IPsec composition or a `Protected` status. The normal Observe lab and
its pinned image bundle remain the regression baseline.

## Local results — 2026-10-23

The two-node `cmtc-mtls` kind fixture runs the Cilium agent from source
`0d787e82f2a54b0f51eec97a39c24556dd3596d5`, Cilium ztunnel v1.0.0 from
`5bb9cf256b10a209ae9bc0624ddfbf27dbc439de`, SPIRE 1.15.5 and cert-manager 1.21.1.
The first traffic trial used the qualified operator image from `42f89f83`.
Subsequent local tests deployed the Podman-built operator from
`d8124529b590bfb24adbd3d2916a4a984b666f9e` (image config
`aea8a5f923d8ed119b4fc9226a0f3d33452e43f655ca2bed0e498a1973eece24`).
Its authenticated startup ACK and recovery were checked separately from pod readiness.

| Check | Observed result |
| --- | --- |
| External root → cluster issuer → ADS server chain | Verified; test root key removed afterward |
| SPIRE intermediate issuance via cert-manager | Successful; server and both node agents Ready |
| Plaintext control before namespace enrollment | 10/10 requests; canary visible in 20 captured packets |
| Enrolled cross-node positive trial | 10/10 requests; canary absent; 202 HBONE packets |
| TLS packet evidence | 4 handshake-record packets and 136 application-data-record packets, including capture duplication; these are not handshake counts |
| Workload identities | Client/server SPIFFE URI SANs match their distinct service accounts |
| Workload certificate chains | Both verify for TLS client/server use against the external test root |
| Native proxy telemetry | 10 completed connections labeled `connection_security_policy="mutual_tls"`, with the expected source/destination principals |
| Unenrolled source → enrolled destination | **Failed security gate:** plaintext HTTP 200 was accepted |
| Proxy service account creates CertificateRequests | Denied by Kubernetes RBAC |

The plaintext-bypass failure leaves CMTC-403 open. TLS success and a valid common
root do not establish authorization, cluster identity isolation or first-packet
admission. Native TCP connection counters must not be relabeled as TLS handshakes.

SPIRE's pinned server image runs as UID 1000. The inherited root-owned server
socket hostPath prevented its Unix API from starting. The isolated post-renderer
uses a pod-local socket volume and consistent non-root server/sidecar identity.
This fixture override still needs a general Cilium installer fix before that
profile can be qualified independently of the fixture.

## Build and run locally

This section preserves the older isolated fixture. Do not run it against `cmtc-a`
or `cmtc-b`. For the current strict ZDS profile, follow
[installation requirements](../../INSTALLATION_REQUIREMENTS.md): only the
SPIRE-backed node proxy needs the host PID namespace; the Cilium agent must not
have it. Keep the root-owned proxy check and the restricted delegated API socket.

Run `scripts/lab/mtls/build.sh` from the MacBook. It uses Podman, an explicit Linux
architecture, bounded build resources, the committed image source and a Docker
archive for transfer. `CMTC_GO_CACHE` and `CMTC_GO_MOD_CACHE` optionally reuse
compatible host-mounted Go caches. Select another existing Podman connection
with `CMTC_PODMAN_CONNECTION`; preserve other projects' running workloads.

Run the following inside the dedicated Linux kind runtime, with the repository
and archive available there:

```bash
export CILIUM_SOURCE_DIR=/path/to/verified/cilium-spire-source
export CMTC_MTLS_FIXTURE_ARCHIVE=/path/to/cmtc-podman-image.tar
bash scripts/lab/mtls/bootstrap.sh
bash scripts/lab/mtls/enable.sh
kubectl --kubeconfig "$(cat .tmp/mtls-spike/kubeconfig-path)" apply -f scripts/lab/mtls/workloads.yaml
```

Bootstrap refuses to replace an existing `cmtc-mtls` cluster. Issuer and ADS keys
are generated inside their destination cluster; the runner receives public CSRs
only. A temporary external test root signs the cluster issuer, then is removed.
The chain permits root → cluster issuer → SPIRE intermediate → workload SVID.
The post-renderer requires the expected SPIRE resources and configures the
cert-manager UpstreamAuthority without a self-signed fallback.

Record plaintext controls before applying `io.cilium/mtls-enabled=true` to this
fixture namespace. Enrollment, SPIRE registration, SVID validation, xDS ACKs and
traffic evidence are distinct assertions. Keep successful and failed raw results,
source/image pins and public certificates; exclude kubeconfig credentials and
private keys. [Issue #7](https://github.com/ephico2real2/clustermesh-trust-controller/issues/7)
tracks dependency retries, authenticated acknowledgments and structured logging.


## Subsequent local qualification and screenshot

- The SPIRE outage test recorded seven structured retries while the server was
  absent, no false authenticated ACK, and a successful ACK after restoring it.
  Existing Service/Pod-IP load completed 1,200/1,200 HTTP 200 on each path during
  this test. This qualifies the initial operator retry slice, not all of issue #7.
- A fresh five-minute capture run completed **3,000/3,000 HTTP 200 per path**
  (6,000 total), with no application sidecars. Native ztunnel metrics from both
  nodes and positive traffic rates were verified before accepting the PNG.
- The [experimental Grafana view](../../examples/observability/ztunnel-spike/README.md)
  shows actual principals, native TCP opens/bytes and the non-mTLS classification.
  Its Playwright walk passed all nine panels with no `No data`; it visibly keeps
  the failed plaintext gate open. Local URL:
  <http://127.0.0.1:13000/d/cmtc-spire-mtls-spike>.
- The [CNP/CCNP experiment](../research/PLAINTEXT_ENFORCEMENT.md) preserved enrolled
  mTLS and blocked direct HTTP on port 80 using an explicit deny, including both
  tested host sources. Default-deny alone was reopened by an additive allow.
  Temporary rules were removed; general strict admission is still incomplete.

The user confirmed the deployment shape: **CMTC DaemonSet plus node-level
ztunnel; no per-pod sidecars**. CMTC manages and verifies configuration; ztunnel
performs workload TLS. This single-cluster test uses local Kubernetes workload
discovery and does not need ClusterMesh. Remote discovery remains a separate gate.

[Immutable local evidence and screenshot](https://github.com/ephico2real2/clustermesh-trust-controller/blob/ec770d287ea3bd2b81f7f9140f46f401f9e48e47/2026-10-24T0423Z-local-spire-mtls-d8124529/README.md) includes raw load,
query vectors, public certificates, packet captures and all 30 policy observations.


## Native authenticated-only qualification — 2026-10-24

Cilium source `f052d1276b0fb1619809db0059fbbb7898c9cfae` publishes a native
GLOBAL DENY for absent verified TLS principals, without application-port
predicates. It is experimental and defaults off. The isolated Helm revision 5
runs the host-Podman-built ARM64 agent (image config
`0f3a6f60cbb61700e0760536bf7fe0cbe5678a26c2f0e968505ec962a519d8dc`)
on both nodes; actual deployed content, binary version and native policies match.
The unchanged qualified fork runtime/BPF base is reused beneath the new Go agent.

| Check | Observed result |
| --- | --- |
| Steady and post-ztunnel/Cilium restart matrix | 57/57 passed: mTLS via Service/Pod IP on 80/8080/9443 and mapped Service 18080→8080; unenrolled same/cross-node pods and both hosts received no HTTP response |
| Continuous restart probes | 384 during ztunnel restart + 1,014 during Cilium restart; zero unexpected HTTP responses |
| Fresh authenticated load | Service 3,000/3,000 + Pod IP 3,000/3,000 HTTP 200 |
| Fresh unauthenticated load | 900/900 attempts rejected; zero HTTP responses |
| SPIRE outage with operator d8124529 | Six structured retries while unavailable; no false authenticated ACK; ACK after recovery |
| Logger field validation | Retry stage/attempt/elapsed/backoff/deadline/error and ACK fields present |
| Public SVIDs and packet evidence | Expected client/server identities and chains verified; no HTTP canary in capture; TLS application-data records present |
| Grafana 12.2.0 | 12 populated panels in both themes; every query validated; all five pie categories and the full caption fit |

[Immutable raw output, source patch and both-theme screenshots](https://github.com/ephico2real2/clustermesh-trust-controller/blob/1c192a5ee84fb5218cb1385fdd9c5bf45ca69e1a/2026-10-24T0509Z-local-authenticated-only-f052d127/README.md)
retain commands/exit status, load results, retries, native DENY records,
source/image pins, public certificates, PCAP and query vectors. No private keys or
kubeconfig credentials are published. This is local Linux ARM64 qualification;
no new CI or AMD64 success is claimed.

The [authenticated-only Grafana view](http://127.0.0.1:13000/d/cmtc-authenticated-only?from=1792817142251&to=1792817452353)
replays the recorded load window. The user-requested titles distinguish attempts,
actual policy DENY and authenticated TCP starts. Headline counts are reset-aware
selected-range increases; the pie partitions completed destination TCP attempts,
not HTTP requests or TLS handshakes. The independent whole-run HTTP totals above
can differ from the selected-range estimates. The native identity table retains
lifetime counter readings at range end, with overlapping source/destination rows.
Presentation follows the pinned diagram-kit dashboard skill; the complete metric
inventory and validator live beside the JSON.

**CMTC-403 remains open.** These bounded trials close the reproduced tested
plaintext paths with the native rule; they do not establish fresh first-packet
admission, safety while policy is missing, authenticated destination permissions,
platform/probe exceptions, remote identity isolation, ClusterMesh or layered
WireGuard/IPsec qualification. `fullFailClosedProtection` stays false, the API
stays Observe-only and the compatibility guard remains. Issue #7's broader
registration/proxy/recovery and issuer-fault acceptance is also incomplete.
