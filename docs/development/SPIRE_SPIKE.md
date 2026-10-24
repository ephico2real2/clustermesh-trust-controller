# Isolated SPIRE workload mTLS spike

This is CMTC-101's single-cluster, cross-node credential/traffic fixture. It does
not establish ClusterMesh compatibility, authorization, fail-closed protection,
WireGuard/IPsec composition or a `Protected` status. The normal Observe lab and
its pinned image bundle remain the regression baseline.

## Local results — 2026-10-23

The two-node `cmtc-mtls` kind fixture runs the Cilium agent from source
`0d787e82f2a54b0f51eec97a39c24556dd3596d5`, Cilium ztunnel v1.0.0 from
`5bb9cf256b10a209ae9bc0624ddfbf27dbc439de`, SPIRE 1.15.5 and cert-manager 1.21.1.
The initial operator is the existing qualified fork image from `42f89f83`.
The new operator retry/ACK/logging slice is source
`d8124529b590bfb24adbd3d2916a4a984b666f9e`; its image/runtime qualification is a
separate step and must not be attributed to the earlier traffic trial.

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
