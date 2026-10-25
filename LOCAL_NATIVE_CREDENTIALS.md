# Local native workload credentials

The native credential path now works on all four nodes in `cmtc-a` and `cmtc-b`.
A trusted node probe fetches a workload SVID through the real ztunnel CRI and SPIRE client.
The application has no sidecar, node socket mount or private-key file.

This test proves credential delivery. It does not prove workload traffic encryption, authorization or `Protected` status.
The combined ClusterMesh/ztunnel guard remains closed.

## Source and image

| Item | Qualified value |
| --- | --- |
| Diagnostic source | ztunnel `3b1a6a9e8fa3fcc9d3de499835feeafc0e735d39` |
| Diagnostic image | `localhost/cmtc-spire-workload-check@sha256:081b2dabeef4548673e9d8a68e98dfd1aec19ccc55c8a60f182af2fc660b7394` |
| Image configuration | `sha256:6f4f445e01d3f06d003a94f5904a33c11bce25dd29fd219f474e8035b1b8f87c` |
| Platform | Linux ARM64 |
| SPIRE server and agent source | `28f6b8d84ade21c6accb32ba9689a3bdf64877ec` |
| Build engine | MacBook Podman, connection `cmtc-ubuntu-build` |
| Cluster engine | Existing Colima `cmtc-cilium` and kind |

[The evidence index](docs/evidence/spire-native-credentials/summary.json) records commands, results, failures, source pins and cleanup.
The diagnostic image contains no proxy listeners.
Its `fetch` command emits public certificates only.
Its `version` command reports the exact clean source revision.

## Credential checks

1. The runner checks the cluster UID and node UID.
2. The runner checks the probe image and running container incarnation.
3. The runner checks the exact SPIRE registration.
4. The native CRI client finds the target Pod UID on the local node.
5. The process binder holds a pidfd for that exact container process.
6. The binder checks the kernel Pod UID and container cgroup.
7. SPIRE attests that PID through its verified kubelet connection.
8. The native client fetches the SVID and trust bundle.
9. The client rechecks the held process and CRI identity.
10. The host verifies the public leaf signature, exact SPIFFE URI, validity and current approved SPIRE signer.

The pidfd stays open through attestation and bundle delivery.
A reused PID cannot replace the original process.
A remote Pod UID cannot use a local process as its delegate.

The SPIFFE identity contains the cluster-specific trust domain, namespace and service account.
The registration also selects the actual Pod UID and node name.
A replacement Pod with the same name and service account needs a new registration.

## Local build and import

The [recorded build script](docs/evidence/spire-native-credentials/image/build.sh) uses the pinned Rust builder and runtime base.
It rejects a dirty source tree.
It compiles the diagnostic example with `--locked` and records the binary hash.
It builds with `--platform linux/arm64`.
It saves a Docker archive with the host Podman CLI.

The runner loads the archive into both existing kind clusters.
It checks the configuration ID, architecture and binary revision on each node.
Archive import initially reused different compressed base-layer representations on workers and control planes.
The configuration ID and binary were equal, but the manifest digests differed.
The runner exported one verified canonical OCI manifest and loaded it on all four nodes.
It then verified the actual manifest bytes and configuration on every node.
No registry publication or unrelated image deletion was needed.

The recorded scripts contain exact paths and ownership pins from this run.
They are execution evidence. Do not reset an existing ledger to rerun them.

## Probe privileges

The temporary probe runs with host PID visibility, UID1000 and GID0.
It drops all Linux capabilities.
It has a read-only root filesystem and no Kubernetes API token.
Its working directory is `/`.
The distroless image's default `/home/nonroot` directory is not accessible to UID1000.

UID1000 can traverse SPIRE's private socket directory.
GID0 can connect to the node CRI socket.
These are trusted node privileges. A read-only socket mount still permits RPC.
Ordinary applications receive neither socket.

This probe configuration does not qualify the production proxy's socket permissions.
The production root/GID1337 proxy still needs a narrow, tested socket access configuration.
Do not add DAC capabilities or widen directories to bypass that gate.

## Failure and recovery evidence

| Test | Observed result |
| --- | --- |
| Existing workload on each node | Exact current-signer SVID verified on all four nodes |
| Wrong service account or namespace | Native identity mismatch |
| Wrong trust domain | Explicit local-domain configuration rejection |
| Missing or cross-node Pod UID | Local CRI lookup rejected |
| Unregistered delegate | SPIRE `PermissionDenied` |
| Unregistered workload | No SVID before the bounded native deadline |
| Deleted Pod and same-name replacement | Old UID rejected; replacement needs its own registration |
| Workload registration removal | Fresh credential requests stop; exact re-registration restores delivery |
| Delegate registration removal | `PermissionDenied`; exact re-registration restores delivery |
| SPIRE agent restart | Fresh native SVID verified after each of four node restarts |
| Wrong kubelet CA | Actual x509 attestation failure; no SVID; approved-template restoration recovers delivery |

The runner records propagation separately from permanent denial.
Positive registration waits have five attempts with capped backoff and a 60-second retry-admission window.
Each API and RPC also has its own timeout.
Only the explicit SPIRE no-identity response can retry.
Process, TLS, structural and signer failures remain fatal.
The logs contain the stage, attempt, elapsed time, backoff and underlying public error.
The first short retry budget expired in one cluster; the failure is retained.

Removing a registration is a fresh-credential test.
It does not revoke an already-issued certificate or drain an existing TLS connection.
Those remain separate acceptance gates.

The wrong-CA test changes only a task-owned public ConfigMap reference.
It restores the exact original DaemonSet template.
It changes no kubelet certificate, node network file, signer or PVC.

## Next dependency

Complete authenticated native remote workload and policy delivery.
Bind policy and source-IP checks to actual kernel state and retained workload capture.
Qualify the production proxy socket permissions.
Then build the exact Cilium and ztunnel images and test real cross-cluster positive, negative and recovery traffic.
Keep workload mTLS and WireGuard/IPsec evidence separate.
