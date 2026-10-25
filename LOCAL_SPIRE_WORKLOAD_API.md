# Local SPIRE node APIs

Both mesh clusters now run the current SPIRE agent fork on all four nodes.
Each agent exposes a separate Workload API socket and Admin API socket.
The agent verifies the kubelet certificate against the approved per-node CA and the exact node DNS name.
Applications have no sidecars, socket mounts or private-key files.

This increment enables the node APIs. It does not prove workload SVID delivery or workload mTLS.
[The deployment ledger](docs/evidence/spire-workload-api/summary.json) records that boundary.

## Exact runtime

| Item | Value |
| --- | --- |
| Source | `28f6b8d84ade21c6accb32ba9689a3bdf64877ec` |
| Image | `localhost/cmtc-spire-agent@sha256:bf2286fb7a93084ebd17128d629e1b12715722c30d37e430ac922b0503219078` |
| Configuration ID | `sha256:707fcee4feff6cfc29478b7fbb86b4ad2a592784659b2b77c67b07fec53d0ff6` |
| Platform | Linux ARM64 |
| Build | Host Podman, explicit `cmtc-ubuntu-build` connection |
| Runtime | Existing Colima `cmtc-cilium`, kind `cmtc-a` and `cmtc-b` |

The source starts from current upstream main. The [SPIRE PKI guide](LOCAL_SPIRE_PKI.md) records the fork and server recovery fix.
The new agent uses the hardened kernel-cgroup container locator.
The older agent could use workload-controlled mount information as a fallback.

## Build and import

[The exact build script](docs/evidence/spire-workload-api/build-agent.sh) compiles a static agent from the clean source commit.
It uses the pinned musl builder and the pinned agent runtime base.
It records the binary version, image configuration and archive hash.

[The import script](docs/evidence/spire-workload-api/load-and-verify.py) loads that archive into each existing kind cluster.
Restricted version Jobs verify the source and running image on every node.
The runner removes only its Jobs, with exact UID and resourceVersion preconditions.
[The canonical pin step](docs/evidence/spire-workload-api/pin-imports.py) verifies the actual containerd manifest bytes and configuration ID.
It creates a canonical manifest reference without replacing an existing image tag.
The synthetic Docker-archive CRI digest is not a usable pull reference.

The recorded scripts contain this lab's paths and ownership pins.
They are execution evidence. Do not rerun the bootstrap against an existing ownership ledger.

## Node identity and kubelet TLS

Each kind node already has a two-certificate public serving chain.
Its leaf contains the node DNS name. It has no IP SAN.
Each node has a distinct serving CA.

The host collects only `/var/lib/kubelet/pki/kubelet.crt` through the independently pinned kind node.
It does not read `kubelet.key` or the combined kubelet client PEM.
The planner verifies the leaf and CA fingerprints, signatures, certificate roles, validity and exact DNS SAN.
It mounts only the approved CA as the agent's trust anchor.

The agent uses `spec.nodeName` as the verified TLS hostname.
Explicit Pod host aliases map that name to the pinned node IP.
`skip_kubelet_verification` is false.
No node certificate, kubelet setting or node network file changes.
A valid renewed leaf from the same CA and DNS name is permitted.
A different CA requires a new explicit public approval.

## Socket and registration boundaries

The host socket parent is `/run/cmtc-spire/<cluster>` on each selected node.
Its separate `agent` and `admin` directories belong to UID/GID1000 with mode0700.
The initializer validates existing directories. It does not adopt or change a foreign directory.
The SPIRE agent remains UID1000.

An ordinary application never receives the Admin API or CRI socket.
A trusted node diagnostic process can receive those sockets to exercise ztunnel's real credential path.
That process is part of the node trust boundary. A read-only socket mount still permits RPC.
Host PID visibility is required for future held-process checks against the host PIDs returned by CRI.
Applications and the CMTC Observe DaemonSet do not gain host PID access.

The [planner](scripts/lab/spire/workload_api.py) produces immutable public configuration, an exact DaemonSet patch and proposed registration commands.
Registration selects the actual namespace, service account, Pod UID and node name.
Only the selected delegate identity is configured as an authorized delegate.
The bootstrap creates no workload registrations and grants no Cilium operator administration.
The real native credential checks remain a separate step.

## Local evidence

The affected agent packages pass170 top-level race tests and373 subtests, with no failures or skips.
Vet passes.
The SPIRE Python suite passes72 cases, including actual loopback TLS rejection for wrong DNS and wrong CA.
These fixture tests do not substitute for a live workload credential test.

Both agent rollouts pass exact image/source checks.
They preserve the Cilium DaemonSet and configuration, SPIRE server template and PVC, actual signing authority, enabled issuer producer and publication UID.
[The public ledger and raw results](docs/evidence/spire-workload-api/summary.json) retain the evidence.
Private keys remain outside the evidence.

Next, verify exact workload registrations and native credential delivery on every node.
Then qualify process incarnation, native remote provenance, effective policy, actual drains and cross-cluster traffic.
Keep the ClusterMesh/ztunnel compatibility guard closed until those gates pass.
