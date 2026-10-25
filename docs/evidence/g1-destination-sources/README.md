# Source egress delivered to the destination (G1, ADR-010) — live traffic, 2026-10-25

**Result:** with the Cilium agents at `6090aa6eff`, enrolled workload traffic runs over workload mTLS through
ztunnel:
- same node, across nodes and across clusters, in both directions, on ports 80, 8080 and 31337;
- the Global Service by ClusterIP.

**Per-connection evidence:**
- Every allowed Pod-IP probe (48 of 48) is joined to one ztunnel connection. Both ztunnels logged it, it used HBONE
  port 15008, and the server-side ztunnel read the expected client SPIFFE ID from the client certificate.
- All 72 fixture connections in the 23:00–23:13Z logs have these properties.
- The unregistered callers got no response (12 of 12), and no ztunnel logged them.

**Still broken:** DNS from enrolled Pods, and with it the Global Service by name. The failure is diagnosed; the fix is
in progress (see [Open](#open)).

Scope: this record covers the recorded source, images and fixture only. It is not a `Protected` claim.
- It shows traffic outcomes, per-connection peer identities and the agents' admission state.
- It does not show recovery, explicit native drop events for the negative probes, or WireGuard/IPsec.

Current pins and open gates are in [delivery status](../../agile/DELIVERY_STATUS.md). The design is in
[ADR-010](../../architecture/adr/ADR-010.md). How the evidence was made, and how to repeat it, is in the tutorial
[Prove mTLS for each request from ztunnel logs](PROVE_MTLS_FROM_ZTUNNEL_LOGS.md).

## Pins

| Component | Source | Deployed image |
|---|---|---|
| Cilium agent | fork `feat/opus-mesh-mtls-finalization` at `6090aa6eff` | `localhost/cilium:dev-overlay-6090aa6eff`, image ID `f913c79d6bfe` on all four nodes |
| ztunnel | fork at `f221f29b59` | `localhost/cmtc-ztunnel:native-f221f29b59` (`sha256:5cf97f91…`) |
| SPIRE node agent | fork at `0f8fe4d681` | `localhost/cmtc-spire-agent:delegated-0f8fe4d681` |

Clusters: `kind-cmtc-a` (kube-system UID `bb7182c7-de95-4e70-816a-a1400d755794`) and `kind-cmtc-b`
(`f2687af6-bd96-45a3-98a2-d1397a3ee244`). Trust domains: `cmtc-a.mesh.example` and `cmtc-b.mesh.example`.

The fixture:
- **Enrolled namespace `cmtc-live-mtls`:** two clients (service account `mesh-client`) and two servers
  (`rebel-base`) per cluster, one of each per node.
- **Negative namespace `cmtc-live-mtls-unauth`:** two unregistered callers per cluster.
- **Pod map:** [`fixture-pods.txt`](fixture-pods.txt), read 23:23:09Z.
- **Policy:** no CiliumNetworkPolicy applies, so both native maps allow all peers.

## Why ports 80, 8080 and 31337

The fixture servers run the sample app `mesh-example/rebel-base` (commit `dd6a68a`, 2026-10-24). Its nginx listens on
exactly these three ports (`examples/apps/clustermesh/backend-poc1.yaml:23-25`). No document records why these three
were chosen. Each one tests something different:
- **80:** a privileged, well-known port (below 1024).
- **8080:** a typical unprivileged application port.
- **31337:** a high port inside the NodePort range (30000–32767). Traffic to a Pod IP on this port must not be
  handled as a NodePort under kube-proxy replacement.

With HBONE, the outer port is always 15008 and the original port travels inside the tunnel (`dst.hbone_addr`). The
destination's policy plan holds rules per port. Three ports show that each port is carried and kept, not only the
first.

## Procedure

1. **Baseline.** At 22:57Z, with agents at `6a00282808`, probe same-node, cross-node and cross-cluster.
2. **Build.** Build the agent overlay from `6090aa6eff` with host Podman. Import it into all four nodes and verify the
   image ID on each.
3. **Roll.** Set the image on both `cilium` DaemonSets (OnDelete) and replace the agents one at a time:
   - started 22:58Z;
   - each agent Ready in 13–15 s.
4. **Admission check.** Read each agent's `cilium_ztunnel_xds_effective_policy_sources` gauge and its admission logs.
5. **Matrix.** Run the fixture runner per scope (`live_mtls_fixture_runner.py probe --scope <scope>`); each scope
   stops at its first failure.
6. **No-DNS and DNS checks.** Probe the Global Services by ClusterIP, then compare DNS from enrolled and unenrolled
   Pods.
7. **Per-connection evidence (23:23–23:35Z).** Extract the ztunnel logs of all four nodes for 23:00–23:13Z, write the
   Pod map, view the logs and join every probe. The commands are in the
   [tutorial](PROVE_MTLS_FROM_ZTUNNEL_LOGS.md#try-it-on-this-folder).

## Results

**Before** (agents `6a00282808`):

| Scope | Result | File |
|---|---|---|
| cmtc-a same node | 6/6 allowed | `probes/cmtc-a-20261025T225746946707Z-probe-same-allow.json` |
| cmtc-a cross node | reset, curl rc 56 | `probes/cmtc-a-20261025T225747583271Z-probe-crossnode-allow.json` |
| cmtc-a cross cluster | reset, curl rc 56 | `probes/cmtc-a-20261025T225747842667Z-probe-crosscluster-allow.json` |

**After** (agents `6090aa6eff`, 23:00–23:01Z):

| From | Same node | Cross node | Cross cluster (Pod IP) | Global Service by name | Unregistered caller |
|---|---|---|---|---|---|
| cmtc-a | 6/6 mTLS proven | 6/6 mTLS proven | 12/12 mTLS proven | failed: curl exit 28 (DNS) | 6/6 no response, no ztunnel line |
| cmtc-b | 6/6 mTLS proven | 6/6 mTLS proven | 12/12 mTLS proven | failed: curl exit 28 (DNS) | 6/6 no response, no ztunnel line |

- "mTLS proven" is the join verdict: both ztunnel lines, HBONE port 15008, and the expected peer and destination
  SPIFFE IDs. Each allowed reply also named the expected serving cluster.
- The negative probes ended in a curl connect timeout (exit 28). The native drop events of these flows were not
  recorded, so this record does not show which component dropped them.
- Row files are in `probes/`. Every verdict, with its two log lines, is in [`join.json`](join.json).

**Global Service by ClusterIP**, recorded at 23:10:33Z in [clusterip-dns-gauges.txt](clusterip-dns-gauges.txt):
- 12/12 allowed, every reply from the expected cluster;
- all 12 connections (23:10:33–34Z) are in the ztunnel logs, over HBONE with the expected peer identity.

**DNS**, in the same file:
- from enrolled `client-worker`: "no servers could be reached", in both clusters;
- from unenrolled Pods: resolves, in both clusters.

**Source admission:**
- Gauges read node=2, cluster=2, peer=4 on all four agents.
- By 23:00:08Z each destination plan had 7 rules, one per admitted caller. No plan was republished afterwards.

### Per-connection evidence from the ztunnel logs

`scripts/evidence/ztunnel_log_view.py ztunnel-access/*.log` reports:

| Measure | Value |
|---|---|
| Log coverage | 23:00:00–23:13:00Z on all four nodes; extracts in [`ztunnel-access/`](ztunnel-access/) |
| Fixture connections | 72; every one over HBONE port 15008 |
| Seen by both ztunnels | 72 of 72 |
| Peer identity read from the client certificate, equal to the client's identity | 72 of 72 |
| `allow policy match` on the server side | 72 of 72. Each server matched its own effective policy: `cilium_l4_effective_fbee11ea…` (cmtc-a/server-worker), `ebbea754…` (cmtc-a/server-control-plane), `8c6eef8c…` (cmtc-b/server-worker), `67aaedf0…` (cmtc-b/server-control-plane) |
| Peer identities | `mesh-client@cmtc-a.mesh.example` 36, `mesh-client@cmtc-b.mesh.example` 36; each accepted by all four servers |

The 72 connections are:
- 24 from the cmtc-a matrix (23:00:41–43Z);
- 24 from the cmtc-b matrix (23:01:05–07Z);
- 12 at 23:01:51–52Z from both `client-worker` Pods. No probe file records this burst. Its shape matches the ClusterIP
  check (3 ports × 2 Services per cluster);
- 12 from the ClusterIP check (23:10:33–34Z).

### Observations not yet explained

- **HBONE handshake errors on the client side.** There are 24 lines of `Error in HBONE connection handshake:
  PermissionDenied, "authenticated issuer profile/session expired or changed"`, between 23:01:54Z and 23:12:22Z.
  - **Where:** `client-worker` on both worker nodes (8 each) and `client-control-plane` on both control-plane nodes
    (4 each).
  - **When:** every timestamp is within 2 ms after a whole second. Each group comes 3 s to 2 min after a burst of
    probe traffic.
  - **Effect:** no probe failed because of them. The 23:10:33Z probes passed.
  - The cause is not diagnosed.
- **Log rotation.** Kubelet rotated the control-plane ztunnel logs at 23:02:30Z (cmtc-b) and 23:02:51Z (cmtc-a), so
  `kubectl logs` no longer returned the 23:00Z matrix. The extracts were read from the node's `/var/log/pods` files
  instead.

## Open

- **DNS from enrolled Pods** is diagnosed. `cilium-dbg monitor` on cmtc-a-worker shows the query dropped at the
  source endpoint's egress:
  `drop (Policy denied) … file bpf_lxc.c:1626, identity 69042->66322: 10.10.1.205:46029 -> 10.10.0.193:53 udp`.
  - The native HBONE-only gate (`bpf/lib/ztunnel_admission.h`) passes only TCP/15008 and has no resolver exception.
  - The fix is in progress; it is not part of this record.
- **Recovery on `6090aa6eff`:** agent restart, ztunnel restart, node reboot, drain, lost ACK.
- **Explicit native drop events** for the negative probes.
- **The client-side handshake errors** above.
- **Policy shapes:** a source whose egress denies the destination, and a live port narrowing. Both are unit-tested only.
- **WireGuard/IPsec composition.**
- **The ADR-010 review findings:** see delivery status.
