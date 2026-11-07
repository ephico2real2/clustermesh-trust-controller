# Strict ZDS PID namespace recovery

Recorded 2026-10-25. The user explicitly approved host PID namespaces on both
Cilium agent DaemonSets. Cilium source: `51170b123988cda86aaea1bef3ccd95d221b8bbb`.
Ztunnel source: `35a6c9403eb5c00b1b79aafe2851f423cd195540`.

The original configuration had node ztunnel in the host PID namespace and the
Cilium agent in a private PID namespace. Strict ZDS rejected the peer with
`strict ZDS drain requires a root-owned local proxy process`.

After setting agent `hostPID: true` and replacing agents one node at a time,
all four agents and all four proxies were Ready. The JSON receipts contain Pod
UIDs, node names, hostPID values, running image IDs and restart counts. Log
extracts record V2_DRAIN and initial snapshot delivery where retained. The
root-ownership check was not changed. No proxy restart or checkpoint reset was
used for this correction.

## Remaining errors

The subsequent `clustermesh-runtime-check.json` records remote readiness 0/1,
despite connected etcd and synchronized remote resource inventory. Recent logs
also report membership writer lock timeouts and native ZDS ownership busy
errors during endpoint regeneration. These are open failures. Pod readiness
does not qualify healthy ClusterMesh or end-to-end workload mTLS.

See [installation requirements](../../../INSTALLATION_REQUIREMENTS.md) for the
manifest patch and checks. The operational source-chart audit also rendered
`--set hostPID=true` at the recorded Cilium revision: the agent field remained
absent, while the SPIRE-backed proxy field was true. A chart fix is required.
