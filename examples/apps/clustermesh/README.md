# Bidirectional ClusterMesh sample

The sample runs the same `rebel-base` application in both clusters. Each
backend returns its cluster name, and each global Service selects exactly one
cluster's backend. This makes the direction of a cross-cluster request visible
in terminal output and retained CI artifacts.

The lab applies `global-service.yaml` and `client.yaml` in both `mesh-example`
namespaces, `backend-poc1.yaml` only in `cmtc-a`, and `backend-poc2.yaml` only in
`cmtc-b`. It checks local and remote Global Service calls from clients in both
clusters on TCP/80, TCP/8080 and TCP/31337, plus direct cross-cluster Pod-IP
calls on all three ports:

| Client cluster | Service | Expected response |
| --- | --- | --- |
| `cmtc-a` | `rebel-base-cmtc-a` | `cmtc-a` |
| `cmtc-a` | `rebel-base-cmtc-b` | `cmtc-b` |
| `cmtc-b` | `rebel-base-cmtc-b` | `cmtc-b` |
| `cmtc-b` | `rebel-base-cmtc-a` | `cmtc-a` |

`scripts/lab/test.sh` checks the serving-cluster response for every path before
the load phase. Port 31337 is an arbitrary high-port probe, not a required port
list for mTLS enforcement.
`scripts/lab/load.sh start` runs six-minute local shop loads and cross-cluster
service loads in both directions on TCP/80, 8080 and 31337. Every run gets
unique Job names and an immutable `artifacts/load/<run-id>/` evidence directory;
`collect` retains each Fortio log and JSON result. Take Grafana and browser
screenshots after the load is active using the configured capture workflow, and
retain them beside that run's query evidence.

This is ClusterMesh reachability evidence in the current Observe profile. That
profile still disables ztunnel encryption. The user's enhanced
`ephico2real2/cilium` fork is the intended data plane, but the current source
still retains the ClusterMesh/ztunnel compatibility guard and has not yet
qualified remote workload discovery or effective policy. The same workloads
and service identities are intended for that profile; it must also verify
SPIFFE identities, both cross-cluster directions, unauthenticated and
unauthorized negative cases, encrypted inter-node packets and real traffic
metrics before it can claim end-to-end mTLS.
