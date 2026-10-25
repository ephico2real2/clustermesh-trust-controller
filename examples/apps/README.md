# Reused demo applications

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Copied from the user's [cilium-implementation-poc](https://github.com/ephico2real2/cilium-implementation-poc/tree/22fb6e14c0cca8c78af1f072d1e89ebaea6a916b), commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`:

| Local example | Original | Purpose |
|---|---|---|
| `clustermesh/` | `demos/07-clustermesh/` | The same Nginx application and a client run in both clusters; two global services make each cross-cluster direction explicit. |
| `shop/10-lab.yaml` | `demos/26-cf2cnp-policy-from-flows/10-lab.yaml` | Shop server, authorized POS and unauthorized stranger clients. |

The sample manifests are adapted to the CMTC cluster names and include explicit backend identities and service accounts. `shop/20-allow-pos.yaml` is a CMTC adaptation that enforces the expected TCP/80 caller. The CI test applies it in each cluster and requires POS success plus stranger denial. It verifies local and remote global-service requests in both directions; each backend returns its cluster name. The CI cluster names are `cmtc-a` and `cmtc-b`.

Manual use on disposable Cilium clusters:

```sh
kubectl --context kind-cmtc-a apply -f examples/apps/shop
kubectl --context kind-cmtc-b apply -f examples/apps/shop
kubectl --context kind-cmtc-a create namespace mesh-example
kubectl --context kind-cmtc-b create namespace mesh-example
kubectl --context kind-cmtc-a -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml
kubectl --context kind-cmtc-b -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml
kubectl --context kind-cmtc-a -n mesh-example apply -f examples/apps/clustermesh/backend-poc1.yaml -f examples/apps/clustermesh/client.yaml
kubectl --context kind-cmtc-b -n mesh-example apply -f examples/apps/clustermesh/backend-poc2.yaml -f examples/apps/clustermesh/client.yaml
```

These examples exercise Cilium ClusterMesh routing and policy and provide real application screenshots. The current CMTC Observe profile evaluates their namespace metadata and inventories pods; it does not enable ztunnel or establish workload mTLS. See [the ClusterMesh example contract](clustermesh/README.md), `scripts/lab/test.sh` for failing assertions and the [lab runbook](../../docs/development/OBSERVE_LAB.md) for the complete evidence workflow. No production credentials or signing keys are included.

## Current local demonstration

Both retained clusters run `rebel-base` (two replicas, one on each node),
`mesh-client`, and the shop/POS/stranger example. Backend responses identify the
cluster in JSON and the serving Pod in `X-CMTC-Pod`. Required anti-affinity plus
an explicit lab control-plane toleration makes cross-node testing repeatable;
`maxSurge: 0`/`maxUnavailable: 1` avoids a rolling-update scheduling deadlock on
the two-node fixture.

Local loopback forwards for the current session:

| Sample | cmtc-a | cmtc-b |
| --- | --- | --- |
| Cluster-identifying backend API | <http://127.0.0.1:18080> | <http://127.0.0.1:18081> |
| Shop HTTP server | <http://127.0.0.1:18082> | <http://127.0.0.1:18083> |

To recreate the forwards, use separate terminals:

```sh
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
kubectl --context kind-cmtc-a -n mesh-example port-forward --address=127.0.0.1 svc/rebel-base-cmtc-a 18080:80
kubectl --context kind-cmtc-b -n mesh-example port-forward --address=127.0.0.1 svc/rebel-base-cmtc-b 18081:80
kubectl --context kind-cmtc-a -n cf2cnp-lab port-forward --address=127.0.0.1 svc/shop 18082:80
kubectl --context kind-cmtc-b -n cf2cnp-lab port-forward --address=127.0.0.1 svc/shop 18083:80
```

A port-forward is a browsing convenience and does not prove ClusterMesh or mTLS.
`scripts/lab/test.sh` performs the real in-cluster tests: 12 Service assertions
and 24 direct Pod-IP assertions across every local/remote backend and port
80/8080/31337. It first verifies two ready backend Pods on distinct nodes in
each cluster, and checks the intended Pod's response header for direct requests.
The existing Observe/API, exclusion, conflict, namespace recreation, RBAC and
shop allow/deny assertions still run. The latest topology update passed all
36 paths; workload encryption remains an unfinished security gate.
