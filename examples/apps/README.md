# Reused demo applications

Copied from the user's [cilium-implementation-poc](https://github.com/ephico2real2/cilium-implementation-poc/tree/22fb6e14c0cca8c78af1f072d1e89ebaea6a916b), commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`:

| Local example | Original | Purpose |
|---|---|---|
| `clustermesh/global-service.yaml`, `backend-poc1.yaml`, `backend-poc2.yaml` | `demos/07-clustermesh/` | Nginx global service returns its serving cluster in JSON. |
| `shop/10-lab.yaml` | `demos/26-cf2cnp-policy-from-flows/10-lab.yaml` | Shop server, authorized POS and unauthorized stranger clients. |

The four copied manifests retain their original contents. `shop/20-allow-pos.yaml` is a CMTC adaptation that enforces the expected TCP/80 caller. The CI test applies it in each cluster and requires POS success plus stranger denial. CI uses the cluster-2 backend only for the global service; its original payload says `poc2`, proving that the response came from the imported remote backend. The CI cluster names are `cmtc-a` and `cmtc-b`.

Manual use on disposable Cilium clusters:

```sh
kubectl --context kind-cmtc-a apply -f examples/apps/shop
kubectl --context kind-cmtc-b apply -f examples/apps/shop
kubectl --context kind-cmtc-a create namespace mesh-example
kubectl --context kind-cmtc-b create namespace mesh-example
kubectl --context kind-cmtc-a -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml
kubectl --context kind-cmtc-b -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml -f examples/apps/clustermesh/backend-poc2.yaml
```

These examples exercise Cilium networking/policy and provide real application screenshots. The initial CMTC Observe build evaluates their namespace metadata and inventories pods; it does not enable ztunnel or establish workload mTLS. See `scripts/lab/test.sh` for failing assertions and the [lab runbook](../../docs/development/OBSERVE_LAB.md) for the complete evidence workflow. No production credentials or signing keys are included.
