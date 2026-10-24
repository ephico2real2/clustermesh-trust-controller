# Recreate and recover the persistent Kind ClusterMesh

`cmtc-a` and `cmtc-b` are the only persistent local Kind clusters. Recreate
these two when their state is damaged or when the user explicitly requests a
fresh lab. Use another temporary cluster only for a test that requires a
non-ClusterMesh topology, and delete it when that test is over. Do not create or
depend on a separate `cmtc-mtls` cluster.

The clusters run in Colima profile `cmtc-cilium`, which uses Docker as Kind's
container runtime. Host inspection confirmed Colima 0.10.3 runs this profile on
Ubuntu 24.04.4 LTS. Colima is a higher-level Lima manager that provisions the
Linux guest and container runtime; a direct Lima instance would add guest
provisioning work without changing Kind's per-node IP behavior. Preserve other
Colima profiles and containers, including the existing BuildKit container.

## Why the node addresses are discovered dynamically

Kind's [cluster configuration](https://kind.sigs.k8s.io/docs/user/configuration/)
lets the lab set Pod and Service CIDRs, API server settings and host port
mappings. It does not define a static Docker-network IP for each node. The
container IPs can change when Colima or its Docker network is recreated.

ClusterMesh uses the Cilium API server's NodePort (`32379`) as the peer
endpoint. The lab records the live Docker-network IPv4 address of every control
plane and worker node in both clusters. Advertising all node addresses gives
the peer more than one reachable NodePort endpoint and avoids assuming the
control-plane address stays fixed. The helper is
[`scripts/lab/kind-node-ips.py`](../../scripts/lab/kind-node-ips.py); the
bootstrap stores these address arrays in `.tmp/mesh-values.json`.

This is a local-lab endpoint-discovery strategy. It does not assign static IPs
or change Kind's Docker network. For production ClusterMesh, use stable node
addresses or a stable load balancer as described in the
[Cilium ClusterMesh setup guide](https://docs.cilium.io/en/stable/network/clustermesh/setup/).

Use direct Lima only if a concrete need requires lower-level VM networking or
guest provisioning than this Ubuntu Colima profile provides. Lima's default
network is user-mode; VMNet is an option for host/guest IP reachability, but a
stable guest address still does not pin the Docker IPs of individual Kind nodes.
See the [Colima FAQ](https://github.com/abiosoft/colima/blob/main/docs/FAQ.md)
and [Lima networking guide](https://lima-vm.io/docs/config/network/user/).

## Recover endpoints after a Colima restart

Run from the repository root with the `cmtc-cilium` Docker socket selected and
both clusters present:

```bash
export DOCKER_HOST="unix://$HOME/.colima/cmtc-cilium/docker.sock"
kind get clusters
python3 scripts/lab/kind-node-ips.py cmtc-a
python3 scripts/lab/kind-node-ips.py cmtc-b
bash scripts/lab/reconcile-clustermesh-endpoints.sh
```

The reconciliation helper is deliberately scoped to exactly `cmtc-a` and
`cmtc-b`. It refuses to create a missing cluster or operate on another one. It
compares the discovered addresses with the checked-in lab's generated Helm
values. If they changed, it performs a `helm upgrade --reuse-values` for each
cluster, waits for node, issuer and certificate readiness, and then waits for
both Cilium ClusterMesh links. If an upgrade is interrupted, rerun the helper;
updating both releases from the same generated values is idempotent.

The helper needs `.tmp/cilium-chart-path` and `.tmp/mesh-values.json`, which
`scripts/lab/up.sh` generates during bootstrap. For a one-off recovery against
another values file or a pinned source checkout, set:

```bash
CMTC_MESH_VALUES_PATH=/absolute/path/to/mesh-values.json \
CMTC_CILIUM_CHART_PATH=/absolute/path/to/cilium/install/kubernetes/cilium \
bash scripts/lab/reconcile-clustermesh-endpoints.sh
```

## Recreate only the two persistent clusters

The bootstrap intentionally refuses to replace existing clusters. First
confirm the selected runtime and cluster names, then delete only these exact
two Kind clusters and run the repository bootstrap:

```bash
export DOCKER_HOST="unix://$HOME/.colima/cmtc-cilium/docker.sock"
export KUBECONFIG="$HOME/.kube/config"
kind get clusters
kind delete cluster --name cmtc-a
kind delete cluster --name cmtc-b
bash scripts/lab/up.sh
```

`up.sh` uses the image lock in `config/cilium-images.lock.json`, creates the
two configured Pod/Service CIDR pairs, installs the pinned Cilium chart and
CMTC image, creates the lab certificate chain without placing its root private
key in either cluster, discovers all four node addresses, and configures both
ClusterMesh peer lists. It refuses to create any cluster if either target name
already exists and requires the selected `cmtc:dev` image to be available to
the Colima Docker runtime for import into Kind.

After bootstrap, run the local two-cluster application test and preserve its
output:

```bash
bash scripts/lab/reconcile-clustermesh-endpoints.sh
bash scripts/lab/test.sh
```

Check node readiness, issuer/certificate readiness, Cilium image IDs, and
`cilium clustermesh status` in both contexts. `scripts/lab/test.sh` verifies
CMTC Observe behavior plus local and cross-cluster Service and Pod-IP traffic on
ports 80, 8080 and 31337. The current bootstrap has `encryption.enabled=false`
and does not install ztunnel, so this baseline is **not** workload-mTLS or
node-encryption evidence. Keep those acceptance gates open until the exact
Cilium and ztunnel images run the positive, plaintext-negative, restart and
packet-capture checks on this same two-cluster lab.
