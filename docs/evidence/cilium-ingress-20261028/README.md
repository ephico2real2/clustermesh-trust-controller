# Cilium Ingress on kind-cmtc-a and kind-cmtc-b, 2026-10-28

Result: Cilium Ingress runs on both clusters in shared mode. The Service `cilium-ingress` has the address
172.18.250.10 (cmtc-a) or 172.18.251.10 (cmtc-b) from LB IPAM, with no node port, and the agents announce it on the
kind network (L2). Workload mTLS is unchanged.

State: **deployed and traffic-qualified** (the mTLS matrix) on both clusters. At 04:25Z the Ingress path itself was
not tested yet: no Ingress object existed until the observability hub was installed.

## kind-cmtc-a, 04:17-04:25Z

| Step | Time (UTC) | Result |
|---|---|---|
| Plan | 04:17Z | `cilium_adopt.py plan`: 28 changes, 0 deletions, 0 kubectl manager entries, 0 refusals ([plan](cmtc-a-plan.txt)): 19 `cilium-config` keys, the `cilium` and `cilium-operator` ClusterRoles, new Service `cilium-ingress`, its EndpointSlice, IngressClass `cilium`, and the `cilium-secrets` Roles and RoleBindings. No Pod template change |
| Upgrade | 04:17:37-04:17:44 | `cilium_adopt.py upgrade`: revision 10. No Pod changed ([before](cmtc-a-pods-before.txt), [after](cmtc-a-pods-after-helm.txt)) |
| Operator restart | 04:18:05-04:18:11 | `--enable-ingress-controller='true'` in the startup flags; no warning or error lines |
| Agent restart | 04:18:42-04:19:11 | One agent at a time (`maxUnavailable: 1`). Each logged `stage=issuer-profile-source-succession` ("floors carried"), then issuer-profile ACKs |
| Unchanged Pods | | ztunnel, clustermesh-apiserver (restarts 0,0,0), cilium-envoy, hubble-relay, hubble-ui: the same Pods ([after](cmtc-a-pods-after-restart.txt)) |
| Address | 04:19Z | `cilium-ingress` LoadBalancer, external IP 172.18.250.10, `allocateLoadBalancerNodePorts: false`, ports 80 and 443 with no `nodePort`. Lease `cilium-l2announce-kube-system.cilium-ingress` held by cmtc-a-control-plane. From cmtc-b-worker, ARP for 172.18.250.10 resolves to cmtc-a-control-plane's eth0 MAC; TCP 80 is refused (no listener while no Ingress exists) |
| Drift | 04:20Z | `cilium_release.py check --strict`: 0 differences |
| mTLS matrix | 04:21:13-04:25:17 | [matrix-cmtc-a/join.txt](matrix-cmtc-a/join.txt): 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed |

Inputs: `config/lab/cilium/base.yaml` (`ingressController`, `l2announcements`), the image lock
`.tmp/cilium-image-values.json`, and the cluster values from `cilium_cluster_values.py --from-live`. The address pool,
the L2 policy and the CoreDNS zones come from `charts/cmtc-lab-network` with `config/lab/network/`.

## kind-cmtc-b, 07:40-07:46Z

The same procedure, after the SPIRE recovery ([spire-sidecar-outage-20261028](../spire-sidecar-outage-20261028/README.md)).

| Step | Time (UTC) | Result |
|---|---|---|
| Plan | 07:40Z | `cilium_adopt.py plan`: 28 changes, 0 deletions, 0 kubectl manager entries, 0 refusals ([plan](cmtc-b-plan.txt)): the same 19 `cilium-config` keys, 2 ClusterRoles and 7 new objects as cmtc-a. No Pod template change |
| Upgrade | 07:40:28-07:40:34 | `cilium_adopt.py upgrade`: revision 11. No Pod was created and no restart count changed ([after](cmtc-b-pods-after-helm.txt)) |
| Operator restart | 07:40:53-07:40:55 | `enable-ingress-controller='true'` and `enable-l2-announcements='true'` in the startup flags; 0 warning or error lines |
| Agent restart | 07:41:09-07:41:38 | One agent at a time. Each logged `stage=issuer-profile-source-succession` ("floors carried"). Warnings: the same startup set as the cmtc-a agents at 04:18Z (`Unable to acquire source membership writer lock`, `Remote workload source membership was withdrawn`, `Remote IP identity snapshot is invalid`). One error on cmtc-b-control-plane at 07:41:35Z: cilium-health's socket was not up yet; at 07:43-07:45Z both agents report cluster health 4/4 |
| Unchanged Pods | | Only the two agents and the operator are new ([after](cmtc-b-pods-after-restart.txt)). clustermesh-apiserver (restarts 0,0,0), ztunnel (restarts 0), SPIRE: the same Pods |
| Address | 07:42Z | `cilium-ingress` LoadBalancer, 172.18.251.10, `allocateLoadBalancerNodePorts: false`, ports 80 and 443. Lease `cilium-l2announce-kube-system.cilium-ingress` held by cmtc-b-worker. From cmtc-a-worker, ARP for 172.18.251.10 resolves to cmtc-b-worker's eth0 MAC; TCP 80 is refused (cmtc-b has no Ingress) |
| Drift | 07:41Z | `cilium_release.py check --strict`: 0 differences. ClusterMesh: cmtc-a 2/2 connected, KVStoreMesh 1/1 |
| mTLS matrix | 07:42:23-07:46:27 | [matrix-cmtc-b/join.txt](matrix-cmtc-b/join.txt): 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed |

The earlier version of this record ran `pods` without quoting the `custom-columns` argument; zsh expanded `[*]`, the
listing before the upgrade was empty, and it is not kept. The check above uses the Pod creation times instead.

Open:

- The first request through the Ingress was tested at the observability install (hub on cmtc-a).
- Observed, not investigated: on cmtc-a the agents log `Issuer profile refresh failed; keeping the accepted profile
  until it expires` (`output changed during API observation`) 3 to 4 times between 05:42Z and 07:13Z; ACKs continue
  every 10 s after each one.
