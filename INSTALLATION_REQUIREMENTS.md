# CMTC installation requirements

Scope: the experimental strict ZDS profile in our Cilium and ztunnel forks.
Updated 2026-10-25. Use the retained `cmtc-a` and `cmtc-b` clusters.
Read [delivery status](docs/agile/DELIVERY_STATUS.md) for source and image pins.

## Shared PID namespace for strict ZDS

Set `spec.template.spec.hostPID: true` on both node DaemonSets:

| DaemonSet | Namespace | Required process identity |
| --- | --- | --- |
| `cilium` | `kube-system` | Agent can identify the local proxy process |
| `ztunnel-cilium` | `kube-system` | Proxy runs as UID 0 in the node PID namespace |

ZDS is the local Unix-socket protocol between Cilium and ztunnel. Our strict
drain check reads kernel peer credentials with `SO_PEERCRED`. It requires UID 0
and a visible PID greater than zero. A proxy outside the agent's PID namespace
can appear as PID 0. The agent then rejects it with:

```text
strict ZDS drain requires a root-owned local proxy process
```

Sharing the node PID namespace makes the peer PID visible. Keep the UID and PID
checks enabled. `hostNetwork: true` alone does not provide PID visibility.
This configuration exposes node process IDs to these node components. It does
not grant applications access to SPIRE's Admin socket. Ordinary application Pods
and the standard CMTC Observe node agent keep their existing PID isolation.

This requirement belongs to the current CMTC strict ZDS implementation. It is
not a universal requirement for every upstream Cilium installation. The source
check is `requireRootProxyPeer` in `pkg/ztunnel/zds/drain_receipt.go`, reviewed at
Cilium `51170b123988cda86aaea1bef3ccd95d221b8bbb`.

## Install or upgrade the node components

The Cilium chart at that source commit does **not** render agent `hostPID`.
Its SPIRE-backed ztunnel template already renders `hostPID: true`. Passing
`--set hostPID=true` does not fix the agent: the chart has no such value.

Use the [explicit agent manifest patch](config/experimental/strict-zds/cilium-hostpid.patch.yaml)
with that chart. This is a merge patch, not a standalone Kubernetes resource.
Apply it after installing or upgrading the matching fork chart:

```bash
kubectl --context kind-cmtc-a -n kube-system patch daemonset cilium \
  --type merge --patch-file config/experimental/strict-zds/cilium-hostpid.patch.yaml
kubectl --context kind-cmtc-b -n kube-system patch daemonset cilium \
  --type merge --patch-file config/experimental/strict-zds/cilium-hostpid.patch.yaml
```

Select the owned kubeconfig explicitly before running these commands. Preserve
the recorded source, images, volumes and other security settings. A Helm upgrade
can remove a live patch. Repeat the patch and verification until a qualified
fork chart includes the setting. Do not assume an image rebuild changes a Pod
manifest.

Replace the agent Pods one node at a time. The current DaemonSets use `OnDelete`;
changing the template does not change existing Pods. Use UID-preconditioned
deletion and wait for each replacement before proceeding. Preserve the proxy's
durable issuer checkpoint during all restarts. Disable its one-time checkpoint
bootstrap after the initial durable commit.

## Verify the installation

Check each DaemonSet template:

```bash
kubectl --context kind-cmtc-a -n kube-system get ds cilium ztunnel-cilium \
  -o custom-columns=NAME:.metadata.name,HOST_PID:.spec.template.spec.hostPID
kubectl --context kind-cmtc-b -n kube-system get ds cilium ztunnel-cilium \
  -o custom-columns=NAME:.metadata.name,HOST_PID:.spec.template.spec.hostPID
```

Require `true` for all four rows. Check every running Pod separately:

```bash
kubectl --context kind-cmtc-a -n kube-system get pods \
  -l 'k8s-app=cilium' -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,HOST_PID:.spec.hostPID
kubectl --context kind-cmtc-a -n kube-system get pods \
  -l 'app=ztunnel-cilium' -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,HOST_PID:.spec.hostPID
```

Repeat the Pod checks with `kind-cmtc-b`. Require one agent and one proxy on each
discovered node. Check their image IDs and actual readiness. Then inspect the
new agent logs for the `V2_DRAIN` hello and the completed initial ZDS snapshot.
Retain the original rejection and the recovery logs.

On 2026-10-25, all four agents and all four proxies became Ready after this
correction. See [the runtime receipt](docs/evidence/strict-zds-hostpid/README.md).
This result proves startup recovery. Workload mTLS still requires real traffic,
authenticated peer identities, effective policy, negative tests and recovery
evidence. Read [the security matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md).
