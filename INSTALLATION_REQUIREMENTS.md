# CMTC installation requirements

Scope: the experimental strict ZDS profile in our Cilium and ztunnel forks.
Updated 2026-10-25 21:30 UTC. Use the retained `cmtc-a` and `cmtc-b` clusters.
Read [delivery status](docs/agile/DELIVERY_STATUS.md) for source and image pins.

## Shared PID namespace for strict ZDS

Only the proxy shares the node PID namespace. Since Cilium `0ed63bf906` the
agent does not, and must not:

| DaemonSet | Namespace | `hostPID` | Why |
| --- | --- | --- | --- |
| `cilium` | `kube-system` | absent (false) | The ZDS peer check needs only the proxy's UID |
| `ztunnel-cilium` | `kube-system` | `true` | The proxy binds SPIRE identities to workload processes |

ZDS is the local Unix-socket protocol between Cilium and ztunnel. The strict
drain check reads the proxy's kernel credentials with `SO_PEERCRED` and requires
UID 0 (`authorizeProxyPeer` in `pkg/ztunnel/zds/drain_receipt.go`). The kernel
reports the peer PID as 0 when the proxy is in another PID namespace, so the
check no longer reads the PID. The earlier check also required a PID greater
than zero; that is why the agent briefly needed `hostPID`. A non-root peer is
still rejected with:

```text
strict ZDS drain requires a root-owned local proxy process
```

ztunnel finds each workload's processes and holds them with `pidfd_open` and
`/proc` (`src/identity/spireclient.rs`, `src/identity/process_binding.rs`).
That needs the node PID namespace. Its SPIRE-backed chart template already
renders `hostPID: true`. Ordinary application Pods and the CMTC Observe node
agent keep their PID isolation. Neither component gets SPIRE's Admin socket.

## Install or upgrade the node components

The Cilium chart renders no agent `hostPID`, which is the required state. A
cluster that still carries the earlier interim patch must drop it. Apply the
[removal merge patch](config/experimental/strict-zds/cilium-drop-hostpid.patch.yaml)
(`hostPID: null` deletes the field):

```bash
kubectl --context kind-cmtc-a -n kube-system patch daemonset cilium \
  --type merge --patch-file config/experimental/strict-zds/cilium-drop-hostpid.patch.yaml
kubectl --context kind-cmtc-b -n kube-system patch daemonset cilium \
  --type merge --patch-file config/experimental/strict-zds/cilium-drop-hostpid.patch.yaml
```

Select the owned kubeconfig explicitly before running these commands. Preserve
the recorded source, images, volumes and other security settings. Do not assume
an image rebuild changes a Pod manifest.

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

Require no value (false) for `cilium` and `true` for `ztunnel-cilium` in
both clusters. Check every running Pod separately:

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

On 2026-10-25 (20:51-20:59 UTC) all four agents were replaced with Cilium
`bc2c9639c5` without `hostPID`; each accepted its proxy over ZDS and released
its enrolled workloads. See [the rollout record](docs/evidence/zds-ownership-rollout-20261025/README.md).
The interim `hostPID` agent configuration is recorded in
[the earlier runtime receipt](docs/evidence/strict-zds-hostpid/README.md).
This result proves startup recovery. Workload mTLS still requires real traffic,
authenticated peer identities, effective policy, negative tests and recovery
evidence. Read [the security matrix](docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md).
