# Deployed CMTC Observe lab

Status: experimental first implementation. This builds real Go components and deploys them to two disposable Cilium clusters. It does not yet enable workload mTLS or required WireGuard/IPsec composition. Follow [the implementation plan](../architecture/IMPLEMENTATION_PLAN.md) for those security gates.

## Implemented behavior

- Cluster-scoped `NamespaceMTLSPolicy` API and structural CRD with CEL validation. Explicit AllEligible/MatchSelectors; OR between selectors and AND within them; platform protection before exclusions before inclusion. Empty/ambiguous selectors are rejected. Only Observe is accepted; Strict is rejected by the API and evaluator.
- Controller-runtime reconciler watches policies/namespaces, writes its own policy status, and reports current counts/observed generation. Multiple policies block evaluation until only one remains. Existing Cilium labels are counted as intent and left untouched. `EnforcementVerified` is Unknown with a reason. The controller's RBAC cannot patch namespaces or read signing Secrets.
- Lightweight Go DaemonSet inventories only its node's pods using a server-side field selector. It distinguishes pod-network and host-network inventory and reports observation availability. It has no host mounts, proxy, eBPF access or CA-key permissions. Inventory readiness is not enforcement readiness. Version/digest ACKs are future work.
- Real bounded-label Prometheus metrics: `cmtc_namespace_decisions{cluster,decision}`, `cmtc_namespaces_eligible`, `cmtc_namespaces_selected`, `cmtc_namespaces_enrolled` (labels only), `cmtc_enforcement_available` (0), `cmtc_policy_evaluations_total`, `cmtc_node_agent_ready{cluster,node}`, `cmtc_pods_observed{cluster,node,network}`. No protected-pod or successful-mTLS metrics are invented.

Namespace classification is a conservative initial inventory rule: reserved system/OpenShift/Cilium/CMTC names, declared protected metadata and additional protected names. This is not a qualified OpenShift platform detector and cannot authorize live enrollment.

## CI flow

[ci.yaml](../../.github/workflows/ci.yaml) runs on main/feature pushes. Unit/race tests, vet, binary compilation, generated-schema freshness, formatting and Kustomize/shell checks precede the deployed job.

The deployed job checks published checksums for kind v0.33.0, kubectl v1.36.4, Cilium CLI v0.20.0 and Helm v3.21.4. It builds CMTC from the tested commit; creates cmtc-a/cmtc-b with separate pod/service CIDRs; installs Cilium v1.20.4 and cert-manager v1.21.1; establishes the ClusterMesh API baseline; then deploys the controller, node agents, actual policy CRD and monitoring. This is a new harness adapted from the [pinned PoC review](../research/EXISTING_LAB_REVIEW.md).

For the disposable certificate fixture, the organizational test root key stays on the runner. Each cluster generates its own intermediate key inside a short-lived `lab-ca-init` Job and emits only its public CSR. The runner signs the CSR and returns the public chain; it never exports an intermediate private key. The initializer has a separate temporary namespace-scoped create-Secret permission which is removed after initialization. CMTC itself has no such permission. Root signing files are never uploaded and cleanup removes them. These ClusterMesh certificates are not SPIRE workload SVIDs or a production PKI implementation.

The test step verifies selection/exclusion/platform precedence, relabeling and namespace recreation, multiple-policy conflict/recovery, Strict schema rejection, read-only namespace/Secret RBAC, imported shop POS success/stranger denial and a remote-only Global Service response. Failed security assertions exit nonzero. The results explicitly identify workload mTLS and layered encryption as blocked.

A small Prometheus runs in each cluster; the spoke remote-writes to the hub. Grafana provisions the nine domain dashboards and a tenth, separate live evaluation view. Playwright verifies both clusters' actual metrics, requires the enforcement-unavailable value, captures all ten Grafana pages plus the imported remote app, and writes a screenshot index. Missing future mTLS/trust/transport panels remain No data/unknown. Import and screenshots do not validate those future metrics.

The [capture Dockerfile](../../scripts/capture/Dockerfile) uses the official Ubuntu 24.04 Noble Playwright v1.56.1 image pinned by its manifest digest. Chromium and browser system libraries are already installed in that base; the matching npm package is installed at image build time and a real Chromium launch/close smoke check must pass. CI runs captures inside this prepared image, mounting only the artifact directory and reaching loopback port forwards through Linux host networking. Browser/OS dependencies are not downloaded onto the runner during lab setup. This follows the [official Playwright Docker guidance](https://playwright.dev/docs/docker).

Evidence is collected before cleanup even on failure: policy status, node/pod/image inventory, events, CMTC logs, Cilium/mesh status, assertion results, actual metric samples and PNGs. An explicit allowlist excludes Secrets, kubeconfigs, PKI directories and full sysdumps. The job uploads `artifacts/` and deletes only the two clusters recorded as created by that run. No existing clusters are replaced.

## Local use

Requires Go >=1.26, Docker running, kind, kubectl, Helm, Cilium CLI, OpenSSL and Python. The bootstrap and containerized capture paths target Linux CI; local cluster runs use installed tools. Node/Playwright run inside the Ubuntu capture image. Use CI for screenshots from macOS unless Docker's Linux host networking is already configured.

```sh
make test build
make image
make capture-image
make lab-up
make lab-test
make lab-evidence
make lab-capture
make lab-down
```

Install only the observation components into an existing development cluster with `kubectl kustomize config/default`, replacing `CLUSTER_NAME` and the image with the intended values before applying. The controller image is non-root, has a read-only filesystem and drops capabilities; metrics HTTP access is restricted by a NetworkPolicy. The Grafana/Prometheus fixtures intentionally use disposable lab settings and are not production monitoring manifests.

## Remaining work

No live enrollment, Protected status, SPIRE credential delivery, consumer trust reload/rotation, remote workload discovery, application authorization inside HBONE, first-packet gate or layered encryption claim is made. The hub/trust coordinator and versioned node ACK protocol remain future implementation. Complete those Cilium/CMTC contracts and positive/negative evidence before enabling the primary encrypted profile. Existing source audits describe their original static-review baseline; this runbook describes the current implementation.
