# Deployed CMTC Observe lab

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Status: experimental Observe implementation. The MacBook uses the persistent `cmtc-a` and `cmtc-b` clusters in the `cmtc-cilium` Colima VM. Preserve these clusters and their applications. It does not yet enable workload mTLS or required WireGuard/IPsec composition. Follow [the implementation plan](../architecture/IMPLEMENTATION_PLAN.md) for those security gates.

## Implemented behavior

- Cluster-scoped `NamespaceMTLSPolicy` API and structural CRD with CEL validation. Explicit AllEligible/MatchSelectors; OR between selectors and AND within them; platform protection before exclusions before inclusion. Empty/ambiguous selectors are rejected. Only Observe is accepted; Strict is rejected by the API and evaluator.
- Controller-runtime reconciler watches policies/namespaces, writes its own policy status, and reports current counts/observed generation. Multiple policies block evaluation until only one remains. Existing Cilium labels are counted as intent and left untouched. `EnforcementVerified` is Unknown with a reason. The controller's RBAC cannot patch namespaces or read signing Secrets.
- The current lightweight Go DaemonSet inventories only its node's pods using a server-side field selector. It distinguishes pod-network and host-network inventory and reports observation availability. It has no host mounts, proxy, eBPF access or CA-key permissions. Inventory readiness is not enforcement readiness. The optional eBPF observer and fence use separate DaemonSet profiles. They passed local qualification and their fixtures were removed. The existing Observe deployment does not gain BPF privileges. The prototype must later move into Cilium's agent before the datapath is treated as native or ClusterMesh-capable. Version/digest ACKs are future work.
- Real bounded-label Prometheus metrics: `cmtc_namespace_decisions{cluster,decision}`, `cmtc_namespaces_eligible`, `cmtc_namespaces_selected`, `cmtc_namespaces_enrolled` (labels only), `cmtc_enforcement_available` (0), `cmtc_policy_evaluations_total`, `cmtc_node_agent_ready{cluster,node}`, `cmtc_pods_observed{cluster,node,network}`. No protected-pod or successful-mTLS metrics are invented.

Namespace classification is a conservative initial inventory rule: reserved system/OpenShift/Cilium/CMTC names, declared protected metadata and additional protected names. This is not a qualified OpenShift platform detector and cannot authorize live enrollment.

## Recorded CI flow

CI is deferred during the active local qualification mandate. This section describes the harness. It does not authorize dispatching a workflow or replacing the persistent MacBook clusters.

[ci.yaml](../../.github/workflows/ci.yaml) runs on main/feature pushes. Unit/race tests, vet, binary compilation, generated-schema freshness, formatting and Kustomize/shell checks precede the deployed job.

The deployed job checks published checksums for kind v0.33.0, kubectl v1.36.4, Cilium CLI v0.20.0 and Helm v3.21.4. It builds CMTC from the tested commit; creates cmtc-a/cmtc-b with separate pod/service CIDRs; installs the digest-pinned Cilium fork agent/operator/ClusterMesh images and their source-matched chart, plus cert-manager v1.21.1; establishes the ClusterMesh API baseline; then deploys the controller, node agents, actual policy CRD and monitoring. This is a new harness adapted from the [pinned PoC review](../research/EXISTING_LAB_REVIEW.md).

For the disposable certificate fixture, the organizational test root key stays on the runner. Each cluster generates its own intermediate key inside a short-lived `lab-ca-init` Job and emits only its public CSR. The runner signs the CSR and returns the public chain; it never exports an intermediate private key. The initializer has a separate temporary namespace-scoped create-Secret permission which is removed after initialization. CMTC itself has no such permission. Root signing files are never uploaded and cleanup removes them. These ClusterMesh certificates are not SPIRE workload SVIDs or a production PKI implementation.

The initializer's Secret remains Opaque: bootstrap patches only `data.tls.crt` alongside the existing `tls.key`, since Secret type is immutable. The pinned cert-manager CA issuer loads those data keys ([issuer setup](https://github.com/cert-manager/cert-manager/blob/v1.21.1/pkg/issuer/ca/setup.go)); it does not require changing the Secret type.

The test step verifies selection/exclusion/platform precedence, relabeling and namespace recreation, multiple-policy conflict/recovery, Strict schema rejection, read-only namespace/Secret RBAC, imported shop POS success/stranger denial and a remote-only Global Service response. Failed security assertions exit nonzero. The results explicitly identify workload mTLS and layered encryption as blocked.

The Strict check is deliberately a **negative test**, using server-side dry run. Its expected API validation response is saved in each cluster's `*-strict-rejection.txt`; the main log prints an explicit expected-rejection PASS. An unrelated API/network failure does not count as success. A response saying only Observe is supported confirms this implementation's enforcement-mode restriction; it is not a missing CRD dependency. The deployable sample stays in Observe.

A small Prometheus runs in each cluster; the spoke remote-writes to the hub. Grafana provisions two consolidated pages: Operations and Workload Security. Panel counts depend on the recorded revision. Use [the dashboard guide](../../DASHBOARD_GUIDE.md) and its evidence for the selected revision. All nine original JSON definitions are preserved unchanged, and every original metric has a panel or documented equivalent in these pages. Playwright verifies both clusters' actual metrics, requires the enforcement-unavailable value, captures both themes of both pages plus the imported remote app (five cases), and writes a screenshot index. Missing future mTLS/trust/transport panels remain No data/unknown. Import and screenshots do not validate those future metrics.

The [capture Dockerfile](../../scripts/capture/Dockerfile) uses the official Ubuntu 24.04 Noble Playwright v1.63.0 image pinned by its manifest digest, matching the user's reference action. Chromium and browser system libraries are already installed in that base; the matching npm package is installed at image build time. A real Chromium launch/close check and browser tests of passing/failing panel/text expectations must pass. CI runs captures inside this prepared image, mounting only evidence output (plus a read-only spec when provided) and reaching loopback port forwards through Linux host networking. Browser/OS dependencies are not downloaded onto the runner during lab setup. This follows the [official Playwright Docker guidance](https://playwright.dev/docs/docker).

The [local browser-walk action](../../.github/actions/browser-walk/action.yml) ports the user's existing page walker and demo55 capture-publication flow. It accepts YAML/JSON page specs, actions, resolver/login settings and explicit expectations. Default CMTC pages are generated with named reasons for each permitted future-metric No data panel; implemented metrics and all live Observe panels must have data. The walker retains PNGs and its verdict before publication. CI then commits only the PNGs and browser log into a unique run/attempt folder on `ci-captures`, embeds immutable raw-image links in the job summary, and finally fails any unmet expectations. Artifacts are uploaded on failure as well. [Provenance and adaptations](../../scripts/capture/SOURCE.md) document the exact copied source, publication permissions and identity.

A domain dashboard may pass its rendering checks while its feature evidence remains **BLOCKED**. The log and `walk-results.json` distinguish these results explicitly; a known empty mTLS panel is not a passed mTLS test. The historical first passing run had 37 missing panels among the 45 original domain panels, while all six original live Observe panels had data. The consolidated pages retain future panels with a `planned` title: the current local deployment has ten missing planned Operations signals and sixteen missing planned Security signals. Native security panels require the separate SPIRE fixture; the baseline Observe CI does not deploy it. These are named implementation gaps, not exporter successes. Startup readiness retries are quiet; exhausting readiness still fails capture.

Evidence is collected before cleanup even on failure: policy status, node/pod/image inventory, events, CMTC logs, Cilium/mesh status, assertion results, actual metric samples and PNGs. An explicit allowlist excludes Secrets, kubeconfigs, PKI directories and full sysdumps. The job uploads `artifacts/` and deletes only the two clusters recorded as created by that run. No existing clusters are replaced.

## Local use

See [CILIUM_IMAGES.md](CILIUM_IMAGES.md) for local fork builds, GHCR publication, source/chart pins and image overrides. The checked-in lock selects the development baseline for both local kind and CI.

Requires Go >=1.26, Podman for MacBook image builds, the existing kind runtime, kubectl, Helm, Cilium CLI, OpenSSL and Python. The bootstrap and containerized capture paths target Linux CI; local cluster runs use installed tools. Node/Playwright run inside the Ubuntu capture image. The MacBook uses the dedicated Ubuntu Colima guest's host networking for the existing capture image and local port-forwards. This does not change the Podman image-build requirement.

For the existing clusters, use the owned application runner:

```sh
python3 scripts/lab/spire/check_app_paths.py --out /private/tmp/cmtc-app-paths-new-run
```

Use a Python environment with `cryptography` installed. The output directory must not exist. The runner creates its own clients, checks 36 paths, saves evidence and removes only those clients. A failed assertion or cleanup returns a nonzero exit code.

The `lab-up`, `lab-test` and `lab-down` Make targets belong to the disposable harness. Do not run them against the persistent labs. Follow [the Podman local runbook](PODMAN_LOCAL_VALIDATION.md) for builds and exact-image deployment.

Install only the observation components into an existing development cluster with `kubectl kustomize config/default`, replacing `CLUSTER_NAME` and the image with the intended values before applying. The controller image is non-root, has a read-only filesystem and drops capabilities; metrics HTTP access is restricted by a NetworkPolicy. The Grafana/Prometheus fixtures intentionally use disposable lab settings and are not production monitoring manifests.

## Remaining work

Observe itself does not establish live protection. Separate native SPIRE credential tests have passed; see [the credential guide](../../LOCAL_NATIVE_CREDENTIALS.md). Protected status, complete remote authorization, first-packet admission, recovery and layered encryption remain open. The hub/trust coordinator and versioned node ACK protocol remain future implementation. Complete those Cilium/CMTC contracts and positive/negative evidence before enabling the primary encrypted profile. Existing source audits describe their original static-review baseline; this runbook describes the current implementation.
