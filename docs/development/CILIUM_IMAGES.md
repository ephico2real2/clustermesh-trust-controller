# Cilium fork image development

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

The recorded published bundle contains agent, generic operator and ClusterMesh API server images from **our fork**, with immutable digests in [the development lock](../../config/cilium-images.lock.json). The chart and its CRDs are fetched from that exact `source_sha`, rather than combining current-main binaries with a release chart. The original v1.20.4 source audit remains a historical research baseline.

The historical published source is `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`, which adds the Authorization transport lifecycle. [Publisher CI 40053175683](https://github.com/ephico2real2/cilium/actions/runs/40053175683) passed after reusing the ARM64 images built locally on this MacBook and building native AMD64 images in GitHub. It verified source/platform labels and actual agent binary versions before assembling the two-platform indices. [Wire CI 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200) and local Linux ARM64 each passed 150 race-enabled tests/subtests. This source enables no policy producer or protected profile; deployed-image baseline qualifications are tracked in [VALIDATION.md](VALIDATION.md).

The public package is `ghcr.io/ephico2real2/cilium-dev`. Each component uses a distinct `sha-<full-source-commit>-<component>` tag and a two-platform image index (Linux AMD64 and ARM64). Native tags append the architecture. Digest pins, not mutable tags, select the tested version. This keeps the existing public package accessible to kind without registry Secrets.

**Current state (read 2026-10-25T23:07Z):** `cmtc-a` and `cmtc-b` do not run the published GHCR bundle. They run
local Podman overlay images from our fork, imported by archive: the agent `localhost/cilium:dev-overlay-6090aa6eff`
and the operator and ClusterMesh API server `dev-overlay-0ed63bf906`. Local archive overrides take precedence over
the historical publication lock. See [delivery status](../agile/DELIVERY_STATUS.md) for the exact pins. CI and
publication remain deferred.

## Develop, build and select a version

The strict ZDS profile requires the node PID namespace for the SPIRE-backed
ztunnel only. Since Cilium `0ed63bf906` the agent must **not** have `hostPID`;
the root-owned peer check reads only the proxy's UID. Follow
[installation requirements](../../INSTALLATION_REQUIREMENTS.md) before deployment
and after every chart upgrade. Verify both DaemonSet templates and all
replacement Pods. Keep the root-owned peer check enabled.

For local-first CMTC/Cilium security work, use the [Podman build, kind archive
import, and qualification runbook](PODMAN_LOCAL_VALIDATION.md). It documents
the MacBook's explicit Podman connection, pinned Linux ARM64 build inputs,
archive transfer into the existing Colima kind runtime, deployed image/source
verification, and real positive/negative traffic checks. Do not change the
default container engine or create replacement clusters to work around an
unavailable VM.

The Cilium fork's `contrib/cmtc-images/build.sh` and the
`cmtc-development-images.yaml` workflow are optional **publication** paths.
They build/push GHCR images and are separate from local Podman qualification.
The active mandate defers CI and publication; do not run those paths unless the
user changes that instruction. When publication is authorized, use one exact
source SHA, validate the resulting digest lock, and select it with
`CILIUM_IMAGE_LOCK=/absolute/path/to/images.lock.json` or a reviewed update to
`config/cilium-images.lock.json`. `make cilium-prepare` then fetches the chart
from that same source. Never select a mutable `latest` image.

The workflow's `cilium_image_lock_url` input accepts an immutable raw GitHub URL
in either owned repository for a future CI run. It does not change the checked-
in default lock. All three components must be pinned to matching source and
digest metadata when using this bundle path.

Both clusters must pass rollout, pinned image-spec, runtime image-ID and agent binary version checks. The resulting `cilium-image-verification.json` accompanies the lock, Helm overrides and source SHA in CI artifacts. Actual shop allow/deny tests and a remote-only Global Service precede six-minute load streams (20 requests/s per local shop; 10 requests/s cross-cluster). Those streams remain active during browser capture; final Fortio summaries must show at least 99% HTTP 200, sustained duration and a minimum achieved rate. This is baseline connectivity/policy evidence for the publication path; it is not workload-mTLS or transport-encryption evidence.

## Which Hubble image contains the change?

| Change | Component to build | Source repository |
| --- | --- | --- |
| Remote workload metadata, parsers, Hubble flow production and metrics | Cilium **agent**, already in this bundle; matching operator/CRDs accompany it | `ephico2real2/cilium` |
| L7 Grafana dashboard JSON | Matching **Helm chart**, fetched at `source_sha` | `ephico2real2/cilium` |
| Flow aggregation/Relay behavior | Custom `hubble-relay` image when its code changes | The same Cilium fork |
| Hubble web UI | UI frontend/backend images when their code changes | Separate `cilium/hubble-ui` fork only when needed |
| Standalone Hubble CLI behavior | CLI binary/image when its code changes | Separate `cilium/hubble` fork only when needed |

The [September draft](https://github.com/ephico2real2/cilium-implementation-poc/blob/main/docs/upstream/drafts/cilium-pr-remote-workload.md) describes an older CEP-only workaround. The broader remote-workload fix [#48563](https://github.com/cilium/cilium/pull/48563) merged October 6 and is already in our current-main fork. The remaining source-All dashboard fix is also in our chart. Reapplying that old patch or creating a separate Hubble fork is unnecessary for these changes.

Optional `images.hubble-relay`, `images.hubble-ui` and `images.hubble-ui-backend` entries in a bundle accept the same `{"image":"ghcr.io/ephico2real2/...@sha256:..."}` form and render the corresponding Helm image overrides. They do not enable those components implicitly. The CMTC Observe profile keeps Hubble disabled; the separate fork dashboard CI enables it and retains [real Gateway load evidence](https://github.com/ephico2real2/cilium/actions/runs/40035107452). Future Relay/UI changes need their own source pins and tests before adding them to this bundle.

The static ClusterMesh/ztunnel rejection was replaced by capability validation in Cilium `37d5fce0f7`. Custom images and screenshots do not establish workload mTLS, authorization enforcement or layered WireGuard/IPsec encryption.

## CMTC and KVStoreMesh

CMTC has no separate KVStoreMesh deployment or direct storage dependency on it. In this selected Cilium 1.21 development profile, ClusterMesh always uses KVStoreMesh for remote cluster state; the lab already runs that container in each mesh API server pod. CMTC policies/status remain Kubernetes CRDs, while Prometheus stores metrics. Missing unimplemented mTLS dashboard signals are not fixed by persisting mesh cache data. See the [Cilium 1.21 ClusterMesh command reference](https://docs.cilium.io/en/latest/cmdref/cilium_clustermesh_enable/).

The Hubble dashboard workflow accepts the same published lock through `image_lock_url` with its matching `source_sha`; it tests real external Gateway, pod Gateway and direct-pod load before before/after PNGs. This is a separate observability qualification from the CMTC two-cluster Observe baseline.

The Fortio Jobs write their JSON to an emptyDir from a non-root init container. A separate results container prints only the JSON after the load finishes; init-container console logs are retained separately. This avoids Kubernetes merging console output into the result document.

## Run the meshing scripts on this MacBook

Run the Linux lab scripts inside the dedicated Colima VM, where kind node addresses and Docker host networking are reachable. The existing profile is `cmtc-cilium` (8 CPUs, 16 GiB RAM); `/private/tmp` is mounted at the same path on both sides. Its local lab checkout is `/private/tmp/cmtc-mac-qualification`. The retained clusters are `cmtc-a` and `cmtc-b`. The [initial local qualification](https://github.com/ephico2real2/clustermesh-trust-controller/tree/18d063335fb130770003c915cb1bed1ee87528fc/2026-10-24T0033Z_cmtc_local-macos-arm64) records their first GHCR bootstrap at source `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`; subsequent image advances are tracked through the development lock and validation PR evidence.

```sh
colima -p cmtc-cilium ssh
cd /private/tmp/cmtc-mac-qualification
export PATH="$PWD/.tmp/bin:$PATH"
kubectl --context kind-cmtc-a get nodes
cilium clustermesh status --context kind-cmtc-a
cilium clustermesh status --context kind-cmtc-b
```

The VM needs `fs.inotify.max_user_instances=8192` for the multi-node lab. Its initial value of 128 caused a Cilium worker to fail with `couldn't initialize inotify: too many open files`; the tested setting is persisted in `/etc/sysctl.d/99-cmtc-kind.conf` inside this dedicated VM. `fs.inotify.max_user_watches` is 1048576. These are Linux VM settings.

For a fresh run, use `scripts/lab/ci-bootstrap.sh`, `make image`, `make capture-image`, `make lab-up`, `make lab-test`, `bash scripts/lab/load.sh start`, `make lab-capture`, `bash scripts/lab/load.sh collect` and `make lab-evidence` inside the VM. Set `GITHUB_PATH` to a temporary file for the bootstrap's tool-path output, then add `.tmp/bin` to `PATH`. `make lab-up` refuses to replace existing cluster names; `make lab-down` removes only the clusters recorded by that checkout. Keep generated files and signing material outside published evidence.
