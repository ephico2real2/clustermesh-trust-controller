# Cilium fork image development

The CMTC kind lab now consumes agent, generic operator and ClusterMesh API server images from **our fork**, with immutable digests in [the development lock](../../config/cilium-images.lock.json). The chart and its CRDs are fetched from that exact `source_sha`, rather than combining current-main binaries with a release chart. The original v1.20.4 source audit remains a historical research baseline.

The current selected source is `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`, which adds the Authorization transport lifecycle. [Publisher CI 40053175683](https://github.com/ephico2real2/cilium/actions/runs/40053175683) passed after reusing the ARM64 images built locally on this MacBook and building native AMD64 images in GitHub. It verified source/platform labels and actual agent binary versions before assembling the two-platform indices. [Wire CI 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200) and local Linux ARM64 each passed 150 race-enabled tests/subtests. This source enables no policy producer or protected profile; deployed-image baseline qualifications are tracked in [VALIDATION.md](VALIDATION.md).

The public package is `ghcr.io/ephico2real2/cilium-dev`. Each component uses a distinct `sha-<full-source-commit>-<component>` tag and a two-platform image index (Linux AMD64 and ARM64). Native tags append the architecture. Digest pins, not mutable tags, select the tested version. This keeps the existing public package accessible to kind without registry Secrets.

## Develop, build and select a version

Complete the local qualification before pushing a change that starts CI or dispatching a workflow. Use the MacBook's dedicated Ubuntu Colima VM with the source mounted into Linux containers. Run the affected tests and lint, build the intended image locally, then verify the two-cluster policy/connectivity tests, sustained load and browser evidence against that image. For Hubble changes, run the local Gateway and dashboard qualification as well. When target architectures differ, build the required Linux platform locally with Docker before publication; record the platform and source revision. CI repeats a successful local qualification. A CI failure is reproduced and fixed locally before rerunning it.

1. Work in a full checkout of `git@github.com:ephico2real2/cilium.git`. Keep upstream changes integrated through a reviewed fork PR; preserve existing feature branches. Commit the intended source under the configured human identity with a DCO signoff. The image helper refuses tracked source modifications.
2. Select a working Docker engine, log in locally and build from the committed checkout. The fork's `contrib/cmtc-images/build.sh` uses the native Cilium Dockerfiles and publishes all three components. On this Mac the isolated `colima-cmtc-cilium` context is available; it does not replace the existing Docker context or MongoDB environment.

   ```sh
   export DOCKER_CONTEXT=colima-cmtc-cilium
   gh auth token | docker login ghcr.io -u ephico2real2 --password-stdin
   CILIUM_TARGET_PLATFORM=linux/arm64 make cilium-build-push CILIUM_SOURCE_DIR=/absolute/path/to/cilium
   ```

   Native AMD64 builders use `linux/amd64`. The local build records metadata and a native lock in `artifacts/cilium-build/`. Credentials must stay outside evidence directories.
3. Run the fork's publisher against the **same full source SHA**. `local_arm64=true` waits for the local ARM64 set instead of rebuilding it; the Ubuntu AMD64 job builds any missing images. It verifies source/platform labels and the agent version, then publishes the multi-architecture indices and `cilium-image-bundle` artifact. Future CI publication uses only `GITHUB_TOKEN` with package-write permission. The existing package must grant `ephico2real2/cilium` Write under Manage Actions access.

   ```sh
   gh workflow run cmtc-development-images.yaml -R ephico2real2/cilium -f source_sha=<40-character-SHA> -f local_arm64=true
   gh run download <successful-run-id> -R ephico2real2/cilium -n cilium-image-bundle -D artifacts/cilium-bundle
   ```

4. Set `CILIUM_IMAGE_LOCK=/absolute/path/to/images.lock.json` for one local run, or deliberately replace `config/cilium-images.lock.json` and open a CMTC PR to advance the default. `make cilium-prepare` validates it and fetches the exact chart. `CILIUM_SOURCE_DIR` may point at an existing clean checkout at the same SHA to avoid fetching. `make image lab-up lab-test lab-evidence` then uses those images. Use the existing capture prerequisites described in [OBSERVE_LAB.md](OBSERVE_LAB.md).

The CI workflow also accepts `cilium_image_lock_url`, an immutable raw GitHub URL in either owned repository, to test an alternate lock without changing the default. The lock requires full SHA and digest references under the user's GHCR namespace. A mismatched/modified chart fails before creating clusters. All three components are overridden on both Helm install and mesh upgrade. No image source is selected with `latest`.

Both clusters must pass rollout, pinned image-spec, runtime image-ID and agent binary version checks. The resulting `cilium-image-verification.json` accompanies the lock, Helm overrides and source SHA in CI artifacts. Actual shop allow/deny tests and a remote-only Global Service precede six-minute load streams (20 requests/s per local shop; 10 requests/s cross-cluster). Those streams remain active during browser capture; final Fortio summaries must show at least 99% HTTP 200, sustained duration and a minimum achieved rate. This is baseline connectivity/policy evidence; workload mTLS and transport composition remain blocked.

## Which Hubble image contains the change?

| Change | Component to build | Source repository |
| --- | --- | --- |
| Remote workload metadata, parsers, Hubble flow production and metrics | Cilium **agent**, already in this bundle; matching operator/CRDs accompany it | `ephico2real2/cilium` |
| L7 Grafana dashboard JSON | Matching **Helm chart**, fetched at `source_sha` | `ephico2real2/cilium` |
| Flow aggregation/Relay behavior | Custom `hubble-relay` image when its code changes | The same Cilium fork |
| Hubble web UI | UI frontend/backend images when their code changes | Separate `cilium/hubble-ui` fork only when needed |
| Standalone Hubble CLI behavior | CLI binary/image when its code changes | Separate `cilium/hubble` fork only when needed |

The [September draft](https://github.com/ephico2real2/cilium-implementation-poc/blob/main/docs/upstream/drafts/cilium-pr-remote-workload.md) describes an older CEP-only workaround. The broader remote-workload fix [#48563](https://github.com/cilium/cilium/pull/48563) merged October 6 and is already in our current-main fork. The remaining source-All dashboard fix is also in our chart. Reapplying that old patch or creating a separate Hubble fork is unnecessary for these changes.

Optional `images.hubble-relay`, `images.hubble-ui` and `images.hubble-ui-backend` entries in a bundle accept the same `{"image":"ghcr.io/ephico2real2/...@sha256:..."}` form and render the corresponding Helm image overrides. They do not enable those components implicitly. The current CMTC Observe profile keeps Hubble disabled; the separate fork dashboard CI enables it and retains [real Gateway load evidence](https://github.com/ephico2real2/cilium/actions/runs/40035107452). Future Relay/UI changes need their own source pins and tests before adding them to this bundle.

The ztunnel compatibility rejection is retained. Custom images and screenshots do not establish workload mTLS, authorization enforcement or layered WireGuard/IPsec encryption.

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
