# Local image build and deployment

Build images with **Podman from the MacBook host**. Target `linux/arm64`. Transfer each image to the existing Colima kind runtime by archive.

Building an image, importing an image and deploying an image are separate actions. Verify each result. Pushes that
trigger CI, manual CI dispatch and registry publication are deferred ([AGENTS.md](AGENTS.md)).

Follow the loop **edit → run against `cmtc-a`/`cmtc-b` → test traffic, failures and recovery → package**. Build an
image only after the live path works. One compiler and one live writer act at a time; check the build and lab leases
before you start. Current source and image pins are in [delivery status](docs/agile/DELIVERY_STATUS.md).

## Select the component

| Image | Contents | Recipe and evidence |
| --- | --- | --- |
| CMTC | Controller, node inventory process and PKI helper commands | [Dockerfile](Dockerfile), [producer build arguments](docs/evidence/approved-issuer-lineage/build-command.json) |
| Experimental registrar | Exact SPIRE registration helper | [Containerfile](build/Containerfile.spire-registrar), [registrar guide](LOCAL_SPIRE_REGISTRAR.md) |
| CMTC observer or fence | Go loader and compiled eBPF object | [Exact build and transfer (2026-10-24)](LOCAL_DAEMONSET_TELEMETRY.md#exact-build-and-transfer) |
| Cilium agent, operator, ClusterMesh API server | Overlay binaries on the selected runtime base | [Agent build procedure](docs/development/PODMAN_LOCAL_VALIDATION.md#2-build-a-cilium-agent-image-with-podman); the 2026-10-25 scripts `build_agent_overlay.sh`, `build_operator_current.sh`, `build_apiserver_overlay.sh` in [the activation operations](docs/evidence/local-activation-20261025/operations/) |
| SPIRE server | Modified SPIRE server binary | [Recorded build script](docs/evidence/spire-recovery/build-server.sh) |
| SPIRE agent | Modified SPIRE node agent binary | [Recorded build script](docs/evidence/spire-workload-api/build-agent.sh) (2026-10-24); `build_spire_agent_overlay.sh` in [the activation operations](docs/evidence/local-activation-20261025/operations/) (2026-10-25) |
| Native SVID diagnostic | Public-output native credential check; no proxy | [Recorded build script](docs/evidence/spire-native-credentials/image/build.sh) |
| Ztunnel | Workload TLS proxy binary | `build_ztunnel_image.sh` in [the activation operations](docs/evidence/local-activation-20261025/operations/); earlier [TLS image build](docs/evidence/pinned-tls-foundation/build-image.sh) |

The PKI initializer/completer is part of the CMTC image. It is not a new certificate authority service. The registrar image is a separate experiment. Read [the registration ownership review](SPIRE_REGISTRATION_DESIGN.md).

Recorded scripts contain their original paths and source pins. Review those inputs before reproducing a build in a new directory. Do not overwrite a retained evidence run.

## 1. Inspect the environment

```sh
podman system connection list
podman --connection cmtc-ubuntu-build info
podman --connection cmtc-ubuntu-build ps
colima -p cmtc-cilium status
```

Preserve unrelated containers. Do not change the default Podman connection. A local image configuration ID identifies an image in that builder's store; it is not a portable registry reference.

## 2. Freeze the source

Run this example from the CMTC repository after the affected source is committed. It exports the selected commit. Uncommitted working files are excluded.

```bash
set -euo pipefail
BUILD_SOURCE_SHA=$(git rev-parse HEAD)
BUILD_TASK_DIR=$(mktemp -d /private/tmp/cmtc-image-build.XXXXXX)
mkdir "$BUILD_TASK_DIR/source"
git archive "$BUILD_SOURCE_SHA" | tar -x -C "$BUILD_TASK_DIR/source"
printf '%s\n' "$BUILD_SOURCE_SHA" > "$BUILD_TASK_DIR/source-sha.txt"
git status --short > "$BUILD_TASK_DIR/working-tree.txt"
```

Compare the selected commit with the tested source. A build from an older clean commit does not include a newer dirty fix. Exporting to `/private/tmp` also avoids relying on a new MacBook file being visible through an existing VM mount.

## 3. Run the source checks

Use the qualified builder recorded for the component. The local Go 1.27.3 builder configuration is `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`.

For CMTC:

```bash
podman --connection cmtc-ubuntu-build run --rm \
  --platform linux/arm64 --cpus 2 --memory 4g \
  -e GOMAXPROCS=2 -e GOFLAGS=-p=2 \
  -v "$BUILD_TASK_DIR/source:/src:ro" -w /src \
  f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  sh -ec 'go test -race -count=1 -json ./...; go vet ./...' \
  > "$BUILD_TASK_DIR/go-checks.jsonl" 2>&1
```

This ordinary suite does not replace privileged Linux kernel tests. Use [the Podman qualification runbook](docs/development/PODMAN_LOCAL_VALIDATION.md) for actual eBPF and namespace tests. Record selected, passed, failed and skipped counts. Zero selected tests cannot qualify a change.

## 4. Build the selected image

The following example builds the experimental registrar. It uses the recorded local builder and pinned runtime. It does not select the registrar as the permanent production owner.

```bash
BUILD_IMAGE_TAG="localhost/cmtc-spire-registrar:local-${BUILD_SOURCE_SHA:0:10}"
podman --connection cmtc-ubuntu-build build \
  --platform linux/arm64 --jobs 1 --memory 3g \
  --build-arg BUILDPLATFORM=linux/arm64 \
  --build-arg TARGETOS=linux --build-arg TARGETARCH=arm64 \
  --build-arg BUILD_IMAGE=f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  --build-arg RUNTIME_IMAGE=gcr.io/distroless/static-debian13@sha256:ed4ec1de07c43dc8d073221ee9e545cf54e12f7a4d451a4ee7d7bb3ce6165d52 \
  --build-arg SOURCE_REVISION="$BUILD_SOURCE_SHA" \
  --label org.opencontainers.image.source=https://github.com/ephico2real2/clustermesh-trust-controller \
  -f "$BUILD_TASK_DIR/source/build/Containerfile.spire-registrar" \
  -t "$BUILD_IMAGE_TAG" "$BUILD_TASK_DIR/source" \
  > "$BUILD_TASK_DIR/build.log" 2>&1
```

For the CMTC image, select the root Dockerfile. Preserve its recorded build arguments and source revision label. For SPIRE, use the linked static-build recipes. For Cilium, an agent-only overlay does not rebuild the operator, ClusterMesh API server, chart or eBPF objects. Rebuild each component whose source changed.

## 5. Verify and export

```bash
podman --connection cmtc-ubuntu-build image inspect "$BUILD_IMAGE_TAG" \
  > "$BUILD_TASK_DIR/image.json"
podman --connection cmtc-ubuntu-build run --rm \
  --platform linux/arm64 --network none --memory 128m \
  "$BUILD_IMAGE_TAG" --version > "$BUILD_TASK_DIR/version.txt" 2>&1
rg -F "$BUILD_SOURCE_SHA" "$BUILD_TASK_DIR/version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive \
  -o "$BUILD_TASK_DIR/image-arm64.tar" "$BUILD_IMAGE_TAG"
shasum -a 256 "$BUILD_TASK_DIR/image-arm64.tar" \
  > "$BUILD_TASK_DIR/image-arm64.tar.sha256"
```

This version command applies to the registrar example. Other components have different executable paths or version interfaces. For the CMTC runtime, retain the binary hash as in [the rollout ledger](docs/evidence/approved-issuer-lineage/baseline-rollout.json).

Require the intended source label, Linux ARM64 platform and image configuration ID. Keep the archive checksum with those records.

## 6. Import into the existing clusters

```bash
export DOCKER_HOST="unix://$HOME/.colima/cmtc-cilium/docker.sock"
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
kind load image-archive "$BUILD_TASK_DIR/image-arm64.tar" --name cmtc-a
kind load image-archive "$BUILD_TASK_DIR/image-arm64.tar" --name cmtc-b
```

Importing does not change a running Pod. Verify all four node image stores before rollout. Resolve the loaded tag through `crictl inspecti`. Compare its configuration ID and architecture with the build record. Correlate running Pod image IDs with the imported `repoDigests`.

Some archive imports produce a synthetic CRI digest. Do not assume that digest is a pullable image reference. [The SPIRE importer](docs/evidence/spire-workload-api/load-and-verify.py) records the exact normalization and verification procedure for that image.

## 7. Deploy and qualify

Use the owning component's reviewed deployment helper. It must pin the existing object UID and template. It must preserve signers, PVCs, service accounts, permissions and unrelated applications.

Do not replace the persistent labs. A build step never changes ztunnel, SPIRE socket or Admin permissions. The Cilium
agent and ztunnel DaemonSets use `OnDelete`: change only the image fields, then replace one Pod at a time with a UID
precondition ([lab scripts, section 4](docs/development/LAB_SCRIPTS.md#4-update-the-mesh-images-on-the-running-lab)).
Keep `hostPID` absent on the Cilium agent and `true` on ztunnel ([installation requirements](INSTALLATION_REQUIREMENTS.md)).

After rollout, verify the actual running binary and image. Run the owning positive, negative, restart and recovery tests. Save traffic, identity, packet and dashboard evidence where applicable. A version-only Job proves execution of that image; it does not prove mTLS.

For application continuity, use the owned-client runner:

```sh
python3 scripts/lab/spire/check_app_paths.py --out /private/tmp/cmtc-app-paths-new-run
```

Use a Python environment with `cryptography` installed. The new output directory must not exist. The runner checks 36 paths and cleans up its own clients. Any assertion or cleanup failure returns a nonzero exit code.

## Build record checklist

Record the source SHA, source diff state, toolchain, runtime base, target platform, commands and exit codes. Record the archive checksum, configuration ID, imported node IDs and actual running binary. Keep failed attempts and cleanup results.

Use [current delivery status](docs/agile/DELIVERY_STATUS.md) to distinguish built, imported, deployed and fully qualified increments. Read [the PKI flow guide](PKI_TRUST_FLOW.md) for certificate ownership and verification boundaries.
