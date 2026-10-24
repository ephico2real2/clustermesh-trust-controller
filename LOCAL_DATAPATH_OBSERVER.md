# Local CMTC datapath observer

This is the first custom CMTC Go plus eBPF prototype. It counts packets and skb bytes on an explicitly selected disposable workload's host-veth TCX hook, then returns `TCX_NEXT`. It never changes packet data or a Cilium policy verdict. It does not enforce mTLS, admit workloads or establish `Protected` status.

The production destination remains native integration in the enhanced Cilium agent. The existing CMTC Observe DaemonSet stays unprivileged. The experimental manifest is outside default provisioning in [config/experimental/datapath-observer.yaml](config/experimental/datapath-observer.yaml).

## Ownership and lifecycle

The operator supplies an immutable node-specific configuration with cluster, node, Pod UID, network namespace inode, veth name/index/MAC/peer index, direction and the audited Cilium link/program IDs. Pod UID is an audit association, not a kernel-authenticated workload identity. The loader requires a veth with an existing TCX Cilium link; legacy TC and netkit are unsupported. A `cil_` program name is a sanity check, not proof of ownership.

The attach transaction holds the exact foreign link FD, checks the baseline revision and inserts its own link immediately before Cilium. It then releases the foreign FD so it cannot prolong Cilium's link lifetime. Every sample checks the frozen interface and complete chain. Drift stops the process; it never follows replacement interfaces automatically. Cleanup closes only its own link/maps/programs. SIGKILL closes the process-owned FDs through the kernel.

Readiness and counter emission require a successful sample within three seconds. Failed or stale samples suppress packet/byte series rather than fabricating zeros. Netlink receives have a two-second inactivity timeout; freshness independently covers a stalled sampling loop. The only HTTP listener is node-loopback `127.0.0.1:18082`. This profile has no remote Prometheus scraper or active dashboard panel yet.

| Metric | Meaning |
| --- | --- |
| `cmtc_datapath_observer_ready` | Fresh sample and exact observed attachment; never protection readiness. |
| `cmtc_datapath_observer_packets_total` | Absolute private-map packet total at this hook, before Cilium's verdict. Includes attempts Cilium later rejects. |
| `cmtc_datapath_observer_bytes_total` | Absolute skb-byte total at this hook. |

These are not HTTP requests, TCP connections, rejection counters or TLS handshakes. GRO and ordinary protocol traffic affect packet counts. Labels are limited to the configured cluster, node and direction; Pod UID, IP and interface incarnations are not metric labels.

## Qualified local kernel loop

Builds use the MacBook's Podman CLI, Linux ARM64 and the selected `cmtc-ubuntu-build` connection. The reusable Ubuntu test builder is based on `quay.io/cilium/cilium-builder@sha256:97d3a0f90898e83c8e63712accb64518f50ae0c4709c423f047c7871e8710ad5`, with Go 1.27.3, clang 21.1.8, iproute2, iptables and bpftool. The qualified local builder configuration ID is `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`.

The initial rootless run failed all four original privileged cases with `EPERM`: container root mapped to UID 501, while unprivileged BPF was disabled. A large memlock limit and `--privileged` did not grant privileges in the initial user namespace. The fix uses a task-owned rootful Podman service in the existing Ubuntu VM, with a disposable **private** container network namespace. No global BPF sysctl or kind networking changes are needed.

Start that service through the owned VM, keep its socket directory private, and use the host Podman CLI with that socket's explicit SSH URL. Import the already built test image into its separate image store with `podman save`/`podman load`. Stop the task-owned service after the tests. Never run these fixture tests with host networking or inside a kind node.

Export the current source into a VM-accessible `/workspace` mount. In the disposable privileged test container, run:

```sh
export CMTC_BPF_TEST_PRIVATE_NETNS=1
sh scripts/lab/qualify-observer.sh
go test -race -count=1 -v ./...
go vet ./...
```

The script compiles the actual C source with `clang -target bpfel -O2 -g -Wall -Werror`, builds a static ARM64 CLI, runs ordinary and tagged privileged race tests, vets both profiles and records binary/ELF hashes. Prerequisite failures are failures, never skipped acceptance cases.

Nine privileged tests exercise the actual verifier and `BPF_PROG_TEST_RUN`, unchanged packet/`TCX_NEXT`, raw-packet counter changes, wrong namespace/program rejection, foreign chain drift, legacy-TC refusal, Cilium-owner detach, SIGKILL/restart, concurrent sampling/cleanup, deliberate ifindex/name/MAC/program reuse, ingress plus egress hooks, and occupied-listener rejection before BPF loading. The Cilium-named fixture program is synthetic; it cannot qualify actual Cilium policy behavior. Full CMTC tests cover the dependency upgrades, while focused collector tests verify live zero versus unavailable, absolute repeated scrapes, freshness and concurrent collection.

Raw diagnostics are under `/private/tmp/cmtc-observer-20261024/`. [Durable qualification results](docs/evidence/datapath-observer/qualification.json) and adjacent original-failure/final logs record 25 unique top-level tests and 49 subtests, zero failures/skips, across the full CMTC regression and privileged profiles. Three local subprocess checks also qualify bounded log capture/reaping. The image's extracted BPF ELF exactly matches the kernel-tested ELF: `74c67287b17c8f346db54bd8e7a02ba3bc7fb83b92a822762b5de1b3edcc8716`.

## Image and cluster qualification

Build only committed source with `build/Containerfile.bpf-observer`, passing the qualified builder ID as `BUILD_IMAGE` and the full commit SHA as `SOURCE_SHA`. The image packages the static CLI and compiled ELF, records the revision label, and exposes it through `--version`. Use Podman on the host, explicitly `--platform linux/arm64`.

The qualified source is `b193510f206a8655a3f9c240728b71b0427a5b31`. Its image is `localhost/cmtc-bpf-observer:observe-b193510f20`, configuration ID `sha256:a66f9e5678824d15bdb45b60a70659a1534b919cc6753d8d81eb3d20eb309cdb`. It reports the full source revision through `--version` and is imported on all four nodes. The following is the actual build/archive/load sequence; choose a fresh VM-accessible output directory and retain its logs:

```sh
SOURCE_SHA=b193510f206a8655a3f9c240728b71b0427a5b31
BUILD_IMAGE=f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529
IMAGE=localhost/cmtc-bpf-observer:observe-b193510f20
OUT=/private/tmp/cmtc-observer-20261024
mkdir -p "$OUT/committed-source"
git archive "$SOURCE_SHA" | tar -x -C "$OUT/committed-source"
podman --connection cmtc-ubuntu-build build --platform linux/arm64 \
  --jobs 1 --memory 3g --env GOMAXPROCS=2 --env GOMEMLIMIT=1536MiB \
  --env GOFLAGS=-p=2 --unsetenv GOMAXPROCS --unsetenv GOMEMLIMIT --unsetenv GOFLAGS \
  --build-arg BUILD_IMAGE="$BUILD_IMAGE" --build-arg SOURCE_SHA="$SOURCE_SHA" \
  -f "$OUT/committed-source/build/Containerfile.bpf-observer" \
  -t "$IMAGE" "$OUT/committed-source"
podman --connection cmtc-ubuntu-build run --rm --network none "$IMAGE" --version
podman --connection cmtc-ubuntu-build save --format docker-archive \
  --output "$OUT/observer-arm64.tar" "$IMAGE"
export DOCKER_HOST=unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock
kind load image-archive "$OUT/observer-arm64.tar" --name cmtc-a
kind load image-archive "$OUT/observer-arm64.tar" --name cmtc-b
```

Export a docker archive and load it into the existing `cmtc-a` and `cmtc-b` runtime. Verify the deployed image configuration ID and revision. Configure only audited disposable clients; opt in their nodes using `security.cmtc.io/bpf-observer-lab=true` and an immutable per-node ConfigMap. Do not label other nodes or platform workloads.

Kind's Kubernetes image ID is an imported manifest reference. It differs from the configuration ID and may not be directly resolvable by `crictl inspecti`. Resolve the explicit loaded tag, require the expected configuration ID, require the running Pod's digest to occur in that image's recorded `repoDigests`, and check the in-Pod `--version`. Never compare a manifest digest directly to a configuration ID.

Before accepting cluster integration, record actual native Cilium link/program IDs, positive packet deltas and unchanged allow/deny behavior before/during/after attachment. Exercise crash/restart and workload deletion/recreation; stale configuration must fail instead of selecting a new incarnation. Compare baseline chains after removing only task-owned resources. Keep authenticated remote discovery, pre-restore/first-packet fencing, effective authorization and workload mTLS/WireGuard/IPsec acceptance open. CI and image publication remain deferred.

## Measured two-cluster results

[Integration evidence](docs/evidence/datapath-observer/integration.json), [all HTTP outputs](docs/evidence/datapath-observer/http-attempts.txt), adjacent native DROP logs and structured JSON logs record:

- 120 policy-controlled attempts: 80 successful requests on ports 80/8080 and 40 expected failures on port 31337. Independent clients first proved both 31337 backend listeners were healthy. Both clusters exercised local and remote control-plane backends from worker-node clients.
- Five phases per cluster: before observer, during observer, after SIGKILL/restart, after uninstall, and after rejecting the old configuration following client replacement. Every phase includes native `Policy denied` lines matching the current source IP and each destination IP/port.
- During the full run, private-map packet/byte deltas were A: 130 packets/10,068 bytes and B: 129 packets/9,998 bytes. Both restarted processes subsequently counted 32 additional packets. These totals include protocol packets and denied attempts; they do not equal HTTP requests.
- A second, shorter 84-attempt run verified six actual container-bound startup/attach/restart/detach/error log streams, atomic object deletion preconditions and node opt-in cleanup. It captured expected stale-configuration errors and graceful cleanup acknowledgments. Final cleanup left no task-owned DaemonSet, namespace or node opt-in, and retained all pre-existing foreign TCX links.

The selected client veth's complete program/link identity stays frozen. Cilium legitimately regenerates host programs on its retained links: the harness accepts only five audited host-hook tuples, with exact matching current-run Cilium loader paths, program names and timestamps. Unknown/veth program changes still fail. [Original harness diagnostics](docs/evidence/datapath-observer/harness-diagnostics.json) preserve the corrected HTTP-tool, numeric-UID, import-reference and program-update assumptions. No observer implementation failure was established by those diagnostics.

The shared dependency update also rebuilt and deployed unprivileged CMTC as `localhost/cmtc:observe-b193510f20`, configuration ID `sha256:e00900c6966ec7b8797a9598c65214e0a95529bc7ef74e78c7dfee4fbe7e897a`. The normal 36-path/API/policy suite passes. [Runtime verification](docs/evidence/datapath-observer/verified-runtime.json) checks sixteen imported component identities, ten ready CMTC/Cilium containers and all four Cilium agent binary hashes. [Image metadata](docs/evidence/datapath-observer/images.json) and adjacent build commands/toolchain hashes identify each component. Cilium remains `8b01a7c954`; the imported proxy remains `1db4fb296b`, with no active ztunnel or node encryption.

The observer was implemented here with internal agent review. Cursor/Grok supplied the separate issuer proposals and is working on a persistent fence proposal. Neither the current process-owned observer nor its successful tests establish fail-closed enforcement: its link intentionally disappears on process death. The persistent kernel fence is the next implementation dependency.
