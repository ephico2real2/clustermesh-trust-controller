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

Eight privileged tests exercise the actual verifier and `BPF_PROG_TEST_RUN`, unchanged packet/`TCX_NEXT`, raw-packet counter changes, wrong namespace/program rejection, foreign chain drift, legacy-TC refusal, Cilium-owner detach, SIGKILL/restart, concurrent sampling/cleanup, deliberate ifindex/name/MAC/program reuse, and ingress plus egress hooks. The Cilium-named fixture program is synthetic; it cannot qualify actual Cilium policy behavior. Full CMTC tests cover the dependency upgrades, while focused collector tests verify live zero versus unavailable, absolute repeated scrapes, freshness and concurrent collection.

Raw diagnostics are under `/private/tmp/cmtc-observer-20261024/`. [Durable qualification results](docs/evidence/datapath-observer/qualification.json) and adjacent original-failure/final logs record 24 unique top-level tests and 49 subtests, zero failures/skips, across the full CMTC regression and privileged profiles. Exact image/runtime results will follow the disposable Cilium integration run. The current code passes the local kernel and Go/race/vet gates; exact-image cluster integration is still pending.

## Image and cluster qualification

Build only committed source with `build/Containerfile.bpf-observer`, passing the qualified builder ID as `BUILD_IMAGE` and the full commit SHA as `SOURCE_SHA`. The image packages the static CLI and compiled ELF, records the revision label, and exposes it through `--version`. Use Podman on the host, explicitly `--platform linux/arm64`.

Export a docker archive and load it into the existing `cmtc-a` and `cmtc-b` runtime. Verify the deployed image configuration ID and revision. Configure only audited disposable clients; opt in their nodes using `security.cmtc.io/bpf-observer-lab=true` and an immutable per-node ConfigMap. Do not label other nodes or platform workloads.

Before accepting cluster integration, record actual native Cilium link/program IDs, positive packet deltas and unchanged allow/deny behavior before/during/after attachment. Exercise crash/restart and workload deletion/recreation; stale configuration must fail instead of selecting a new incarnation. Compare baseline chains after removing only task-owned resources. Keep authenticated remote discovery, pre-restore/first-packet fencing, effective authorization and workload mTLS/WireGuard/IPsec acceptance open. CI and image publication remain deferred.
