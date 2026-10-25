# Local CMTC eBPF DaemonSet and telemetry qualification

The opt-in CMTC image contains the compiled eBPF object and its Go loader. The
loader validates the frozen workload/interface identity and native Cilium chain
before attachment. The ordinary Observe node agent stays unprivileged. This
prototype covers one explicitly audited workload hook per selected node;
automatic enrollment, first-packet admission and workload mTLS remain open.

There are two separate profiles: the observer returns NEXT before Cilium's
verdict; the fence unconditionally drops at its audited hook. Neither verifies
TLS. Read the [observer](LOCAL_DATAPATH_OBSERVER.md) and
[persistent fence](LOCAL_DATAPATH_FENCE.md) guides for ownership and limitations.

## Exact build and transfer

Runtime source is `5b1bc205fee9c6bc999c7d545e23ac0ff6f29bf2`. The
[recorded build script](docs/evidence/daemonset-telemetry/build-images.py)
exports that committed tree, builds on the MacBook through the explicit
`cmtc-ubuntu-build` Podman connection, sets `linux/arm64`, bounds compilation
resources and checks the image revision and CLI version. Its pinned builder
contains Go1.27.3 and clang21.1.8. This is ARM64 qualification only.

The [image ledger](docs/evidence/daemonset-telemetry/images.json) records tags,
configuration IDs, archive hashes and extracted CLI/ELF hashes. The fence tag is
`localhost/cmtc-bpf-fence:metrics-5b1bc205fe`; the observer tag is
`localhost/cmtc-bpf-observer:metrics-5b1bc205fe`.

The [transfer script](docs/evidence/daemonset-telemetry/load-images.py) uses
`podman save --format docker-archive`, then `kind load image-archive` into the
existing Colima-backed `cmtc-a` and `cmtc-b`. It preserves the runtime provider.
On every node, `crictl inspecti` must match the expected image configuration ID
and ARM64 architecture. The [four-node import ledger](docs/evidence/daemonset-telemetry/loaded-images.json)
retains the synthetic manifest references separately from configuration IDs.
These scripts describe this machine's recorded build; verify paths, source,
builder availability and owned resources before replaying them.

## Health and metrics boundaries

Fence health is loopback-only on port 18083 and binds the daemon Pod UID, canonical
configuration, ELF and source revision. The opt-in metrics-only listener binds
the exact downward Node IP on port 18084. Observer metrics use port 18085; observer health
remains loopback-only on port 18082. Exposed routes permit GET `/metrics`; health,
configuration and debugging routes return 404, and mutation requests return 405.
These lab HTTP endpoints are not an authenticated production scrape policy.

Each profile exports two counters (packets, skb bytes) and one fresh verification
gauge, with bounded cluster/node/direction labels. Stale or unverified samples
omit counters. Missing sources stay unavailable. Fence counters survive exact
pinned-map adoption; observer maps reset on process/attachment restart. Packet
counts include retransmits and are not request or handshake counts.

Each cluster's existing Prometheus scrapes locally. Cluster B remote-writes to
the A hub queried by Grafana. There is no additional CMTC metrics aggregator.
Local target evidence and central query evidence are both required; central
series alone cannot prove B's scrape target is healthy. See the
[metric contract](observability/METRICS.md) for the separate planned security
families and their actual observing owners.

## Qualification and current limits

The [affected private-kernel run](docs/evidence/daemonset-telemetry/kernel-metrics-final.log)
passes44 distinct top-level tests/126 subtests, race and vet, with zero
failures/skips. The [packaged-object run](docs/evidence/daemonset-telemetry/packaged-kernel.log)
passes28 top-level tests/69 subtests against the extracted ELF/CLI, with zero
failures/skips. These run in private namespaces through the task-owned rootful
Podman test service; rootless `--privileged` does not supply BPF privileges.

The first four-node telemetry attempt stopped before attachment because the
control-plane nodes lacked the explicit PullNever client image. The exact
ARM64 client image was imported and verified on all four nodes. The second
attempt deployed two ready fence instances per cluster, audited metrics routes,
ran48 additional denied HTTP load attempts, checked exact kernel counter deltas
and quiet idle behavior, and verified local scrapes plus central remote-write
queries. Its browser check failed because only33 of39 Operations panels mounted.
The failure was retained and cleanup completed without errors. Restart,
deselection, absent-source and final visual gates for this new image remain
pending; no complete-run claim follows from those partial results.

Live trial diagnostics remain in `/private/tmp/cmtc-daemonset-20261024/`.
The [delivery status](docs/agile/DELIVERY_STATUS.md) records the next gate and
supersedes historical checkpoints. CI, pushing and image publication remain
deferred. ClusterMesh connectivity works; ztunnel is disabled and cross-cluster
workload mTLS is not qualified.
