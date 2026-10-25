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
attempt passed load and queries, then failed its strict39-panel rendering check;
cleanup completed without errors. The corrected browser expands the actual
viewport to measured content height and requires the full expected title multiset
simultaneously visible. Missing panels and oversized pages still fail.

The [third four-node trial](docs/evidence/daemonset-telemetry/fence/summary.json)
passes168 audited client attempts:24 baseline successes and144 expected quarantine
denials, including48 additional telemetry-load attempts. Another84 mesh continuity
checks pass separately. Exact map/program identity, raw kernel deltas, quiet idle,
source Targets APIs, fresh central sample timestamps, cluster selection, SIGKILL/
adoption, node deselection, daemon absence, absent telemetry, defunct retirement
and foreign/native-link cleanup pass with zero cleanup errors. No fence from that
trial remains. The [separate worker lifecycle trial](docs/evidence/daemonset-telemetry/fence-lifecycle/summary.json)
also passes84 attempts (36 baseline/recovery successes,48 denials), corrupted
adoption rejection, stale-Pod identity rejection and exact defunct retirement,
with zero cleanup errors. The [observer trial](docs/evidence/daemonset-telemetry/observer/summary.json)
also passes144 audited attempts:96 native-allowed and48 native-policy-denied.
Both workers demonstrate new kernel map/program IDs and an actual central
counter reset after SIGKILL. Raw endpoints, load/idle, both themes, stale-Pod
rejection, absent telemetry and foreign/native cleanup pass with zero errors.
All six collector families now have collection/query/render evidence. This
completes the bounded prototype and its telemetry increment; it does not close
the security gates listed above.

[Full dashboards and readable sections](docs/evidence/daemonset-telemetry/fence/screenshots/)
were inspected in both themes: Operations39/39 panels, Workload Security29/29.
Packet rates and skb byte rates show real load on both clusters. Fractional range
increases are Prometheus extrapolations, not exact HTTP attempt totals. Planned
security metrics and the uninstalled observer remain unavailable. The
[raw integration archive](docs/evidence/daemonset-telemetry/fence/raw-integration.tar.gz)
retains exact commands, outputs, logs and the exercised source snapshot.

Live trial diagnostics remain in `/private/tmp/cmtc-daemonset-20261024/`.
The [delivery status](docs/agile/DELIVERY_STATUS.md) records the next gate and
supersedes historical checkpoints. CI, pushing and image publication remain
deferred. ClusterMesh connectivity works; ztunnel is disabled and cross-cluster
workload mTLS is not qualified.

## Open the measured Grafana windows

The disposable opt-in clients, labels and DaemonSets are removed after each
trial. Use the retained absolute windows to review real measurements after
cleanup; a later live range correctly has no prototype targets.

- [Four-node fence load](http://127.0.0.1:13000/d/cmtc-observe-lab/cmtc-operations?from=1792889979803&to=1792890025855&theme=dark).
- [Two-worker observer load](http://127.0.0.1:13000/d/cmtc-observe-lab/cmtc-operations?from=1792890555035&to=1792890606197&theme=dark).

Both links require the existing local Grafana port-forward and retained
Prometheus history. Static screenshots and raw evidence remain in the repository.
The normal Observe controllers/node agents and existing applications remain.
