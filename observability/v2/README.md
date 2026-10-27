# CMTC observability v2

**Status, 2026-10-27:** implemented in this folder and checked by the tests below on macOS. Not installed on a
cluster and not traffic-qualified. Tracking issue: #37. The owner reviews and commits it.

v2 replaces the v1 design in `observability/`: `capabilities.json`, `metrics.json`, the eleven dashboards and
`prometheus/`. v1 stays in place until the steps of [the migration plan](docs/MIGRATION.md) run.

## The parts and their state

| Part | What it holds | State |
| --- | --- | --- |
| [`metrics/`](metrics/) | `contract.json`: one entry for each metric, 84 in all, and its JSON schema | Implemented and tested here |
| [`rules/`](rules/) | 9 rule files (49 alerts, 45 recording rules); 5 files in `proposed/` (20 alerts, 20 recording rules) on metrics that need a source change; 14 `promtool` test files | Implemented and tested here with promtool 3.7.0; not deployed |
| [`dashboards/grafana/`](dashboards/grafana/) | 5 Grafana dashboards: 118 panels that draw data, 30 text panels | Implemented and tested here; every query run read-only on the lab hub ([live results](docs/METRICS_AND_SLOS.md#live-results)) |
| [`dashboards/perses/`](dashboards/perses/) | The Perses form, generated from the Grafana JSON | Generated and tested here; not loaded in an OpenShift console |
| [`deploy/`](deploy/) | The Helm chart `cmtc-observability`, for kind (hub and member) and OpenShift | Implemented, rendered and tested here; not installed |
| [`tests/`](tests/) | The validators: contract, rules, dashboards, chart | Implemented and run here |
| [`docs/`](docs/) | [Metrics and service objectives](docs/METRICS_AND_SLOS.md), [collection](docs/COLLECTION.md), [migration from v1](docs/MIGRATION.md), figures | Written here |
| [`source-patches/`](source-patches/) | Patches against the deployed fork and CMTC commits, each with its unit test | UNEXECUTED: not compiled, unit tests not run |

There is no `collectors/` folder. Each signal has an exporter in the process that observes it, so a collector of
our own would make a second reporter for the same event. The client-side DNS signal comes from the eBPF measurement
plane, which the CMTC node agent exports (#36).

## Readers and their questions

Three readers use these dashboards. The **operator** asks whether every Required workload is protected, and if not,
why not. The **security reviewer** asks what was denied, what was revoked, and how long revocation took. **On-call**
asks what is broken now, and which component owns it. Each question has a dashboard row of the same name.

| ID | Reader | Question |
| --- | --- | --- |
| OC1 | on-call | Can these numbers be trusted: is every exporter scraped, and does the hub receive cmtc-b? |
| OC2 | on-call | Which alerts are firing, and which component owns them? |
| OC3 | on-call | Will workload mTLS keep working: is the issuer profile published, does the approval pin the CA SPIRE signs with, and do connections succeed? |
| OC4 | on-call | Are the mesh certificates and processes healthy? |
| OC5 | on-call | Do the service objectives hold? |
| OP1 | operator | Which namespaces are meant to be protected, and is every Required workload released? |
| OP2 | operator | Are Pods captured and enrolled in ztunnel? |
| OP3 | operator | Which callers are admitted as policy sources, and are their plans published and acknowledged? |
| OP4 | operator | Does every node know the peer cluster's workloads? |
| OP5 | operator | Is protected traffic flowing? |
| OP6 | operator | Do in-Pod proxies fetch workload certificates at a normal rate? |
| SEC1 | security reviewer | What did policy deny, and where? |
| SEC2 | security reviewer | What was revoked, was it presented, and how long did the revocation take? |
| SEC3 | security reviewer | Were connections refused over trust or identity? |
| DNS1 | on-call | Is CoreDNS answering, and with which response codes? |
| DNS2 | on-call | Is CoreDNS fast, and are its upstream resolvers healthy? |
| DNS3 | on-call | Do enrolled Pods get answers to their DNS queries, or are the queries dropped first? |

The five dashboards:

| Dashboard | UID | Reader |
| --- | --- | --- |
| CMTC on-call overview | `cmtc-v2-on-call` | on-call |
| CMTC workload protection | `cmtc-v2-protection` | operator |
| CMTC trust profile and issuer succession | `cmtc-v2-trust` | on-call, operator |
| CMTC security events | `cmtc-v2-security` | security reviewer |
| CMTC DNS | `cmtc-v2-dns` | on-call |

## How a question becomes a panel

1. A reader asks a question. The contract records it under `questions`, with the dashboard rows that answer it.
2. The contract names the component that can answer it truthfully. One event has one reporter.
3. The contract entry gives the metric's name, type, unit and labels, a bound on each label's values, the owner,
   the source file and function at the deployed commit, its status and its collection.
4. `deploy/` scrapes that component. The keep list of each job is the contract's names for that job.
5. `rules/` derives recording rules, service-level indicators and alerts. Every rule has a `promtool` test.
6. A dashboard row asks the question. Its panels give the answer, and each says when its data is unavailable.

The tests join these steps: a name that a rule or panel reads must be in the contract, a keep list must equal the
contract, and every question must have its row.

## Three status classes

| Class | Meaning | Title marker |
| --- | --- | --- |
| current | The deployed source emits it, and the labs scrape it today | none |
| proposed | The deployed source emits it; it is collected once `deploy/` is installed | ` · proposed` |
| planned | It needs a source change first: a patch in `source-patches/`, or the measurement plane of #36 | ` · planned` |

The tests compute the class of each panel from its queries and the contract. A panel takes the class of its least
ready query. A row takes the class of its most ready panel. A title that claims more than its queries can deliver
fails the tests, and so does a description that does not start with what the panel waits for.

## Signal map

The lifecycle runs from namespace intent to traffic, then revocation. The trust, PKI, DNS, measurement, collection
and platform stages support it. The counts are metric entries of the contract, by class.

| Stage | What it covers | Reporters | Current | Proposed | Planned |
| --- | --- | --- | --- | --- | --- |
| intent | Which namespaces CMTC selects for protection | CMTC controller | 6 | 0 | 0 |
| inventory | What the node agent observes on its node; never enforcement | CMTC node agent | 2 | 0 | 0 |
| enrollment | Capture and ZDS enrollment of a Pod into ztunnel, and its in-Pod proxy | Cilium agent, ztunnel | 4 | 2 | 0 |
| identity | The workload certificates ztunnel fetches, and the CA that signs them | SPIRE server, SPIRE agent | 0 | 0 | 3 |
| admission | The callers the Cilium agent admits into effective plans | Cilium agent | 3 | 0 | 1 |
| publication | Effective plans published to ztunnel over xDS, and their acknowledgment | Cilium agent, ztunnel | 2 | 1 | 3 |
| release | Quarantine release of a Required workload | Cilium agent | 0 | 0 | 1 |
| traffic | Connections opened and failed, TLS handshakes, datapath drops | ztunnel, Cilium agent | 0 | 5 | 0 |
| revocation | Certificate revocation and policy narrowing reaching the datapath | ztunnel | 0 | 2 | 1 |
| trust | The issuer profile CMTC publishes, and the approval it pins (ADR-010) | CMTC controller | 4 | 0 | 5 |
| pki | The mesh PKI of ADR-011: Certificates and the trust-manager Bundle | cert-manager, trust-manager | 0 | 5 | 0 |
| dns | CoreDNS on the server side, the measurement plane on the client side | CoreDNS, CMTC node agent | 0 | 12 | 5 |
| measurement | The eBPF measurement plane of ADR-005 itself | CMTC node agent | 0 | 0 | 7 |
| collection | Scrapes, remote write to the hub, alert evaluation | Prometheus | 1 | 5 | 0 |
| platform | Process IDs, reconcile errors, leadership | CMTC controller, kubelet | 2 | 2 | 0 |
| **all** | | | **24** | **34** | **26** |

![Signal flow: each component's exporter, the scrape in its cluster, remote write to the hub, rules and dashboards](docs/figures/signal-flow.light.png)

The figure source is [docs/figures/source.html](docs/figures/source.html). [docs/METRICS_AND_SLOS.md](docs/METRICS_AND_SLOS.md)
maps each question to its metrics.

## Rules that every part keeps

- **Protected is never inferred.** A label, readiness, a registration, an ACK, a certificate or a TLS shape does
  not prove protection. Control-plane verdicts are prerequisites; traffic outcomes are the evidence.
- **Unavailable is never zero.** No rule or panel fabricates `vector(0)`. Every job has an alert on its `up`
  series, the hub expects a fixed list of clusters and nodes, and an empty number or table says why it is empty.
- **One reporter per event.** A denial is counted by the ztunnel that refused it, a release by the Cilium agent
  that granted it.
- **Every series keeps `cluster` and `node`,** and `namespace` and `pod` for a Pod target. cmtc-b's series reach the
  hub by remote write.
- **One colour per cluster:** cmtc-a blue `#4e79a7`, cmtc-b red `#e15759`, from the Tableau 10 palette only.

## Run the checks

The tests need Python 3.9 or later (the standard library only), Helm 3 or 4, and promtool 3.7.0 for the rule
tests. Python has no YAML parser of its own, so the tests parse YAML through Helm (`tests/helmyaml.py`). Without
promtool, its tests report as skipped, not passed.

```sh
cd observability/v2
deploy/sync-files.sh --check
PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
rules/run-promtool.sh                     # the pinned Prometheus image, with podman or docker
PROMTOOL=/path/to/promtool rules/run-promtool.sh
```

CI does not run these tests yet: `unittest discover -s observability` does not enter `v2/tests`, which is not a
package. [The migration plan](docs/MIGRATION.md) adds the step.

## Change something

- **Add a metric:** add its contract entry, then its name to the job's keep list in `deploy/chart/values.yaml`,
  then the rules and their tests, then the panel. Run the tests.
- **Change a dashboard:** edit the Grafana JSON only. Generate the Perses form with
  `~/.local/share/diagram-kit/.venv/bin/perses-dashboard dashboards/grafana/<name>.json dashboards/perses/<name>.json --datasource cmtc-thanos`,
  then run `deploy/sync-files.sh` and the tests.
- **Change a rule:** edit `rules/`, update its test in `rules/tests/`, then run `rules/run-promtool.sh`,
  `deploy/sync-files.sh` and the tests.
