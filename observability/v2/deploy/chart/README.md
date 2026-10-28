# cmtc-observability chart

Status: **deployed on the labs (kind).** Release `cmtc-obs`, namespace `monitoring`, revision 2, installed
2026-10-28T07:23Z on kind-cmtc-a (hub) and kind-cmtc-b (member). On 2026-10-28 the render of this chart with
`deploy/kind/values-<cluster>.yaml` equals `helm get manifest` of the release on cmtc-b (14 objects). On cmtc-a (22
objects) it differs in four places, all for the next upgrade: the Grafana dashboards ConfigMap (the panel markers
removed from 5 dashboards), the rules ConfigMap (one comment of `cmtc-slo.rules.yaml`), and the `checksum/dashboards`
and `checksum/rules` annotations, which restart the Grafana and Prometheus Pods. The hub Prometheus is recreated on
an `emptyDir`, so that upgrade drops the hub's stored series of both clusters. The OpenShift form is rendered and
tested by `observability/v2/tests/test_deploy.py` only; no OpenShift cluster has run it.

The chart collects, evaluates and draws CMTC observability v2. What it scrapes is `metrics/contract.json`; the keep
list of every job is the contract's names for that job, and the tests fail when the two differ.

## What it installs

| Platform | Cluster | Objects |
| --- | --- | --- |
| kind | hub (`hub.enabled=true`) | Prometheus (remote-write receiver, rule files), Grafana with the five dashboards, ClusterIP Services; with `ingress.enabled`, an Ingress for each and a cert-manager Certificate (or an existing TLS Secret) |
| kind | member | Prometheus with `remote_write` to the hub, a ClusterIP Service |
| OpenShift (`global.openshift=true`) | any | PodMonitors in each target's namespace, one PrometheusRule, a PersesDatasource and five PersesDashboards, a Grafana dashboard ConfigMap |

On kind the Prometheus ServiceAccount gets `pods` get/list/watch in each scraped namespace only (a Role per
namespace), and `nodes` and `nodes/metrics` for the kubelet's cAdvisor page (one ClusterRole).

## Install on the labs (kind)

The CMTC Pods admit scrapes from the namespace `monitoring` only (NetworkPolicy `cmtc-metrics` of `charts/cmtc`).
Install into `monitoring`. `scripts/lab/up.sh` installs the release on both clusters, the hub first. The labs'
earlier Prometheus and Grafana (`scripts/lab/monitoring.py`, objects named `prometheus` and `grafana`) are removed;
this chart's objects are named `<release>-*`.

The hub is reached through Cilium Ingress, never a node port. Before the install:

1. Cilium on cmtc-a runs its Ingress controller, with an address from LB IPAM announced on the kind network (L2
   announcements).
2. `<cluster>-ingress-intermediate` exists (`scripts/lab/pki/mesh-pki.sh`, `config/lab-pki/ingress.yaml`); the
   chart's Certificate for the hosts is issued from it.
3. The labs' CoreDNS answers `*.cmtc-a.localtest.me` with cmtc-a's Ingress address. Public DNS answers `127.0.0.1`
   for every `localtest.me` name, so a lookup that misses stays on loopback.
4. On cmtc-b, the namespace `monitoring` carries `trust: enabled`, so trust-manager writes the mesh root ConfigMap
   `cmtc-mesh-root`; the remote write verifies the hub's certificate against it.

```sh
deploy/sync-files.sh
helm upgrade --install cmtc-obs deploy/chart --kube-context kind-cmtc-a -n monitoring -f deploy/kind/values-cmtc-a.yaml
helm upgrade --install cmtc-obs deploy/chart --kube-context kind-cmtc-b -n monitoring -f deploy/kind/values-cmtc-b.yaml
```

## Install on OpenShift

A cluster administrator first:

1. turns on user workload monitoring (`enableUserWorkload: true` in `cluster-monitoring-config`);
2. lists the release namespace in `namespacesWithoutLabelEnforcement` (`user-workload-monitoring-config`): the rules
   read several namespaces;
3. sets the external label `cluster: <clusterName>` on the platform Prometheus (`prometheusK8s.externalLabels`):
   the CoreDNS (`dns-default`), kubelet and `kube_node_info` series the rules read come from it.

Then `helm upgrade --install cmtc-obs deploy/chart -n <namespace> --set global.openshift=true --set clusterName=<name>`,
with `jobs.<job>.namespace` set where the platform runs Cilium, ztunnel or cert-manager elsewhere than on kind.

## Values that matter

| Value | Default | Why |
| --- | --- | --- |
| `clusterName` | required | the `cluster` label of every series |
| `hub.expectedClusters` | `clusterName` | an absent cluster is an alert (`CMTCClusterMetricsAbsent`), never a healthy zero |
| `prometheus.retention` | `7h` | the longest rule window is 6 h (`rules/cmtc-slo.rules.yaml`) |
| `jobs.cadvisor.insecureSkipVerify` | `true` | kind's kubelets serve self-signed certificates; an operator decision |
| `jobs.spireServer.enabled`, `jobs.spireAgent.enabled` | `false` | SPIRE's telemetry is not configured on the labs (`source-patches/cmtc/0002`) |
| `rules.includeProposed` | `false` | rules on metrics that need a source change; they return nothing until it runs |
| `dashboards.clusters` | `[cmtc-a, cmtc-b]` | the two clusters the dashboards draw, each in one fixed colour |

## Files

`files/` is a copy of `../../rules/` and `../../dashboards/`, made by `../sync-files.sh`; edit the originals.
