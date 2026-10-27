# cmtc-observability chart

Status: **implemented, not installed.** `observability/v2/tests/test_deploy.py` renders the chart for the three
cases below and checks the result; no cluster has run it. `docs/COLLECTION.md` lists what to measure after the first
install.

The chart collects, evaluates and draws CMTC observability v2. What it scrapes is `metrics/contract.json`; the keep
list of every job is the contract's names for that job, and the tests fail when the two differ.

## What it installs

| Platform | Cluster | Objects |
| --- | --- | --- |
| kind | hub (`hub.enabled=true`) | Prometheus (remote-write receiver, rule files), its Service on NodePort 30900, Grafana with the five dashboards |
| kind | member | Prometheus with `remote_write` to the hub, a ClusterIP Service |
| OpenShift (`global.openshift=true`) | any | PodMonitors in each target's namespace, one PrometheusRule, a PersesDatasource and five PersesDashboards, a Grafana dashboard ConfigMap |

On kind the Prometheus ServiceAccount gets `pods` get/list/watch in each scraped namespace only (a Role per
namespace), and `nodes` and `nodes/metrics` for the kubelet's cAdvisor page (one ClusterRole).

## Install on the labs (kind)

The CMTC Pods admit scrapes from the namespace `monitoring` only (NetworkPolicy `cmtc-metrics` of `charts/cmtc`).
Install into `monitoring`, after removing the lab's own monitoring objects there (`scripts/lab/monitoring.py`
creates a Deployment, Service and ConfigMap named `prometheus`; this chart's objects are named `<release>-*`).

```sh
deploy/sync-files.sh
helm upgrade --install cmtc-obs deploy/chart --kube-context kind-cmtc-a -n monitoring \
  --set clusterName=cmtc-a --set hub.enabled=true --set 'hub.expectedClusters={cmtc-a,cmtc-b}'
helm upgrade --install cmtc-obs deploy/chart --kube-context kind-cmtc-b -n monitoring \
  --set clusterName=cmtc-b --set remoteWrite.url=http://<a cmtc-a node IP>:30900/api/v1/write
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
