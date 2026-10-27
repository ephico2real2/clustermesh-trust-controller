"""deploy/chart renders for the kind hub, a kind member and OpenShift, and what it renders scrapes, keeps and
evaluates exactly what metrics/contract.json and rules/ define. Needs helm (and promtool for its checks)."""
import filecmp
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

import helmyaml
import model

VALUES_KEY = {"cmtc": "cmtc", "cilium-native": "ciliumAgent", "ztunnel": "ztunnel", "coredns": "coredns",
              "cert-manager": "certManager", "trust-manager": "trustManager", "cadvisor": "cadvisor",
              "prometheus": "prometheus", "spire-server": "spireServer", "spire-agent": "spireAgent"}
KEEP = re.compile(r"^\((?P<names>[^()]+)\)\(_bucket\|_sum\|_count\|_total\)\?$")
HUB = ("clusterName=cmtc-a", "hub.enabled=true", "hub.expectedClusters={cmtc-a,cmtc-b}")
MEMBER = ("clusterName=cmtc-b", "remoteWrite.url=http://172.18.0.3:30900/api/v1/write")
OPENSHIFT = ("clusterName=ocp-1", "global.openshift=true")
# Off by default: they need source-patches/cmtc/0002, which declares the SPIRE telemetry port "prom".
SPIRE = ("jobs.spireServer.enabled=true", "jobs.spireAgent.enabled=true")
SPIRE_JOBS = {"spire-server", "spire-agent"}
# Platform-scraped on OpenShift; kind only here.
KIND_ONLY = {"coredns", "cadvisor", "prometheus"}


def contract_names(job):
    """The names the contract lists for a job's components; up and ALERTS are Prometheus' own."""
    return {m["name"] for m in model.contract()["metrics"]
            if model.job_of(m["component"]) == job and m["name"] not in ("up", "ALERTS")}


def kept(regex):
    match = KEEP.match(regex)
    if not match:
        raise AssertionError(f"not a keep list of cmtc-obs.keep: {regex}")
    return set(match.group("names").split("|"))


def by_kind(objects, kind):
    return [o for o in objects if o["kind"] == kind]


def named(objects, kind, name):
    found = [o for o in objects if o["kind"] == kind and o["metadata"]["name"] == name]
    if len(found) != 1:
        raise AssertionError(f"{kind}/{name}: {len(found)} rendered")
    return found[0]


def promtool():
    return os.environ.get("PROMTOOL") or shutil.which("promtool")


# Words for a reader, which may name the lab clusters: Grafana's titles, descriptions and text, Perses' names and
# Markdown.
PROSE = {"title", "description", "content", "name", "text"}


def machine_strings(node, key=None):
    """Every key and string value of a dashboard that a query or a colour rule reads, prose left out."""
    if isinstance(node, dict):
        for k, value in node.items():
            yield k
            yield from machine_strings(value, k)
    elif isinstance(node, list):
        for value in node:
            yield from machine_strings(value, key)
    elif isinstance(node, str) and key not in PROSE:
        yield node


@unittest.skipUnless(helmyaml.available(), "helm not found")
class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hub = helmyaml.render(*HUB)
        cls.member = helmyaml.render(*MEMBER)
        cls.openshift = helmyaml.render(*OPENSHIFT, namespace="cmtc-observability")
        cls.renamed = helmyaml.render(*OPENSHIFT, "dashboards.clusters={ocp-1,ocp-2}", namespace="cmtc-observability")
        cls.spire = helmyaml.render(*HUB, *SPIRE)
        cls.spire_openshift = helmyaml.render(*OPENSHIFT, *SPIRE, namespace="cmtc-observability")
        cls.values = helmyaml.load([(helmyaml.CHART / "values.yaml").read_text()])[0]
        cls.enabled = {job for job, key in VALUES_KEY.items() if cls.values["jobs"][key]["enabled"]}

    def config(self, objects):
        cm = named(objects, "ConfigMap", "cmtc-obs-prometheus")
        return helmyaml.load([cm["data"]["prometheus.yml"]])[0]

    def test_missing_cluster_name_fails(self):
        done = subprocess.run([helmyaml.HELM, "template", "x", str(helmyaml.CHART)], capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("clusterName is required", done.stderr)

    def test_schema_refuses_unknown_values_and_tags(self):
        # Helm 3 and Helm 4 word schema errors differently; both name the property and the pattern.
        for setting, reason in (("jobs.cmtc.bogus=1", r"bogus"),
                                ("prometheus.image=quay.io/prometheus/prometheus:v3.7.0", r"image.*sha256")):
            with self.subTest(setting=setting):
                done = subprocess.run([helmyaml.HELM, "template", "x", str(helmyaml.CHART), "--set", "clusterName=x",
                                       "--set", setting], capture_output=True, text=True)
                self.assertNotEqual(done.returncode, 0)
                self.assertRegex(done.stderr, reason)

    def test_keep_lists_are_the_contract(self):
        for job, key in VALUES_KEY.items():
            with self.subTest(job=job):
                self.assertEqual(set(self.values["jobs"][key]["keep"]), contract_names(job))

    def test_kind_jobs(self):
        for objects, enabled in ((self.hub, self.enabled), (self.member, self.enabled),
                                 (self.spire, self.enabled | SPIRE_JOBS)):
            jobs = {j["job_name"]: j for j in self.config(objects)["scrape_configs"]}
            self.assertEqual(set(jobs), enabled)
            for name, job in jobs.items():
                with self.subTest(job=name):
                    keep = [r for r in job["metric_relabel_configs"] if r.get("source_labels") == ["__name__"]]
                    self.assertEqual(kept(keep[0]["regex"]), contract_names(name))
                    targets = {r["target_label"] for r in job["relabel_configs"] if "target_label" in r} - {"__address__"}
                    components = [c for c in model.contract()["components"].values() if c["job"] == name]
                    for component in components:
                        self.assertEqual(targets | {"job", "instance"}, set(component["target_labels"]))
                    drops = [r["regex"] for r in job["metric_relabel_configs"] if r.get("action") == "labeldrop"]
                    dropped = {l for c in components for l in c.get("dropped_labels", [])}
                    if dropped:
                        self.assertEqual(len(drops), 1)
                        self.assertEqual({l for l in dropped if re.fullmatch(drops[0], l)}, dropped)
                    else:
                        self.assertEqual(drops, [])

    def test_spire_jobs_scrape_the_prom_port(self):
        """One target per SPIRE container: its port "prom" (source-patches/cmtc/0002), never one per declared port."""
        jobs = {j["job_name"]: j for j in self.config(self.spire)["scrape_configs"]}
        monitors = {o["metadata"]["name"]: o for o in by_kind(self.spire_openshift, "PodMonitor")}
        for job in sorted(SPIRE_JOBS):
            with self.subTest(job=job):
                relabels = jobs[job]["relabel_configs"]
                self.assertIn({"source_labels": ["__meta_kubernetes_pod_container_port_name"], "regex": "prom",
                               "action": "keep"}, relabels)
                self.assertEqual([r for r in relabels if r.get("target_label") == "__address__"], [])
                self.assertEqual(monitors[f"cmtc-obs-{job}"]["spec"]["podMetricsEndpoints"][0]["port"], "prom")

    def test_hub_and_member(self):
        hub, member = self.config(self.hub), self.config(self.member)
        self.assertEqual(hub["global"]["external_labels"], {"cluster": "cmtc-a"})
        self.assertEqual(member["global"]["external_labels"], {"cluster": "cmtc-b"})
        self.assertIn("rule_files", hub)
        self.assertNotIn("rule_files", member)
        self.assertNotIn("remote_write", hub)
        self.assertEqual(member["remote_write"], [{"url": "http://172.18.0.3:30900/api/v1/write"}])
        args = lambda objects: named(objects, "Deployment", "cmtc-obs-prometheus")["spec"]["template"]["spec"][
            "containers"][0]["args"]
        self.assertIn("--web.enable-remote-write-receiver", args(self.hub))
        self.assertNotIn("--web.enable-remote-write-receiver", args(self.member))
        self.assertIn(f"--storage.tsdb.retention.time={self.values['prometheus']['retention']}", args(self.hub))
        self.assertEqual(named(self.hub, "Service", "cmtc-obs-prometheus")["spec"]["ports"][0]["nodePort"], 30900)
        self.assertNotIn("type", named(self.member, "Service", "cmtc-obs-prometheus")["spec"])
        self.assertTrue(by_kind(self.hub, "Deployment") and named(self.hub, "Deployment", "cmtc-obs-grafana"))
        self.assertEqual([o["metadata"]["name"] for o in by_kind(self.member, "Deployment")], ["cmtc-obs-prometheus"])

    def test_rules_are_the_rule_files(self):
        data = named(self.hub, "ConfigMap", "cmtc-obs-prometheus-rules")["data"]
        self.assertEqual(set(data), {p.name for p in model.rule_files(proposed=False)})
        for name, content in data.items():
            if name == "cmtc-collection.rules.yaml":
                self.assertIn('label_replace(vector(1), "cluster", "cmtc-b", "", "")', content)
            else:
                self.assertEqual(content, (model.RULES / name).read_text())

    def test_least_privilege(self):
        for objects, enabled in ((self.hub, self.enabled), (self.spire, self.enabled | SPIRE_JOBS)):
            jobs = [self.values["jobs"][VALUES_KEY[j]] for j in enabled]
            namespaces = {job["namespace"] for job in jobs if "namespace" in job} | {"monitoring"}
            roles = by_kind(objects, "Role")
            self.assertEqual({r["metadata"]["namespace"] for r in roles}, namespaces)
            for role in roles:
                self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["pods"],
                                                  "verbs": ["get", "list", "watch"]}])
            (cluster_role,) = by_kind(objects, "ClusterRole")
            self.assertEqual(cluster_role["rules"], [
                {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list", "watch"]},
                {"apiGroups": [""], "resources": ["nodes/metrics"], "verbs": ["get"]}])

    def test_pods_are_restricted_and_pinned(self):
        for objects in (self.hub, self.member):
            for deployment in by_kind(objects, "Deployment"):
                spec = deployment["spec"]["template"]["spec"]
                with self.subTest(deployment=deployment["metadata"]["name"]):
                    self.assertTrue(spec["securityContext"]["runAsNonRoot"])
                    self.assertEqual(spec["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
                    for container in spec["containers"]:
                        self.assertRegex(container["image"], r"@sha256:[0-9a-f]{64}$")
                        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
                        self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})

    def test_grafana_password_is_a_secret(self):
        grafana = named(self.hub, "Deployment", "cmtc-obs-grafana")["spec"]["template"]["spec"]["containers"][0]
        env = {e["name"]: e for e in grafana["env"]}
        self.assertEqual(env["GF_SECURITY_ADMIN_PASSWORD"]["valueFrom"]["secretKeyRef"],
                         {"name": "cmtc-obs-grafana-admin", "key": "admin-password"})
        self.assertNotRegex((helmyaml.CHART / "values.yaml").read_text(), r"(?im)^\s*[a-z]*password:\s*\S")

    def test_openshift(self):
        for objects, enabled in ((self.openshift, self.enabled), (self.spire_openshift, self.enabled | SPIRE_JOBS)):
            kinds = {o["kind"] for o in objects}
            self.assertFalse(kinds & {"Deployment", "Service", "Role", "ClusterRole"}, kinds)
            # The data source every Perses query names (tests/test_dashboards.py, PersesForm).
            named(objects, "PersesDatasource", "cmtc-thanos")
            monitors = {o["metadata"]["name"]: o for o in by_kind(objects, "PodMonitor")}
            self.assertEqual(set(monitors), {f"cmtc-obs-{job}" for job in enabled - KIND_ONLY})
            for name, monitor in monitors.items():
                job = name.removeprefix("cmtc-obs-")
                endpoint = monitor["spec"]["podMetricsEndpoints"][0]
                with self.subTest(monitor=name):
                    self.assertEqual(monitor["metadata"]["namespace"], self.values["jobs"][VALUES_KEY[job]]["namespace"])
                    relabels = {r.get("targetLabel"): r for r in endpoint["relabelings"]}
                    self.assertEqual(relabels["job"]["replacement"], job)
                    self.assertEqual(relabels["cluster"]["replacement"], "ocp-1")
                    self.assertIn("node", relabels)
                    self.assertIn("component", relabels)
                    keep = [r for r in endpoint["metricRelabelings"] if r.get("sourceLabels") == ["__name__"]]
                    self.assertEqual(kept(keep[0]["regex"]), contract_names(job))

    def test_openshift_rules_use_the_platform_jobs(self):
        (rule,) = by_kind(self.openshift, "PrometheusRule")
        groups = rule["spec"]["groups"]
        self.assertEqual(len({g["name"] for g in groups}), len(groups), "one PrometheusRule: group names are unique")
        want = sum(len(g["rules"]) for p, d in model.parsed_rules().items() if p.parent.name != "proposed"
                   for g in d["groups"])
        self.assertEqual(sum(len(g["rules"]) for g in groups), want)
        exprs = [r["expr"] for g in groups for r in g["rules"]]
        self.assertFalse([e for e in exprs if re.search(r'job=~?"[^"]*\b(coredns|cadvisor)\b', e)])
        records = {r["record"]: r["expr"] for g in groups for r in g["rules"] if "record" in r}
        self.assertEqual(records["cmtc:expected_node:info"], "group by (cluster, node) (kube_node_info)")
        self.assertEqual(records["cmtc:expected_cluster:info"], 'label_replace(vector(1), "cluster", "ocp-1", "", "")')
        dashboards = named(self.openshift, "ConfigMap", "cmtc-obs-grafana-dashboards")["data"]
        self.assertEqual(set(dashboards), set(model.dashboards()))
        for name, content in dashboards.items():
            with self.subTest(dashboard=name):
                self.assertNotRegex(content, r'job=\\"(coredns|cadvisor)\\"')

    def test_dashboards_follow_the_cluster_names(self):
        """dashboards.clusters renames the two clusters in every query and colour rule, in both forms."""
        grafana = named(self.renamed, "ConfigMap", "cmtc-obs-grafana-dashboards")["data"]
        perses = {o["metadata"]["name"]: o["spec"]["config"] for o in by_kind(self.renamed, "PersesDashboard")}
        self.assertEqual(set(perses), {p.stem for p in (model.V2 / "dashboards/perses").glob("*.json")})
        self.assertEqual(set(grafana), set(model.dashboards()))
        forms = {**{f"grafana/{n}": json.loads(t) for n, t in grafana.items()},
                 **{f"perses/{n}": c for n, c in perses.items()}}
        for name, form in forms.items():
            words = set(machine_strings(form))
            with self.subTest(dashboard=name):
                self.assertEqual(sorted(w for w in words if re.search(r"cmtc-[ab]\b", w)), [])
                for cluster in ("ocp-1", "ocp-2"):
                    self.assertTrue(any(f'cluster="{cluster}"' in w for w in words), cluster)

    def test_dashboards_are_the_files(self):
        data = named(self.hub, "ConfigMap", "cmtc-obs-grafana-dashboards")["data"]
        self.assertEqual(data, {name: (model.DASHBOARDS / name).read_text() for name in model.dashboards()})

    @unittest.skipUnless(promtool(), "promtool not found: set PROMTOOL")
    def test_promtool_accepts_the_render(self):
        with tempfile.TemporaryDirectory() as work:
            work = pathlib.Path(work)
            for name, objects in (("hub", self.hub), ("member", self.member), ("spire", self.spire)):
                path = work / f"{name}.yml"
                path.write_text(named(objects, "ConfigMap", "cmtc-obs-prometheus")["data"]["prometheus.yml"])
                done = subprocess.run([promtool(), "check", "config", "--syntax-only", str(path)],
                                      capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            files = []
            for name, content in named(self.hub, "ConfigMap", "cmtc-obs-prometheus-rules")["data"].items():
                files.append(work / name)
                files[-1].write_text(content)
            groups = by_kind(self.openshift, "PrometheusRule")[0]["spec"]["groups"]
            (work / "openshift.json").write_text(json.dumps({"groups": groups}))
            files.append(work / "openshift.json")
            done = subprocess.run([promtool(), "check", "rules", *map(str, files)], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stdout[-3000:] + done.stderr[-3000:])


class ChartFiles(unittest.TestCase):
    """deploy/chart/files/ is a copy of rules/ and dashboards/ (deploy/sync-files.sh)."""

    def test_copies_are_identical(self):
        pairs = [(model.RULES, helmyaml.CHART / "files/rules", "*.rules.yaml"),
                 (model.RULES / "proposed", helmyaml.CHART / "files/rules/proposed", "*.rules.yaml"),
                 (model.DASHBOARDS, helmyaml.CHART / "files/dashboards/grafana", "*.json"),
                 (model.V2 / "dashboards/perses", helmyaml.CHART / "files/dashboards/perses", "*.json")]
        for source, copy, pattern in pairs:
            originals = {p.name for p in source.glob(pattern)}
            copies = {p.name for p in copy.glob(pattern)}
            with self.subTest(directory=copy.relative_to(model.V2).as_posix()):
                self.assertEqual(copies, originals, "run deploy/sync-files.sh")
                for name in originals:
                    self.assertTrue(filecmp.cmp(source / name, copy / name, shallow=False), f"{name} differs")


if __name__ == "__main__":
    unittest.main()
