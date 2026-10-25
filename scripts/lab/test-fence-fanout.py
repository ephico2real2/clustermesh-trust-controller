#!/usr/bin/env python3
"""Simultaneous two-node DaemonSet qualification, actual cmtc-a/b contexts.
Uses explicit physical node routes; qualifies quarantine, never workload mTLS.
"""
import argparse
import copy
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import traceback
import uuid

LIB = Path(__file__).resolve().parent
sys.path.insert(0, str(LIB))
spec = importlib.util.spec_from_file_location("fence_lab", LIB / "test-fence.py")
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)
from fence_manifest_contract import validate_fence_template
require, OWNER, DS, SYSTEM = lab.require, lab.OWNER, lab.DS, lab.SYSTEM
RUN_SELECTOR = "security.cmtc.io/fence-distribution-run"


class NodeHarness(lab.FenceHarness):
    """One actual (cluster,node) route. No synthetic cluster aliases/globals."""
    def __init__(self, args, cluster, node, run_id, parents, out):
        local = copy.copy(args); local.out = str(out); local.directions = ["ingress"]; local.fanout = True
        super().__init__(local)
        self.template = validate_fence_template(self.template, fanout=True)
        self.cluster, self.physical_node, self.parent_registry = cluster, node, parents
        self.run_id = run_id
        self.ns = "cmtc-fanout-" + run_id + "-" + node.removeprefix(cluster + "-")
        self.report.update(run=run_id, scope="explicit-node-daemonset-fanout", cluster=cluster, node=node)
        self.report["clusters"] = {}; self.parents = {}; self.flush()

    def node_name(self, cluster):
        require(cluster == self.cluster, "physical node route crossed actual cluster context")
        return self.physical_node

    def state(self): return self.report["clusters"][self.cluster]

    def backend(self, cluster):
        # Read-only backend catalogue is not node-owned lifecycle state.
        return self.backend_catalog[cluster]

    def prepare(self, backends):
        c, n = self.cluster, self.physical_node
        node = self.get(c, "node", n)
        require(lab.OPTIN not in node["metadata"].get("labels", {}) and RUN_SELECTOR not in node["metadata"].get("labels", {}) and OWNER not in node["metadata"].get("annotations", {}), "preexisting node opt-in/owner")
        agents = json.loads(self.kubectl(c, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "--field-selector", "spec.nodeName=" + n, "-o", "json").stdout)["items"]
        require(len(agents) == 1 and agents[0]["status"].get("containerStatuses") and all(s.get("ready") for s in agents[0]["status"]["containerStatuses"]), "exact selected-node Cilium agent not Ready")
        self.backend_catalog = copy.deepcopy(backends)
        self.report["backendCatalogue"] = self.backend_catalog
        self.report["clusters"] = {c: {"backend": backends[c], "nodeUID": node["metadata"]["uid"],
            "agent": {"name": agents[0]["metadata"]["name"], "uid": agents[0]["metadata"]["uid"]}, "roots": {}, "phases": [], "cases": []}}
        state = self.state(); state["foreignBaseline"] = self.tc(c)
        require(not any(r.get("name") in ("cmtc_fence", "cmtc_observe") for r in state["foreignBaseline"]), "foreign custom hook")
        self.node(c, "sh", "-c", "command -v nsenter && command -v crictl && command -v ip && command -v flock")
        image = json.loads(self.node(c, "crictl", "inspecti", self.args.image).stdout)
        require(image["status"]["id"] == self.args.image_id and image["info"]["imageSpec"]["architecture"] == "arm64", "exact image not loaded on selected node")
        state["importedImage"] = image
        client_image = json.loads(self.node(c, "crictl", "inspecti", self.args.client_image).stdout)
        require(client_image["info"]["imageSpec"]["architecture"] == "arm64", "ARM64 client image must be cached before creating fixtures")
        state["clientImportedImage"] = client_image
        require(self.get(c, "namespace", self.ns, absent=True) is None, "fanout namespace exists")
        self.create(c, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.ns}})
        state["namespaceUID"] = self.get(c, "namespace", self.ns)["metadata"]["uid"]
        self.prepare_roots(c)
        pod = self.new_client(c)
        phase = self.audit(c, pod, "ingress")
        # Record absence, rather than inventing or attaching an egress anchor.
        phase["nativeEgressTCX"] = self.chain_for(self.tc(c), phase["config"]["ifIndex"], "egress")
        phase["nativeEgressQualified"] = False
        self.traffic(c, phase, False)
        self.flush()

    def prepare_roots(self, cluster):
        state = self.state()
        for key, prefix in (("pinRoot", "/sys/fs/bpf/cmtc-fence-"), ("lockRoot", "/run/cmtc-fence-")):
            parent = prefix + self.run_id
            existing = self.node(cluster, "stat", "-c", "%F|%u|%a|%d|%i", parent, check=False)
            if existing.returncode:
                self.node(cluster, "mkdir", "-m", "700", "--", parent)
                identity = self.root_stat(cluster, parent)
                self.parent_registry.add((key, parent, identity))
            else:
                identity = self.root_stat(cluster, parent)
                require((key, parent, identity) in self.parent_registry, "existing parent is not a previously confirmed same-run shared filesystem")
            self.parents[key] = {"path": parent, "stat": identity}
            path = parent + "/" + self.physical_node
            self.node(cluster, "mkdir", "-m", "700", "--", path)
            state["roots"][key] = {"path": path, "stat": self.root_stat(cluster, path)}
            fs = self.node(cluster, "stat", "-f", "-c", "%t", path).stdout.strip()
            require((fs == "cafe4a11") == (key == "pinRoot"), "wrong bpffs/ordinary filesystem route")
            self.flush()

    def node_optin(self, cluster, acquire):
        self.select(acquire, release=not acquire)

    def select(self, enabled, release=False):
        c, n, state = self.cluster, self.physical_node, self.state()
        node = self.get(c, "node", n); meta = node["metadata"]
        require(meta["uid"] == state["nodeUID"], "selected node incarnation changed")
        labels, annotations = meta.get("labels", {}), meta.get("annotations", {})
        escape = lambda s: s.replace("~", "~0").replace("/", "~1")
        patch = [{"op": "test", "path": "/metadata/uid", "value": meta["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]}]
        if OWNER not in annotations and release and lab.OPTIN not in labels and RUN_SELECTOR not in labels:
            state["nodeOwned"] = False
            return
        if OWNER not in annotations:
            require(enabled and not release and lab.OPTIN not in labels and RUN_SELECTOR not in labels, "cannot acquire foreign opt-in")
            if "annotations" not in meta: patch.append({"op": "add", "path": "/metadata/annotations", "value": {}})
            patch += [{"op": "add", "path": "/metadata/annotations/" + escape(OWNER), "value": self.run_id}, {"op": "add", "path": "/metadata/labels/" + escape(RUN_SELECTOR), "value": self.run_id}]
        else:
            require(annotations[OWNER] == self.run_id and labels.get(RUN_SELECTOR) == self.run_id, "node owner changed")
            patch += [{"op": "test", "path": "/metadata/annotations/" + escape(OWNER), "value": self.run_id}, {"op": "test", "path": "/metadata/labels/" + escape(RUN_SELECTOR), "value": self.run_id}]
        if enabled:
            require(lab.OPTIN not in labels, "opt-in already present")
            patch.append({"op": "add", "path": "/metadata/labels/" + escape(lab.OPTIN), "value": "true"})
        elif lab.OPTIN in labels:
            require(labels[lab.OPTIN] == "true", "node opt-in value changed")
            patch += [{"op": "test", "path": "/metadata/labels/" + escape(lab.OPTIN), "value": "true"}, {"op": "remove", "path": "/metadata/labels/" + escape(lab.OPTIN)}]
        if release:
            patch += [{"op": "remove", "path": "/metadata/labels/" + escape(RUN_SELECTOR)}, {"op": "remove", "path": "/metadata/annotations/" + escape(OWNER)}]
        state["nodeOptinAttempted"] = True
        self.kubectl(c, "patch", "node", n, "--type=json", "-p", json.dumps(patch), label="atomic-fanout-node-select")
        state["nodeOwned"] = not release
        self.flush()

    def fence_pod(self, cluster):
        pods = self.get(cluster, "pods", namespace=SYSTEM)["items"]
        selected = [p for p in pods if p["metadata"].get("labels", {}).get("app.kubernetes.io/name") == DS and p["spec"].get("nodeName") == self.physical_node]
        if not selected: return None
        require(len(selected) == 1, "ambiguous selected-node DS Pod")
        p = selected[0]
        require(p["metadata"]["labels"].get(OWNER) == self.run_id, "foreign DS Pod")
        ds = self.get(cluster, "daemonset", DS, SYSTEM)
        require(any(o.get("kind") == "DaemonSet" and o.get("uid") == ds["metadata"]["uid"] for o in p["metadata"].get("ownerReferences", [])), "DS controller UID mismatch")
        return p

    def phase(self): return self.state()["phases"][0]


class Fanout:
    def __init__(self, args):
        self.args, self.run_id = args, uuid.uuid4().hex[:12]
        self.out = Path(args.out).resolve(); self.out.mkdir(parents=True, exist_ok=False)
        self.parents, self.routes, self.shared, self.followers = set(), {}, {}, {}
        self.report = {"run": self.run_id, "status": "running", "scope": "explicit-four-node-opt-in-distribution", "enforcementAvailable": False,
            "mtlsProven": False, "firstPacketAdmissionProven": False, "errors": [], "clusters": {}, "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        for cluster in args.clusters:
            for suffix in ("control-plane", "worker"):
                node = cluster + "-" + suffix
                self.routes[(cluster, node)] = NodeHarness(args, cluster, node, self.run_id, self.parents, self.out / node)
        self.flush()

    def flush(self): (self.out / "fanout-report.json").write_text(json.dumps(self.report, indent=2) + "\n")
    def members(self, cluster): return [h for (c, _), h in self.routes.items() if c == cluster]
    def owner(self, cluster): return self.members(cluster)[0]

    def backends(self):
        result = {}
        for cluster in lab.CLUSTERS:
            h = next(iter(self.routes.values()))
            pods = h.get(cluster, "pods", namespace="mesh-example")["items"]
            choices = [p for p in pods if p["metadata"]["name"].startswith("rebel-base-") and p["spec"].get("nodeName") == cluster + "-control-plane" and p["status"].get("phase") == "Running"]
            require(len(choices) == 1, "missing existing backend")
            p = choices[0]; result[cluster] = {"name": p["metadata"]["name"], "uid": p["metadata"]["uid"], "ip": p["status"]["podIP"]}
        return result

    def continuity(self, label):
        samples = []
        for cluster in self.args.clusters:
            h = self.owner(cluster)
            require(h.kubectl(cluster, "get", "--raw", "/readyz").stdout.strip() == "ok", "API readiness degraded")
            h.agent_exec(cluster, "cilium-dbg", "status", "--brief", label="platform-cilium-status")
            for destination, backend in self.backends().items():
                for port in (80, 8080, 31337):
                    out = h.kubectl(cluster, "-n", "mesh-example", "exec", "mesh-client", "--", "curl", "-fsS", "--max-time", "5", "-D", "-", f"http://{backend['ip']}:{port}/", label="unrelated-platform-client").stdout
                    require("x-cmtc-cluster: " + destination in out.lower(), "unrelated app continuity failed")
                    samples.append({"source": cluster, "destination": destination, "port": port})
        self.report.setdefault("continuity", []).append({"phase": label, "checks": samples}); self.flush()

    def create_config(self, cluster, swapped=False):
        owner, members = self.owner(cluster), self.members(cluster)
        name = DS + "-fanout-" + self.run_id + ("-swapped" if swapped else "")
        configs = [copy.deepcopy(h.phase()["config"]) for h in members]
        if swapped: configs.reverse()
        data = {h.physical_node + ".json": json.dumps(c) for h, c in zip(members, configs)}
        owner.create(cluster, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": SYSTEM}, "immutable": True, "data": data})
        return name

    def create_ds(self, cluster, cm):
        h = self.owner(cluster); body = copy.deepcopy(h.template)
        spec = body["spec"]["template"]["spec"]
        require("kubernetes.io/hostname" not in spec["nodeSelector"], "fanout DS must not pin one hostname")
        spec["nodeSelector"].update({RUN_SELECTOR: self.run_id})
        body["spec"]["template"]["metadata"]["labels"].update({OWNER: self.run_id, lab.LEGACY_OWNER: self.run_id})
        spec["containers"][0]["image"] = self.args.image
        for env in spec["containers"][0]["env"]:
            if env["name"] == "CLUSTER_NAME": env["value"] = cluster
        for volume in spec["volumes"]:
            if volume["name"] == "config": volume["configMap"]["name"] = cm
            elif volume["name"] in ("pins", "locks"): volume["hostPath"]["path"] = h.parents["pinRoot" if volume["name"] == "pins" else "lockRoot"]["path"]
        h.create(cluster, body)

    def delete_ds(self, cluster):
        h = self.owner(cluster)
        for item in list(h.owned.get(cluster, [])):
            if item[0] == "DaemonSet": h.delete_owned(cluster, *item)
        h.poll("all run DS Pods gone", lambda: not [p for p in h.get(cluster, "pods", namespace=SYSTEM)["items"] if p["metadata"].get("labels", {}).get(OWNER) == self.run_id and p["metadata"].get("labels", {}).get("app.kubernetes.io/name") == DS])

    def misroute(self, cluster):
        cm = self.create_config(cluster, swapped=True)
        self.create_ds(cluster, cm)
        for h in self.members(cluster):
            def failed():
                pod = h.fence_pod(cluster)
                if not pod: return False
                statuses = pod["status"].get("containerStatuses", [])
                if not statuses: return False
                s = statuses[0]
                return pod if not s.get("ready") and (s.get("state", {}).get("terminated") or s.get("lastState", {}).get("terminated")) else False
            p = h.poll("misrouted node config rejected", failed)
            h.verify_image(cluster, p)
            logs = h.kubectl(cluster, "-n", SYSTEM, "logs", p["metadata"]["name"], "-c", "fence", check=False).stdout
            require("explicit NODE_NAME/CLUSTER_NAME must match immutable configuration" in logs, "wrong negative failure cause")
            require(h.chain_for(h.tc(cluster), h.phase()["config"]["ifIndex"], "ingress") == h.phase()["baseline"], "misroute changed native chain")
            h.phase()["misroutedConfigRejected"] = {"podUID": p["metadata"]["uid"], "status": p["status"], "logs": logs}; h.flush()
        self.delete_ds(cluster)

    def install_cluster(self, cluster):
        owner = self.owner(cluster)
        require(owner.get(cluster, "daemonset", DS, SYSTEM, absent=True) is None, "existing DS")
        self.misroute(cluster)
        cm = self.create_config(cluster)
        for h in self.members(cluster): h.phase()["configMap"] = cm
        self.create_ds(cluster, cm)
        for h in self.members(cluster):
            pod = h.wait_fence(cluster); h.pin_chain(cluster, h.phase())
            self.followers[(cluster, h.physical_node)] = h.capture(cluster, pod, h.phase(), "install")
        # One Ready Pod on every requested node in the SAME live DaemonSet.
        def all_ready():
            ds = owner.get(cluster, "daemonset", DS, SYSTEM)
            status = ds.get("status", {})
            return ds if status.get("desiredNumberScheduled") == 2 and status.get("numberReady") == 2 and status.get("numberMisscheduled", 0) == 0 else False
        ds = owner.poll("two-node simultaneous fanout Ready", all_ready)
        self.report["clusters"][cluster] = {"daemonSetUID": ds["metadata"]["uid"], "configMap": cm, "simultaneousStatus": ds["status"]}; self.flush()
        for h in self.members(cluster): h.traffic(cluster, h.phase(), True)
        self.continuity(cluster + "-both-ready")

    def after_all_installed(self):
        """Optional telemetry/load hook; all selected clusters remain installed.

        Exceptions fail the run and still invoke exact-owned cleanup. Subclasses
        must keep the existing per-node ownership/image/pin checks in place.
        """
        pass

    def after_all_removed(self):
        """Optional absent-telemetry hook after every exercise removed its DS.

        Original workloads and pinned deny links still exist until cleanup.
        """
        pass

    def exercise_cluster(self, cluster):
        target, peer = self.members(cluster)
        peer_before = peer.wait_fence(cluster)["status"]["containerStatuses"][0]["containerID"]
        key = (cluster, target.physical_node)
        self.followers[key] = target.kill_restart(cluster, target.phase(), self.followers[key])
        require(peer.wait_fence(cluster)["status"]["containerStatuses"][0]["containerID"] == peer_before, "single-node death restarted peer")
        # Removing only selector label stops this node's DS process; its annotation
        # and run selector remain owned, so a new owner cannot be silently claimed.
        target.select(False)
        target.poll("deselected-node process gone", lambda: target.fence_pod(cluster) is None)
        self.followers[key].wait_event(lambda e: e.get("msg") == "process handles released; pins retained", "deselected node retains pins")
        self.followers[key].stop(wait_for_eof=True)
        target.pin_chain(cluster, target.phase()); target.traffic(cluster, target.phase(), True)
        require(peer.wait_fence(cluster)["status"]["containerStatuses"][0]["containerID"] == peer_before, "node label removal affected peer")
        self.continuity(cluster + "-one-node-deselected-still-denied")
        target.select(True)
        pod = target.wait_fence(cluster); target.pin_chain(cluster, target.phase())
        self.followers[key] = target.capture(cluster, pod, target.phase(), "adopt")
        for h in self.members(cluster): h.traffic(cluster, h.phase(), True)
        self.delete_ds(cluster)
        for h in self.members(cluster):
            f = self.followers[(cluster, h.physical_node)]
            f.wait_event(lambda e: e.get("msg") == "process handles released; pins retained", "DS removal retains pins")
            f.stop(wait_for_eof=True)
            h.pin_chain(cluster, h.phase()); h.traffic(cluster, h.phase(), True)
        self.continuity(cluster + "-no-daemon-pins-deny")

    def cleanup(self):
        # First remove ONLY exact run-owned workload Pods so any partial unpinned
        # holder becomes defunct. Then all DS instances, then all retirements while
        # the shared immutable ConfigMap still exists; only then delete that CM.
        for h in self.routes.values():
            if h.cluster not in h.report["clusters"] or "nodeUID" not in h.state(): continue
            try:
                for item in list(h.owned.get(h.cluster, [])):
                    if item[0] == "Pod" and item[1] == h.ns: h.delete_owned(h.cluster, *item)
            except Exception as e: self.report["errors"].append(str(e))
        for cluster in self.args.clusters:
            try: self.delete_ds(cluster)
            except Exception as e: self.report["errors"].append(str(e))
        for h in self.routes.values():
            if h.cluster not in h.report["clusters"] or "nodeUID" not in h.state(): continue
            try:
                for phase in h.state()["phases"]:
                    if "installed" in phase and not phase.get("retired"): h.retire_phase(h.cluster, phase)
            except Exception as e: self.report["errors"].append(str(e))
        # Base cleanup now sees all nodes retired and the DS already absent.
        for h in self.routes.values():
            if h.cluster not in h.report["clusters"] or "nodeUID" not in h.state(): continue
            try: h.cleanup()
            except Exception as e: self.report["errors"].append(str(e))
            self.report["errors"] += [h.physical_node + ": " + e for e in h.report["cleanupErrors"]]
        self.remove_parents()
        self.flush()

    def remove_parents(self):
        removed = set()
        for h in self.routes.values():
            for key, parent in h.parents.items():
                token = (key, parent["path"], parent["stat"])
                try:
                    # Always inspect the actual node namespace, even if another
                    # node reported identical device/inode/path identifiers.
                    result = h.node(h.cluster, "stat", "-c", "%F|%u|%a|%d|%i", parent["path"], check=False)
                    if result.returncode:
                        absent = h.node(h.cluster, "sh", "-c", "test ! -e " + shlex.quote(parent["path"]) + " && test ! -L " + shlex.quote(parent["path"]), check=False)
                        require(absent.returncode == 0 and token in removed, "parent absent without prior confirmed own removal")
                        continue
                    require(result.stdout.strip() == parent["stat"], "parent root incarnation changed")
                    h.node(h.cluster, "rmdir", "--", parent["path"])
                    absent = h.node(h.cluster, "sh", "-c", "test ! -e " + shlex.quote(parent["path"]) + " && test ! -L " + shlex.quote(parent["path"]), check=False)
                    require(absent.returncode == 0, "parent still present after rmdir")
                    removed.add(token)
                except Exception as e: self.report["errors"].append(str(e))

    def execute(self):
        try:
            backends = self.backends()
            for h in self.routes.values(): h.prepare(backends)
            # Activate only exact audited nodes AFTER per-node configs are frozen.
            for h in self.routes.values(): h.select(True)
            self.continuity("before-fanout")
            for cluster in self.args.clusters: self.install_cluster(cluster)
            self.after_all_installed()
            for cluster in self.args.clusters: self.exercise_cluster(cluster)
            self.after_all_removed()
            self.report["status"] = "passed-pending-cleanup"
        except Exception as e:
            self.report.update(status="failed", error=str(e), traceback=traceback.format_exc())
        finally:
            self.cleanup()
            self.report["nodeReports"] = {h.physical_node: str(h.out / "report.json") for h in self.routes.values()}
            self.report["status"] = "passed" if self.report["status"] == "passed-pending-cleanup" and not self.report["errors"] else "failed"
            self.flush()
        print(json.dumps(self.report)); return 0 if self.report["status"] == "passed" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "image-id", "expected-revision", "out"): p.add_argument("--" + name, required=True)
    p.add_argument("--clusters", nargs="+", choices=lab.CLUSTERS, default=list(lab.CLUSTERS))
    p.add_argument("--kubeconfig", default="/private/tmp/cmtc-a-b-20261024.kubeconfig")
    p.add_argument("--template", default="config/experimental/datapath-fence-fanout.yaml")
    p.add_argument("--client-image", default=lab.observer.CURL)
    a = p.parse_args()
    require(len(set(a.clusters)) == len(a.clusters), "duplicate cluster")
    require(a.image.startswith("localhost/") and "@" not in a.image, "already-loaded explicit local image tag required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", a.image_id), "exact image ID required")
    require(re.fullmatch(r"[0-9a-f]{40}", a.expected_revision), "exact committed source revision required")
    require(Path(a.kubeconfig).is_file(), "owned kubeconfig missing")
    return Fanout(a).execute()

if __name__ == "__main__": sys.exit(main())
