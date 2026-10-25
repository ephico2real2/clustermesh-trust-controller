#!/usr/bin/env python3
"""Owned deny-only fence lab. No admission, identity, mTLS or Protected claim.
Copy beside test-observer.py; requires the repository PyYAML venv. Proposal only.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback
import uuid

import yaml

LIB = Path(__file__).resolve().parent
sys.path.insert(0, str(LIB))
spec = importlib.util.spec_from_file_location("owned_observer_harness", LIB / "test-observer.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
from observer_log_capture import ObserverLogFollower
from fence_manifest_contract import validate_fence_template

require, digest = observer.require, observer.digest
SYSTEM, DS, CLIENT = "cmtc-system", "cmtc-bpf-fence", "fence-client"
OWNER, LEGACY_OWNER = "security.cmtc.io/fence-run", observer.OWNER
OPTIN = "security.cmtc.io/bpf-fence-lab"
CLUSTERS = ("cmtc-a", "cmtc-b")


class FenceHarness(observer.Harness):
    # Reuse audited command recording, kubectl/get/create, node/agent_exec,
    # polling, TC inventory, atomic UID+resourceVersion DELETE and foreign audit.
    # Never mutate observer module constants or invoke its observer-specific phases.
    def __init__(self, args):
        self.args, self.run_id, self.counter = args, uuid.uuid4().hex[:12], 0
        self.out = Path(args.out).resolve(); self.out.mkdir(parents=True, exist_ok=False)
        self.env = {**os.environ, "KUBECONFIG": args.kubeconfig}
        self.ns = "cmtc-fence-lab-" + self.run_id
        self.owned, self.monitors, self.followers = {}, {}, {}
        self.template = validate_fence_template(yaml.safe_load(Path(args.template).read_text()), fanout=getattr(args, "fanout", False))
        self.report = {"run": self.run_id, "status": "running", "scope": "deny-only-persistent-quarantine",
            "enforcementAvailable": False, "mtlsProven": False, "firstPacketAdmissionProven": False, "destinationIngressProven": False,
            "nativeTailCallCoverageProven": False, "requestedTCXDirections": args.directions,
            "image": args.image, "expectedImageID": args.image_id, "expectedRevision": args.expected_revision,
            "started": datetime.datetime.now(datetime.timezone.utc).isoformat(), "clusters": {}, "commands": [], "cleanupErrors": []}
        self.flush()

    def node_name(self, cluster):
        """Physical node route; subclasses must retain the actual cluster ID."""
        return cluster + "-worker"

    def backend(self, cluster):
        return self.report["clusters"][cluster]["backend"]

    def node(self, cluster, *arguments, **kwargs):
        return self.command(["colima", "ssh", "--profile", "cmtc-cilium", "--", "docker", "exec",
            self.node_name(cluster), *arguments], **kwargs)

    def create(self, cluster, body):
        body.setdefault("metadata", {}).setdefault("labels", {})[OWNER] = self.run_id
        return super().create(cluster, body)  # Adds legacy shared ownership key too.

    def delete_owned(self, cluster, kind, namespace, name, uid):
        obj = self.get(cluster, kind, name, namespace, absent=True)
        if obj:
            require(obj["metadata"].get("labels", {}).get(OWNER) == self.run_id, "fence cleanup owner changed")
        super().delete_owned(cluster, kind, namespace, name, uid)
        self.owned[cluster] = [x for x in self.owned.get(cluster, []) if x != (kind, namespace, name, uid)]

    def own_pod(self, cluster):
        pod = self.get(cluster, "pod", CLIENT, self.ns)
        require(pod["metadata"]["labels"].get(OWNER) == self.run_id, "foreign client Pod")
        return pod

    def ready_client(self, cluster):
        return self.poll("owned client Ready", lambda: self._ready_client(cluster))

    def _ready_client(self, cluster):
        pod = self.own_pod(cluster)
        statuses = pod["status"].get("containerStatuses", [])
        for status in statuses:
            waiting = status.get("state", {}).get("waiting", {})
            require(waiting.get("reason") not in ("ErrImageNeverPull", "CreateContainerConfigError"),
                "client prerequisite rejected: " + repr(waiting))
        return pod if statuses and all(s.get("ready") for s in statuses) else False

    def new_client(self, cluster):
        self.create(cluster, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": CLIENT, "namespace": self.ns,
            "labels": {"app": "cmtc-fence-client"}}, "spec": {"nodeName": self.node_name(cluster), "restartPolicy": "Never", "terminationGracePeriodSeconds": 5,
            "automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 100, "runAsGroup": 100},
            "containers": [{"name": "curl", "image": self.args.client_image, "imagePullPolicy": "Never",
                "command": ["sh", "-c", "sleep 86400"], "securityContext": {"allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]}})
        return self.ready_client(cluster)

    def preflight(self):
        for cluster in CLUSTERS:
            require(self.get(cluster, "namespace", self.ns, absent=True) is None, "run namespace already exists")
            require(self.get(cluster, "daemonset", DS, SYSTEM, absent=True) is None, "existing fence DS")
            node = self.get(cluster, "node", self.node_name(cluster))
            require(OPTIN not in node["metadata"].get("labels", {}) and OWNER not in node["metadata"].get("annotations", {}), "foreign fence opt-in")
            agents = json.loads(self.kubectl(cluster, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium",
                "--field-selector", "spec.nodeName=" + self.node_name(cluster), "-o", "json").stdout)["items"]
            require(len(agents) == 1 and all(s.get("ready") for s in agents[0]["status"]["containerStatuses"]), "worker agent not uniquely Ready")
            self.report["clusters"][cluster] = {"nodeUID": node["metadata"]["uid"], "agent": {"name": agents[0]["metadata"]["name"],
                "uid": agents[0]["metadata"]["uid"]}, "phases": [], "roots": {}, "cases": []}
            state = self.report["clusters"][cluster]
            state["foreignBaseline"] = self.tc(cluster)
            require(not any(r.get("name") in ("cmtc_fence", "cmtc_observe") for r in state["foreignBaseline"]), "preexisting custom hook")
            self.node(cluster, "sh", "-c", "command -v nsenter && command -v crictl && command -v ip && command -v flock", label="node-tools")
            require(self.node(cluster, "stat", "-f", "-c", "%t", "/sys/fs/bpf").stdout.strip() == "cafe4a11", "existing node bpffs required")
            backend = self.get(cluster, "pods", namespace="mesh-example")
            choices = [p for p in backend["items"] if p["metadata"]["name"].startswith("rebel-base-") and p["spec"].get("nodeName") == cluster + "-control-plane" and p["status"].get("phase") == "Running"]
            require(len(choices) == 1, "one existing local control-plane backend required")
            p = choices[0]
            state["backend"] = {"name": p["metadata"]["name"], "uid": p["metadata"]["uid"], "ip": p["status"]["podIP"]}
            self.create(cluster, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.ns}})
            state["namespaceUID"] = self.get(cluster, "namespace", self.ns)["metadata"]["uid"]
            self.prepare_roots(cluster)
            self.node_optin(cluster, True)
        self.flush()

    def node_optin(self, cluster, acquire):
        state = self.report["clusters"][cluster]
        node = self.get(cluster, "node", self.node_name(cluster))
        require(node["metadata"]["uid"] == state["nodeUID"], "node incarnation changed")
        meta = node["metadata"]; labels, annotations = meta.get("labels", {}), meta.get("annotations", {})
        pointer = lambda v: v.replace("~", "~0").replace("/", "~1")
        patch = [{"op": "test", "path": "/metadata/uid", "value": state["nodeUID"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": meta["resourceVersion"]}]
        if acquire:
            require(OPTIN not in labels and OWNER not in annotations, "node opt-in already owned")
            if "annotations" not in meta: patch.append({"op": "add", "path": "/metadata/annotations", "value": {}})
            patch += [{"op": "add", "path": "/metadata/annotations/" + pointer(OWNER), "value": self.run_id},
                {"op": "add", "path": "/metadata/labels/" + pointer(OPTIN), "value": "true"}]
            state["nodeOptinAttempted"] = True
        else:
            if OWNER not in annotations and OPTIN not in labels: return
            require(annotations.get(OWNER) == self.run_id and labels.get(OPTIN) == "true", "node opt-in ownership changed")
            patch += [{"op": "test", "path": "/metadata/annotations/" + pointer(OWNER), "value": self.run_id},
                {"op": "test", "path": "/metadata/labels/" + pointer(OPTIN), "value": "true"},
                {"op": "remove", "path": "/metadata/labels/" + pointer(OPTIN)},
                {"op": "remove", "path": "/metadata/annotations/" + pointer(OWNER)}]
        self.kubectl(cluster, "patch", "node", self.node_name(cluster), "--type=json", "-p", json.dumps(patch), label="atomic-fence-node-optin")
        state["nodeOwned"] = acquire

    def root_stat(self, cluster, path):
        result = self.node(cluster, "stat", "-c", "%F|%u|%a|%d|%i", path, check=False, label="owned-host-root-stat")
        require(result.returncode == 0 and result.stdout.startswith("directory|0|700|"), "unsafe/changed host root: " + path)
        return result.stdout.strip()

    def prepare_roots(self, cluster):
        state = self.report["clusters"][cluster]
        for key, path in (("pinRoot", "/sys/fs/bpf/cmtc-fence-" + self.run_id), ("lockRoot", "/run/cmtc-fence-" + self.run_id)):
            self.node(cluster, "mkdir", "-m", "700", "--", path, label="create-private-fence-root")
            state["roots"][key] = {"path": path, "stat": self.root_stat(cluster, path)}
            self.flush()
        require(self.node(cluster, "stat", "-f", "-c", "%t", state["roots"]["pinRoot"]["path"]).stdout.strip() == "cafe4a11", "private child not on existing bpffs")
        require(self.node(cluster, "stat", "-f", "-c", "%t", state["roots"]["lockRoot"]["path"]).stdout.strip() != "cafe4a11", "lock root must be ordinary filesystem")

    @staticmethod
    def chain_for(records, ifindex, direction):
        return [{"program": int(r["prog_id"]), "link": int(r["link_id"]), "name": r.get("name", "")}
            for r in records if int(r.get("ifindex", -1)) == ifindex and r.get("kind") == "tcx/" + direction]

    def audit(self, cluster, pod, direction):
        state = self.report["clusters"][cluster]
        require(self.get(cluster, "namespace", self.ns)["metadata"]["uid"] == state["namespaceUID"], "namespace incarnation changed")
        require(self.own_pod(cluster)["metadata"]["uid"] == pod["metadata"]["uid"], "Pod changed before audit")
        cep = self.poll("CiliumEndpoint Pod owner", lambda: self.get(cluster, "ciliumendpoint", CLIENT, self.ns, absent=True))
        require(any(o.get("kind") == "Pod" and o.get("uid") == pod["metadata"]["uid"] for o in cep["metadata"].get("ownerReferences", [])), "CiliumEndpoint lacks exact PodUID owner")
        def endpoint():
            endpoints = json.loads(self.agent_exec(cluster, "cilium-dbg", "endpoint", "list", "-o", "json").stdout)
            matches = [e for e in endpoints if any(a.get("ipv4") == pod["status"]["podIP"] for a in e.get("status", {}).get("networking", {}).get("addressing", []))]
            return matches[0] if len(matches) == 1 and matches[0]["status"].get("state") == "ready" else False
        ep = self.poll("audited Cilium endpoint Ready", endpoint)
        dev = ep["status"]["networking"].get("interface-name")
        require(dev and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", dev), "unsafe/missing host veth")
        host = json.loads(self.node(cluster, "ip", "-d", "-j", "link", "show", "dev", dev).stdout)[0]
        require(host.get("linkinfo", {}).get("info_kind") == "veth", "only host veth supported")
        sandboxes = json.loads(self.node(cluster, "crictl", "pods", "-o", "json").stdout)["items"]
        sandboxes = [p for p in sandboxes if p.get("metadata", {}).get("uid") == pod["metadata"]["uid"] and p["metadata"].get("namespace") == self.ns and p["metadata"].get("name") == CLIENT]
        require(len(sandboxes) == 1, "need exact CRI sandbox incarnation")
        sid = sandboxes[0]["id"]; require(re.fullmatch(r"[0-9a-f]{64}", sid), "invalid sandbox ID")
        inspection = json.loads(self.node(cluster, "crictl", "inspectp", sid).stdout)
        require(inspection["status"]["metadata"]["uid"] == pod["metadata"]["uid"], "CRI sandbox UID mismatch")
        pid = int(inspection["info"]["pid"]); require(pid > 1, "invalid sandbox PID")
        pid_stat = self.node(cluster, "cat", f"/proc/{pid}/stat").stdout
        sandbox_start = pid_stat[pid_stat.rfind(")") + 2:].split()[19]
        require(sandbox_start.isdecimal(), "invalid sandbox process starttime")
        inner = json.loads(self.node(cluster, "nsenter", "--net=/proc/" + str(pid) + "/ns/net", "ip", "-j", "link", "show", "dev", "eth0").stdout)[0]
        addresses = json.loads(self.node(cluster, "nsenter", "--net=/proc/" + str(pid) + "/ns/net", "ip", "-j", "addr", "show", "dev", "eth0").stdout)[0]
        require(host["ifindex"] == inner["link_index"] and host["link_index"] == inner["ifindex"], "sandbox peer/host veth mismatch")
        require(any(a.get("local") == pod["status"]["podIP"] for a in addresses["addr_info"]), "sandbox PodIP mismatch")
        baseline = self.chain_for(self.tc(cluster), host["ifindex"], direction)
        expected = ("cil_from_container" if direction == "ingress" else "cil_to_container")[:15]
        require(baseline and baseline[0]["name"] in (expected, "cil_from_container" if direction == "ingress" else "cil_to_container"), "wrong native workload anchor")
        for hook in ("ingress", "egress"):
            filters = json.loads(self.node(cluster, "tc", "-j", "filter", "show", "dev", dev, hook).stdout or "[]")
            require(not filters, "legacy TC filter present")
        inode = int(self.node(cluster, "stat", "-Lc", "%i", "/proc/self/ns/net").stdout)
        cfg = {"cluster": cluster, "node": self.node_name(cluster), "namespaceUID": state["namespaceUID"], "podUID": pod["metadata"]["uid"],
            "netNSInode": inode, "ifIndex": host["ifindex"], "ifName": dev, "mac": host["address"], "peerIfIndex": inner["ifindex"],
            "direction": direction, "ciliumLinkID": baseline[0]["link"], "ciliumProgramID": baseline[0]["program"],
            "pinRoot": "/cmtc-pins", "lockRoot": "/cmtc-locks"}
        phase = {"direction": direction, "config": cfg, "hostPinRoot": state["roots"]["pinRoot"]["path"], "hostLockRoot": state["roots"]["lockRoot"]["path"], "baseline": baseline, "podUID": pod["metadata"]["uid"], "sandboxID": sid,
            "sandboxPID": pid, "sandboxNetNS": self.node(cluster, "stat", "-Lc", "%i", f"/proc/{pid}/ns/net").stdout.strip()}
        phase["key"] = hashlib.sha256(json.dumps([cluster, cfg["node"], cfg["namespaceUID"], cfg["podUID"], direction], separators=(",", ":")).encode()).hexdigest()
        again = json.loads(self.node(cluster, "crictl", "inspectp", sid).stdout)
        final_stat = self.node(cluster, "cat", f"/proc/{pid}/stat").stdout
        require(int(again["info"]["pid"]) == pid and again["status"]["metadata"]["uid"] == pod["metadata"]["uid"] and
            final_stat[final_stat.rfind(")") + 2:].split()[19] == sandbox_start, "sandbox incarnation changed during audit")
        require(self.own_pod(cluster)["metadata"]["uid"] == pod["metadata"]["uid"], "Pod changed after audit")
        phase["sandboxPIDStarttime"] = sandbox_start
        state["phases"].append(phase); self.flush()
        return phase

    def traffic(self, cluster, phase, deny):
        before = self.counter_map(cluster, phase) if deny else None
        for destination in CLUSTERS:
            backend = self.backend(destination)
            current = self.get(destination, "pod", backend["name"], "mesh-example")
            require(current["metadata"]["uid"] == backend["uid"] and current["status"]["podIP"] == backend["ip"], "backend incarnation changed")
            for port in (80, 8080, 31337):
                result = self.kubectl(cluster, "-n", self.ns, "exec", CLIENT, "--", "curl", "-fsS", "--connect-timeout", "2", "--max-time", "3", "-D", "-",
                    f"http://{backend['ip']}:{port}/", check=False, timeout=10, label=("deny" if deny else "baseline") + f"-{destination}-{port}")
                if deny: require(result.returncode in (7, 28), "unexpected denial/exec failure: " + str(result.returncode))
                else:
                    require(result.returncode == 0 and "x-cmtc-cluster: " + destination in result.stdout.lower() and "x-cmtc-pod: " + backend["name"] in result.stdout.lower(), "baseline HTTP/serving identity failed")
                self.report["clusters"][cluster]["cases"].append({"direction": phase["direction"], "deny": deny, "destination": destination, "port": port, "exit": result.returncode})
        if deny:
            after = self.counter_map(cluster, phase)
            require(after["packets"] > before["packets"] and after["bytes"] > before["bytes"], "HTTP failures lack positive own-fence kernel counter evidence")
            phase.setdefault("counterSamples", []).append({"before": before, "after": after})
        self.flush()

    def pin_chain(self, cluster, phase):
        chain = self.chain_for(self.tc(cluster), phase["config"]["ifIndex"], phase["direction"])
        require(len(chain) == len(phase["baseline"]) + 1 and chain[1:] == phase["baseline"] and chain[0]["name"] == "cmtc_fence", "fence changed native chain/order")
        if "installed" in phase: require(chain == phase["installed"], "persistent TCX incarnation changed")
        else: phase["installed"] = chain
        return chain

    def counter_map(self, cluster, phase):
        pin = phase["hostPinRoot"] + "/" + phase["key"] + "/accounted"
        show = json.loads(self.agent_exec(cluster, "/usr/local/bin/bpftool", "-j", "map", "show", "pinned", pin).stdout)
        if isinstance(show, list): require(len(show) == 1, "ambiguous counter pin"); show = show[0]
        require(show["type"] == "percpu_array" and show.get("name") == "accounted", "wrong fence counter map")
        program = json.loads(self.agent_exec(cluster, "/usr/local/bin/bpftool", "-j", "prog", "show", "id", str(phase["installed"][0]["program"])).stdout)
        if isinstance(program, list): program = program[0]
        require(program.get("map_ids") == [show["id"]], "counter pin is not attached fence's actual map")
        entries = json.loads(self.agent_exec(cluster, "/usr/local/bin/bpftool", "-j", "map", "dump", "pinned", pin).stdout)
        def decode(v):
            if isinstance(v, dict) and "packets" in v and "bytes" in v: return {"packets": int(v["packets"]), "bytes": int(v["bytes"])}
            require(isinstance(v, list) and len(v) == 16, "unknown counter encoding")
            raw = bytes(int(x, 16) if isinstance(x, str) else x for x in v)
            return {"packets": int.from_bytes(raw[:8], "little"), "bytes": int.from_bytes(raw[8:], "little")}
        require(len(entries) == 1, "counter map key cardinality changed")
        values = [decode(v["value"]) for v in entries[0]["values"]]
        return {k: sum(v[k] for v in values) for k in ("packets", "bytes")}

    def fence_pod(self, cluster):
        pods = self.get(cluster, "pods", namespace=SYSTEM)["items"]
        selected = [p for p in pods if p["metadata"].get("labels", {}).get("app.kubernetes.io/name") == DS]
        if not selected: return None
        require(len(selected) == 1, "ambiguous fence Pods")
        p = selected[0]
        require(p["metadata"]["labels"].get(OWNER) == self.run_id, "foreign fence Pod")
        ds = self.get(cluster, "daemonset", DS, SYSTEM)
        require(any(o.get("kind") == "DaemonSet" and o.get("uid") == ds["metadata"]["uid"] for o in p["metadata"].get("ownerReferences", [])), "fence Pod controller UID mismatch")
        return p

    def verify_image(self, cluster, pod):
        statuses = pod["status"].get("containerStatuses", [])
        require(len(statuses) == 1 and statuses[0].get("imageID"), "missing runtime image identity")
        actual = json.loads(self.node(cluster, "crictl", "inspecti", self.args.image).stdout)
        require(actual["status"]["id"] == self.args.image_id and actual["info"]["imageSpec"]["architecture"] == "arm64", "image configuration/architecture mismatch")
        require(digest(statuses[0]["imageID"]) in {digest(x) for x in actual["status"]["repoDigests"]}, "runtime manifest mismatch")
        return statuses[0]

    def wait_fence(self, cluster, restart=None):
        def ready():
            pod = self.fence_pod(cluster)
            if not pod: return False
            statuses = pod["status"].get("containerStatuses", [])
            if not statuses or not statuses[0].get("ready") or (restart is not None and statuses[0]["restartCount"] <= restart): return False
            self.verify_image(cluster, pod)
            version = self.kubectl(cluster, "-n", SYSTEM, "exec", pod["metadata"]["name"], "--", "/cmtc-bpf-fence", "--version").stdout
            require("revision=" + self.args.expected_revision + " " in version and "mode=deny-only" in version and "enforcementAvailable=false" in version, "source/mode pin mismatch")
            return pod
        return self.poll("fence Ready exact image/source", ready)

    def capture(self, cluster, pod, phase, expected_stage):
        status = self.verify_image(cluster, pod)
        stem = f"{cluster}-{phase['direction']}-{status['restartCount']}-{uuid.uuid4().hex[:6]}"
        follower = ObserverLogFollower(["kubectl", "--context", "kind-" + cluster, "-n", SYSTEM, "logs", "-f", pod["metadata"]["name"], "-c", "fence", "--tail=-1"],
            self.env, self.out / (stem + ".jsonl"), self.out / (stem + ".stderr"))
        self.followers.setdefault(cluster, []).append(follower)
        current = self.get(cluster, "pod", pod["metadata"]["name"], SYSTEM)
        require(current["metadata"]["uid"] == pod["metadata"]["uid"] and current["status"]["containerStatuses"][0]["containerID"] == status["containerID"], "container changed during log capture")
        event = follower.wait_event(lambda e: e.get("msg") == "committed deny attachment verified" and e.get("stage") == expected_stage, "real committed fence lifecycle")
        cfg = phase["config"]
        require(all(event.get(k) == cfg[k] for k in ("cluster", "node", "namespaceUID", "podUID")) and event.get("enforcementAvailable") is False, "fence log ownership/scope mismatch")
        phase.setdefault("logs", []).append({"file": stem + ".jsonl", "podUID": pod["metadata"]["uid"], "containerID": status["containerID"], "stage": event})
        return follower

    def install(self, cluster, phase):
        cm = DS + "-" + self.run_id + "-" + phase["direction"]
        phase["configMap"] = cm
        bad = copy.deepcopy(phase["config"]); bad["ciliumProgramID"] += 1  # Same key, wrong immutable ownership; never a new install key.
        self.create(cluster, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cm, "namespace": SYSTEM}, "immutable": True,
            "data": {self.node_name(cluster) + ".json": json.dumps(phase["config"]), "bad.json": json.dumps(bad)}})
        body = copy.deepcopy(self.template)
        spec = body["spec"]["template"]["spec"]
        body["spec"]["template"]["metadata"]["labels"].update({OWNER: self.run_id, LEGACY_OWNER: self.run_id})
        spec["nodeSelector"]["kubernetes.io/hostname"] = self.node_name(cluster)
        spec["containers"][0]["image"] = self.args.image
        for env in spec["containers"][0]["env"]:
            if env["name"] == "CLUSTER_NAME": env["value"] = cluster
        for volume in spec["volumes"]:
            if volume["name"] == "config": volume["configMap"]["name"] = cm
            elif volume["name"] in ("pins", "locks"): volume["hostPath"]["path"] = phase["hostPinRoot" if volume["name"] == "pins" else "hostLockRoot"]
        for mount in spec["containers"][0]["volumeMounts"]:
            if mount["name"] in ("pins", "locks"): mount["mountPath"] = phase["config"]["pinRoot" if mount["name"] == "pins" else "lockRoot"]
        self.create(cluster, body)
        pod = self.wait_fence(cluster); self.pin_chain(cluster, phase)
        return self.capture(cluster, pod, phase, "install")

    def kill_restart(self, cluster, phase, follower):
        pod = self.wait_fence(cluster); status = self.verify_image(cluster, pod)
        cid = status["containerID"].split("://", 1)[-1]; require(re.fullmatch(r"[0-9a-f]{64}", cid), "unsafe container ID")
        info = json.loads(self.node(cluster, "crictl", "inspect", cid).stdout)
        require(info["status"]["id"] == cid and info["status"]["labels"].get("io.kubernetes.pod.uid") == pod["metadata"]["uid"] and info["status"]["metadata"]["name"] == "fence", "SIGKILL CRI ownership mismatch")
        pid = int(info["info"]["pid"]); require(pid > 1, "unsafe PID")
        require(self.node(cluster, "readlink", f"/proc/{pid}/exe").stdout.strip() == "/cmtc-bpf-fence", "wrong PID executable")
        stat = self.node(cluster, "cat", f"/proc/{pid}/stat").stdout
        start = stat[stat.rfind(")") + 2:].split()[19]; require(start.isdecimal(), "unsafe PID starttime")
        script = f'test "$(readlink /proc/{pid}/exe)" = /cmtc-bpf-fence && test "$(awk \'{{print $22}}\' /proc/{pid}/stat)" = {start} && kill -9 {pid}'
        self.node(cluster, "sh", "-c", script, label="SIGKILL-validated-fence")
        restarted = self.wait_fence(cluster, status["restartCount"])
        follower.stop(wait_for_eof=True)
        require(not any(e.get("msg") == "process handles released; pins retained" for e in follower.records()), "SIGKILL falsely reported graceful release")
        terminated = restarted["status"]["containerStatuses"][0].get("lastState", {}).get("terminated", {})
        require(terminated.get("exitCode") == 137 or terminated.get("signal") == 9, "missing real SIGKILL evidence")
        self.pin_chain(cluster, phase); self.traffic(cluster, phase, True)
        phase["sigkill"] = {"pid": pid, "starttime": start, "termination": terminated,
            "scope": "Kubernetes restart/adopt; before-adopt crash denial is separately proven by private kernel tests"}
        return self.capture(cluster, restarted, phase, "adopt")

    def uninstall(self, cluster, phase=None, follower=None):
        resources = list(self.owned.get(cluster, []))
        for item in resources:
            if item[0] == "DaemonSet": self.delete_owned(cluster, *item)
        self.poll("owned fence DS Pods gone", lambda: not [p for p in self.get(cluster, "pods", namespace=SYSTEM)["items"] if p["metadata"].get("labels", {}).get(OWNER) == self.run_id and p["metadata"].get("labels", {}).get("app.kubernetes.io/name") == DS])
        if follower:
            follower.wait_event(lambda e: e.get("msg") == "process handles released; pins retained" and e.get("stage") == "release", "graceful release preserves pins")
            follower.stop(wait_for_eof=True)
        if phase and "installed" in phase: self.pin_chain(cluster, phase)

    def maintenance(self, cluster, phase, mode, expected_exit):
        name = "fence-" + mode + "-" + self.run_id + "-" + phase["direction"]
        cfg = phase["config"]
        mounts = [{"name": "config", "mountPath": "/config", "readOnly": True},
            {"name": "pins", "mountPath": cfg["pinRoot"]}, {"name": "locks", "mountPath": cfg["lockRoot"]}]
        args = ["--config=/config/" + ("bad.json" if mode == "bad-adopt" else cfg["node"] + ".json")]
        if mode == "retire": args += ["--retire-defunct"]
        body = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": SYSTEM}, "spec": {
            "nodeName": cfg["node"], "hostNetwork": True, "automountServiceAccountToken": False, "restartPolicy": "Never",
            "containers": [{"name": "fence", "image": self.args.image, "imagePullPolicy": "Never", "command": ["/cmtc-bpf-fence"], "args": args,
                "env": [{"name": "NODE_NAME", "value": cfg["node"]}, {"name": "CLUSTER_NAME", "value": cluster},
                    {"name": "CMTC_FENCE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}],
                "securityContext": {"privileged": True, "runAsUser": 0, "readOnlyRootFilesystem": True}, "volumeMounts": mounts}],
            "volumes": [{"name": "config", "configMap": {"name": phase["configMap"]}},
                {"name": "pins", "hostPath": {"path": phase["hostPinRoot"], "type": "Directory"}},
                {"name": "locks", "hostPath": {"path": phase["hostLockRoot"], "type": "Directory"}}]}}
        obj = self.create(cluster, body)
        def done():
            pod = self.get(cluster, "pod", name, SYSTEM)
            require(pod["metadata"]["uid"] == obj["metadata"]["uid"], "maintenance Pod replaced")
            statuses = pod["status"].get("containerStatuses", [])
            return pod if statuses and statuses[0].get("state", {}).get("terminated") else False
        pod = self.poll("exact-image maintenance termination", done, timeout=90)
        self.verify_image(cluster, pod)
        terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
        require(terminated["exitCode"] == expected_exit, "unexpected maintenance exit: " + repr(terminated))
        logs = self.kubectl(cluster, "-n", SYSTEM, "logs", name, "-c", "fence", label=mode + "-logs").stdout
        events = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
        if mode in ("bad-adopt", "stale-adopt"): require(any(e.get("stage") == "adopt" and e.get("msg") == "quarantine transaction not qualified" for e in events), "bad config did not fail adoption")
        if mode == "retire": require(any(e.get("msg") == "defunct pins retired" for e in events), "no exact defunct retirement acknowledgment")
        self.delete_owned(cluster, "Pod", SYSTEM, name, obj["metadata"]["uid"])
        return events

    def retire_phase(self, cluster, phase, recreate=False):
        cfg = phase["config"]
        current = self.get(cluster, "pod", CLIENT, self.ns, absent=True)
        if current:
            require(current["metadata"]["uid"] == phase["podUID"], "refuse deletion of replacement client")
            self.delete_owned(cluster, "Pod", self.ns, CLIENT, phase["podUID"])
        def defunct():
            result = self.agent_exec(cluster, "/usr/local/bin/bpftool", "-j", "link", "show", "pinned", phase["hostPinRoot"] + "/" + phase["key"] + "/link", check=False)
            # bpftool can emit a valid detached-link record then exit255 when
            # resolving its absent device name. Never infer defunct from exit.
            # The maintenance CLI subsequently checks the exact kernel link too.
            if not result.stdout.strip(): return False
            info = json.loads(result.stdout)
            if isinstance(info, list):
                require(len(info) == 1, "ambiguous old pinned link")
                info = info[0]
            require(isinstance(info, dict) and info.get("type") == "tcx", "not a TCX link record")
            require(int(info["id"]) == phase["installed"][0]["link"] and
                int(info["prog_id"]) == phase["installed"][0]["program"] and
                info.get("attach_type") == "tcx_" + phase["direction"], "pinned link incarnation changed")
            if result.returncode:
                require(result.returncode == 255 and info.get("ifindex") == 0 and
                    info.get("devname") == "(detached)", "unknown link inspection failure")
            return info if info.get("ifindex") == 0 else False
        phase["defunct"] = self.poll("exact old kernel link defunct", defunct)
        replacement = None
        if recreate:
            replacement = self.new_client(cluster)
            require(replacement["metadata"]["uid"] != phase["podUID"], "Pod UID did not change")
            phase["replacementPodUID"] = replacement["metadata"]["uid"]
            self.traffic(cluster, phase, False)
            phase["staleConfigAdopt"] = self.maintenance(cluster, phase, "stale-adopt", 1)
            require(defunct(), "stale adoption changed old pinned link")
        phase["retirement"] = self.maintenance(cluster, phase, "retire", 0)
        phase["retired"] = True
        if replacement:
            self.traffic(cluster, phase, False)
            self.delete_owned(cluster, "Pod", self.ns, CLIENT, replacement["metadata"]["uid"])
        self.flush()

    def run_phase(self, cluster, direction):
        pod = self.new_client(cluster)
        phase = self.audit(cluster, pod, direction)
        self.traffic(cluster, phase, False)
        follower = self.install(cluster, phase)
        self.traffic(cluster, phase, True)
        follower = self.kill_restart(cluster, phase, follower)
        self.uninstall(cluster, phase, follower)
        # No fence daemon remains. Map dump is read-only and never invokes Adopt.
        self.traffic(cluster, phase, True)
        before = self.pin_chain(cluster, phase)
        phase["badConfigAdopt"] = self.maintenance(cluster, phase, "bad-adopt", 1)
        require(self.pin_chain(cluster, phase) == before, "failed adoption changed live fence")
        self.traffic(cluster, phase, True)
        self.retire_phase(cluster, phase, recreate=True)

    def cleanup(self):
        for cluster, state in self.report["clusters"].items():
            try:
                # On a failed install, holdPartial may refuse SIGTERM while an
                # unpinned link is live. Remove only our exact workload first;
                # never force-kill a live partial holder to make cleanup finish.
                for item in list(self.owned.get(cluster, [])):
                    if item[0] == "Pod" and item[1] == self.ns:
                        self.delete_owned(cluster, *item)
                self.uninstall(cluster)
                for phase in state["phases"]:
                    if "installed" in phase and not phase.get("retired"): self.retire_phase(cluster, phase)
            except Exception as error: self.report["cleanupErrors"].append(f"{cluster} fence retirement: {error}")
            for follower in self.followers.get(cluster, []):
                try: follower.stop(wait_for_eof=True)
                except Exception as error: self.report["cleanupErrors"].append(f"{cluster} log capture: {error}")
            for item in sorted(list(self.owned.get(cluster, [])), key=lambda x: {"DaemonSet": 0, "Pod": 1, "ConfigMap": 2, "Namespace": 3}.get(x[0], 2)):
                try: self.delete_owned(cluster, *item)
                except Exception as error: self.report["cleanupErrors"].append(f"{cluster} exact resource cleanup: {error}")
            try:
                remaining = self.get(cluster, "pods", namespace=SYSTEM)["items"]
                require(not any(p["metadata"].get("labels", {}).get(OWNER) == self.run_id for p in remaining), "owned maintenance/DS process still exists; retain locks")
                require(self.get(cluster, "daemonset", DS, SYSTEM, absent=True) is None, "fence DS still exists; retain locks")
                if state.get("nodeOwned") or state.get("nodeOptinAttempted"): self.node_optin(cluster, False)
                for k, root in state["roots"].items(): require(self.root_stat(cluster, root["path"]) == root["stat"], "host root incarnation changed")
                locks = state["roots"].get("lockRoot")
                if locks:
                    expected = {p["key"] + ".lock" for p in state["phases"]}
                    found = self.node(cluster, "find", locks["path"], "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n").stdout.splitlines()
                    require(set(found) <= expected, "foreign lock root entry; refusing unlink")
                    for name in found:
                        path = locks["path"] + "/" + name
                        mode = self.node(cluster, "stat", "-c", "%F|%u|%a", path).stdout.strip()
                        require(mode == "regular empty file|0|600" or mode == "regular file|0|600", "unsafe lock entry")
                        self.node(cluster, "flock", "-n", path, "rm", "--", path, label="remove-owned-inactive-lock")
                for root in state["roots"].values(): self.node(cluster, "rmdir", "--", root["path"], label="remove-empty-owned-root")
                self.verify_foreign_links(cluster)
            except Exception as error: self.report["cleanupErrors"].append(f"{cluster} retained host roots/foreign audit: {error}")
        self.flush()

    def execute(self):
        try:
            self.preflight()
            for cluster in CLUSTERS:
                for direction in self.args.directions: self.run_phase(cluster, direction)
            self.report["status"] = "checks-passed-cleanup-pending"
        except Exception as error:
            self.report.update(status="failed", error=str(error), traceback=traceback.format_exc())
        finally:
            self.cleanup()
            if self.report["cleanupErrors"]: self.report["status"] = "failed"
            elif self.report["status"] == "checks-passed-cleanup-pending": self.report["status"] = "passed"
            self.report["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat(); self.flush()
        print(json.dumps({"status": self.report["status"], "report": str(self.out / "report.json"), "errors": self.report["cleanupErrors"]}))
        return 0 if self.report["status"] == "passed" else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True); p.add_argument("--image-id", required=True)
    p.add_argument("--expected-revision", required=True); p.add_argument("--out", required=True)
    p.add_argument("--kubeconfig", default="/private/tmp/cmtc-a-b-20261024.kubeconfig")
    p.add_argument("--template", default="config/experimental/datapath-fence.yaml")
    p.add_argument("--client-image", default=observer.CURL)
    p.add_argument("--directions", nargs="+", choices=("ingress", "egress"), required=True,
        help="Actual native TCX hooks to qualify; current owned fixture exposes ingress only")
    a = p.parse_args()
    require(a.image.startswith("localhost/") and "@" not in a.image, "explicit archive-loaded local tag required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", a.image_id), "exact image configuration ID required")
    require(re.fullmatch(r"[0-9a-f]{40}", a.expected_revision), "exact committed source revision required")
    require(Path(a.kubeconfig).is_file(), "owned kubeconfig missing")
    return FenceHarness(a).execute()


if __name__ == "__main__": sys.exit(main())
