#!/usr/bin/env python3
"""Owned two-cluster Observe TCX qualification. No mTLS/Protected assertion.
Run with the repository venv (PyYAML), after loading --image on owned kind nodes.
All mutations are confined to a fresh cmtc-observer-lab namespace, one uniquely
owned ConfigMap/DaemonSet, and the explicitly checked worker opt-in label.
"""
import argparse
import copy
import datetime
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import traceback
import uuid

import yaml

from observer_log_capture import ObserverLogCaptureMixin

NS = "cmtc-observer-lab"
SYSTEM = "cmtc-system"
DS = "cmtc-bpf-observer"
CLIENT = "observer-client"
OPTIN = "security.cmtc.io/bpf-observer-lab"
OWNER = "security.cmtc.io/observer-run"
CURL = "curlimages/curl:8.14.1"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(value):
    matches = re.findall(r"sha256:[0-9a-f]{64}", value or "")
    return matches[-1] if matches else value


def validate_native_program_updates(changes, logs, started):
    """Permit only audited Cilium host-link updates with current owner logs."""
    audited = {
        ("eth0", "tcx/ingress", "cil_from_netdev"),
        ("eth0", "tcx/egress", "cil_to_netdev"),
        ("cilium_net", "tcx/ingress", "cil_to_host"),
        ("cilium_host", "tcx/ingress", "cil_to_host"),
        ("cilium_host", "tcx/egress", "cil_from_host"),
    }
    since = datetime.datetime.fromisoformat(started.replace("Z", "+00:00"))
    for change in changes:
        row = change["before"]
        identity = (row.get("devname"), row.get("kind"), row.get("name"))
        require(identity in audited, "unaudited foreign program update: " + repr(identity))
        path = f"/sys/fs/bpf/cilium/devices/{identity[0]}/links/{identity[2]}"
        found = False
        for line in logs.splitlines():
            if 'msg="Updated link for program"' not in line:
                continue
            if not re.search(r"(?:^|\s)link=" + re.escape(path) + r"(?:\s|$)", line):
                continue
            if not re.search(r"(?:^|\s)progName=" + re.escape(identity[2]) + r"(?:\s|$)", line):
                continue
            timestamp = re.search(r"(?:^|\s)time=(\S+)", line)
            if not timestamp:
                continue
            try:
                event = datetime.datetime.fromisoformat(timestamp.group(1).replace("Z", "+00:00"))
                found = event >= since
            except (ValueError, TypeError):
                continue
            if found:
                break
        require(found, "no current native update evidence for " + path)


class Harness(ObserverLogCaptureMixin):
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.run_id = uuid.uuid4().hex[:12]
        self.counter = 0
        self.env = {**os.environ, "KUBECONFIG": args.kubeconfig}
        self.report = {"run": self.run_id, "status": "running", "scope": "observe-only-tcx-policy-preservation",
                       "enforcementAvailable": False, "mtlsProven": False, "image": args.image,
                       "expectedImageID": args.image_id, "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "clusters": {}, "commands": [], "cleanupErrors": []}
        self.owned = {}
        self.monitors = {}
        self.observer_log_init()
        self.template = yaml.safe_load(Path(args.template).read_text())
        require(self.template["metadata"]["name"] == DS, "unexpected observer template")
        require(self.template["metadata"]["namespace"] == SYSTEM, "unexpected observer namespace")
        self.flush()

    def flush(self):
        temporary = self.out / ".report.tmp"
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(self.out / "report.json")

    def command(self, argv, *, input=None, timeout=30, check=True, label="command"):
        self.counter += 1
        stem = f"{self.counter:04d}-{re.sub('[^a-zA-Z0-9_-]', '-', label)}"
        started = time.monotonic()
        try:
            result = subprocess.run(argv, input=input, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout, env=self.env)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""; errors = error.stderr or b""
            if isinstance(output, bytes): output = output.decode(errors="replace")
            if isinstance(errors, bytes): errors = errors.decode(errors="replace")
            result = subprocess.CompletedProcess(argv, 124, output, errors + "\nCOMMAND TIMEOUT")
        (self.out / (stem + ".stdout")).write_text(result.stdout[:2_000_000])
        (self.out / (stem + ".stderr")).write_text(result.stderr[:2_000_000])
        self.report["commands"].append({"argv": argv, "exit": result.returncode,
            "elapsedSeconds": round(time.monotonic() - started, 3), "stdout": stem + ".stdout", "stderr": stem + ".stderr"})
        self.flush()
        if check and result.returncode:
            raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr[-1500:]}")
        return result

    def kubectl(self, cluster, *arguments, **kwargs):
        return self.command(["kubectl", "--context", "kind-" + cluster, *arguments], **kwargs)

    def get(self, cluster, resource, name=None, namespace=None, absent=False, **kwargs):
        argv = ["get", resource]
        if name: argv.append(name)
        if namespace: argv += ["-n", namespace]
        if absent: argv.append("--ignore-not-found")
        result = self.kubectl(cluster, *argv, "-o", "json", label="get-" + resource, **kwargs)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def create(self, cluster, body):
        metadata = body.setdefault("metadata", {})
        metadata.setdefault("labels", {})[OWNER] = self.run_id
        result = self.kubectl(cluster, "create", "-f", "-", "-o", "json", input=json.dumps(body), check=False, label="create-" + body["kind"])
        if result.returncode:
            # A timed-out create can have succeeded server-side. Recover only
            # an exact run-labelled object so finally can clean our own work.
            obj = self.get(cluster, body["kind"], metadata["name"], metadata.get("namespace"), absent=True)
            if obj and obj["metadata"].get("labels", {}).get(OWNER) == self.run_id:
                self.owned.setdefault(cluster, []).append((body["kind"], metadata.get("namespace"), metadata["name"], obj["metadata"]["uid"]))
            raise RuntimeError("create failed or outcome uncertain: " + metadata["name"] + ": " + result.stderr[-1000:])
        obj = json.loads(result.stdout)
        # Register ownership immediately after confirmed creation, before waits.
        self.owned.setdefault(cluster, []).append((body["kind"], metadata.get("namespace"), metadata["name"], obj["metadata"]["uid"]))
        return obj

    def node(self, cluster, *arguments, **kwargs):
        return self.command(["colima", "ssh", "--profile", "cmtc-cilium", "--", "docker", "exec", cluster + "-worker", *arguments], **kwargs)

    def agent_exec(self, cluster, *arguments, **kwargs):
        agent = self.report["clusters"][cluster]["agent"]["name"]
        return self.kubectl(cluster, "-n", "kube-system", "exec", agent, "--", *arguments, **kwargs)

    def poll(self, description, function, timeout=90):
        until = time.monotonic() + timeout
        last = None
        while time.monotonic() < until:
            last = function()
            if last: return last
            time.sleep(1)
        raise RuntimeError(f"timeout: {description}; last={last!r}")

    def tc(self, cluster):
        result = self.agent_exec(cluster, "/usr/local/bin/bpftool", "-j", "net", label="tcx-inventory")
        data = json.loads(result.stdout)
        require(isinstance(data, list), "bpftool net must return array")
        return [entry for network in data for entry in network.get("tc", [])]

    @staticmethod
    def chain(records, ifindex):
        return [{"program": int(row["prog_id"]), "link": int(row["link_id"]), "name": row.get("name", "")}
                for row in records if int(row.get("ifindex", -1)) == ifindex and row.get("kind") == "tcx/ingress"]

    def wait_client(self, cluster):
        def ready():
            pod = self.get(cluster, "pod", CLIENT, NS)
            statuses = pod["status"].get("containerStatuses", [])
            for status in statuses:
                waiting = status.get("state", {}).get("waiting", {})
                require(waiting.get("reason") not in ["CreateContainerConfigError", "ErrImageNeverPull"],
                        "client startup rejected: " + str(waiting))
            return pod if statuses and all(status.get("ready") for status in statuses) else False
        return self.poll("disposable client Ready", ready)

    def create_client(self, cluster):
        return self.create(cluster, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": CLIENT, "namespace": NS,
            "labels": {"app": "cmtc-observer-client"}}, "spec": {"nodeName": cluster + "-worker",
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 100, "runAsGroup": 100}, "containers": [{"name": "curl", "image": CURL,
            "imagePullPolicy": "Never", "command": ["sh", "-c", "sleep 86400"],
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}})

    def preflight(self):
        for cluster in ["cmtc-a", "cmtc-b"]:
            require(self.get(cluster, "namespace", NS, absent=True) is None, f"refuse existing {NS} in {cluster}")
            require(self.get(cluster, "daemonset", DS, SYSTEM, absent=True) is None, f"refuse existing {DS}")
            node = self.get(cluster, "node", cluster + "-worker")
            require(OPTIN not in node["metadata"].get("labels", {}), "refuse existing observer opt-in label")
            require(OWNER not in node["metadata"].get("annotations", {}), "refuse existing node run ownership")
            agents = self.kubectl(cluster,
                "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "--field-selector", "spec.nodeName=" + cluster + "-worker", "-o", "json", label="worker-agent")
            pods = json.loads(agents.stdout)["items"]
            require(len(pods) == 1, "need exactly one worker Cilium agent")
            state = {"agent": {"name": pods[0]["metadata"]["name"], "uid": pods[0]["metadata"]["uid"]}, "nodeUID": node["metadata"]["uid"], "cases": []}
            self.report["clusters"][cluster] = state
            baseline = self.tc(cluster)
            require(not any(row.get("name") == "cmtc_observe" for row in baseline), "foreign/preexisting CMTC observer found")
            state["foreignBaseline"] = baseline
            tool = self.node(cluster, "sh", "-c", "command -v curl || command -v wget", label="metrics-client")
            state["metricsTool"] = tool.stdout.strip().splitlines()[-1]
            backend = self.get(cluster, "pods", namespace="mesh-example")
            candidates = [pod for pod in backend["items"] if pod["metadata"]["name"].startswith("rebel-base-")
                and pod["spec"].get("nodeName") == cluster + "-control-plane" and pod["status"].get("phase") == "Running"]
            require(len(candidates) == 1, "need one existing control-plane rebel-base backend")
            selected = candidates[0]
            state["backend"] = {"cluster": cluster, "name": selected["metadata"]["name"], "ip": selected["status"]["podIP"], "uid": selected["metadata"]["uid"]}
            self.flush()
        # Existing read-only client establishes listener health independently of
        # the new CNP. This rules out a dead31337 listener as denial evidence.
        for origin in ["cmtc-a", "cmtc-b"]:
            for destination in ["cmtc-a", "cmtc-b"]:
                backend = self.report["clusters"][destination]["backend"]
                result = self.kubectl(origin, "-n", "mesh-example", "exec", "mesh-client", "--", "curl", "-fsS", "--max-time", "5", "-D", "-", f"http://{backend['ip']}:31337/", label="independent-31337-control")
                require("x-cmtc-cluster: " + destination in result.stdout.lower(), "independent backend31337 identity missing")

    def discover(self, cluster, pod):
        state = self.report["clusters"][cluster]
        def endpoint():
            result = self.agent_exec(cluster, "cilium-dbg", "endpoint", "list", "-o", "json", label="endpoint-inventory")
            endpoints = json.loads(result.stdout)
            matches = [ep for ep in endpoints if any(addr.get("ipv4") == pod["status"]["podIP"] for addr in ep.get("status", {}).get("networking", {}).get("addressing", []))]
            if len(matches) != 1 or matches[0].get("status", {}).get("state") != "ready": return False
            policy = matches[0]["status"].get("policy", {})
            realized, desired = policy.get("realized", {}), policy.get("spec", {})
            if realized.get("policy-enabled") not in ["egress", "both"]: return False
            if realized.get("policy-revision", 0) < desired.get("policy-revision", 1): return False
            return matches[0]
        ep = self.poll("Cilium endpoint ready", endpoint)
        network = ep["status"]["networking"]
        device = network.get("interface-name") or network.get("interfaceName")
        require(device and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", device), "missing/unsafe host veth name")
        attrs = json.loads(self.node(cluster, "ip", "-j", "link", "show", "dev", device, label="host-veth").stdout)[0]
        baseline = self.chain(self.tc(cluster), attrs["ifindex"])
        require(baseline and baseline[0]["name"].startswith("cil_"), "Cilium must be first baseline anchor")
        inode = int(self.node(cluster, "stat", "-Lc", "%i", "/proc/self/ns/net", label="node-netns-inode").stdout.strip())
        config = {"cluster": cluster, "node": cluster + "-worker", "podUID": pod["metadata"]["uid"], "netNSInode": inode,
                  "ifIndex": attrs["ifindex"], "ifName": device, "mac": attrs["address"], "peerIfIndex": attrs["link_index"],
                  "direction": "ingress", "ciliumLinkID": baseline[0]["link"], "ciliumProgramID": baseline[0]["program"]}
        require(all(config.values()), "incomplete frozen observer config")
        state.update(config=config, baselineChain=baseline, endpoint=ep)
        (self.out / f"{cluster}-config.json").write_text(json.dumps(config, indent=2) + "\n")
        self.flush()
        return config

    def start_monitor(self, cluster):
        self.stop_monitor(cluster)
        endpoint_id = str(self.report["clusters"][cluster]["endpoint"]["id"])
        path = self.out / f"{cluster}-drop-{self.counter}.log"
        file = path.open("w")
        argv = ["kubectl", "--context", "kind-" + cluster, "-n", "kube-system", "exec", self.report["clusters"][cluster]["agent"]["name"], "--", "cilium-dbg", "monitor", "--type", "drop", "--from", endpoint_id]
        process = subprocess.Popen(argv, stdout=file, stderr=subprocess.STDOUT, env=self.env, text=True)
        self.monitors[cluster] = (process, file, path)
        time.sleep(0.5)
        require(process.poll() is None, "native Cilium DROP monitor failed: " + path.read_text()[-1000:])
        self.report["clusters"][cluster].setdefault("dropMonitors", []).append({"argv": argv, "path": path.name, "endpointID": endpoint_id})

    def stop_monitor(self, cluster):
        monitor = self.monitors.pop(cluster, None)
        if not monitor: return
        process, file, path = monitor
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
        file.close()
        if path.stat().st_size > 2_000_000:
            path.write_text(path.read_text()[:2_000_000] + "\nTRUNCATED\n")

    def traffic(self, cluster, phase, repetitions=2):
        state = self.report["clusters"][cluster]
        monitor_path = self.monitors[cluster][2]
        offset = monitor_path.stat().st_size
        attempts = 0
        for _ in range(repetitions):
            for destination in ["cmtc-a", "cmtc-b"]:
                backend = self.report["clusters"][destination]["backend"]
                for port in [80, 8080, 31337]:
                    result = self.kubectl(cluster, "-n", NS, "exec", CLIENT, "--", "curl", "-fsS", "--connect-timeout", "2", "--max-time", "3", "-D", "-", f"http://{backend['ip']}:{port}/", check=False, timeout=10, label=f"{phase}-{destination}-{port}")
                    allowed = port != 31337
                    if allowed:
                        require(result.returncode == 0, f"allowed request failed {cluster}->{destination}:{port}")
                        require("x-cmtc-cluster: " + destination in result.stdout.lower(), "wrong serving cluster")
                        require("x-cmtc-pod: " + backend["name"] in result.stdout.lower(), "wrong serving Pod")
                    else:
                        require(result.returncode in [7, 28], f"denial failed or unrelated error: {result.returncode} {result.stdout}")
                    state["cases"].append({"phase": phase, "destination": destination, "port": port, "allowed": allowed, "exit": result.returncode})
                    attempts += 1
        def policy_drop():
            text = monitor_path.read_text(errors="replace")[offset:]
            source = next(a["ipv4"] for a in state["endpoint"]["status"]["networking"]["addressing"] if a.get("ipv4"))
            denied = [line for line in text.splitlines() if re.search(r"policy.denied|policy_denied|POLICY_DENIED", line, re.I)]
            for destination in ["cmtc-a", "cmtc-b"]:
                target = self.report["clusters"][destination]["backend"]["ip"]
                flow = re.escape(source) + r":\d+\s*->\s*" + re.escape(target) + r":31337\b"
                if not any(re.search(flow, line) for line in denied):
                    return False
            return text
        output = self.poll("native policy DROP evidence for " + phase, policy_drop, timeout=8)
        state.setdefault("dropEvidence", []).append({"phase": phase, "monitor": monitor_path.name, "offset": offset, "length": len(output), "tail": output[-4000:]})
        self.flush()
        return attempts

    def metrics(self, cluster):
        tool = self.report["clusters"][cluster]["metricsTool"]
        arguments = [tool, "-fsS", "--max-time", "3", "http://127.0.0.1:18082/metrics"] if tool.endswith("curl") else [tool, "-qO-", "-T", "3", "http://127.0.0.1:18082/metrics"]
        raw = self.node(cluster, *arguments, label="observer-metrics").stdout
        result = {}
        for name in ["cmtc_datapath_observer_packets_total", "cmtc_datapath_observer_bytes_total", "cmtc_datapath_observer_ready"]:
            values = re.findall(r"^" + name + r"(?:\{[^\n]*\})? ([0-9.eE+-]+)$", raw, re.M)
            require(len(values) == 1, "missing/ambiguous metric " + name)
            result[name] = float(values[0])
        require(result["cmtc_datapath_observer_ready"] == 1, "observer metric sample unavailable")
        return result

    def observer_pod(self, cluster):
        result = self.kubectl(cluster, "-n", SYSTEM, "get", "pods", "-l", "app.kubernetes.io/name=" + DS, "-o", "json", label="observer-pod")
        pods = json.loads(result.stdout)["items"]
        return pods[0] if len(pods) == 1 else None

    def wait_observer(self, cluster, previous_restart=None):
        def ready():
            pod = self.observer_pod(cluster)
            if not pod: return False
            statuses = pod["status"].get("containerStatuses", [])
            if len(statuses) != 1 or not statuses[0].get("ready"): return False
            status = statuses[0]
            if previous_restart is not None and status["restartCount"] <= previous_restart: return False
            # Kubernetes reports an imported manifest digest, not the image
            # configuration ID. Resolve the actual running reference via CRI.
            actual = json.loads(self.node(cluster, "crictl", "inspecti", self.args.image, label="running-image-config").stdout)
            require(digest(status["imageID"]) in {digest(ref) for ref in actual["status"]["repoDigests"]},
                    "running manifest differs from the locally imported image")
            require(actual["status"]["id"] == self.args.image_id, "deployed observer configuration ID mismatch")
            require(actual["info"]["imageSpec"]["architecture"] == "arm64", "wrong deployed architecture")
            return pod
        return self.poll("observer Ready/exact image", ready, timeout=90)

    def check_chain(self, cluster, attached):
        state = self.report["clusters"][cluster]
        chain = self.chain(self.tc(cluster), state["config"]["ifIndex"])
        if attached:
            require(len(chain) == len(state["baselineChain"]) + 1 and chain[1:] == state["baselineChain"] and chain[0]["name"] == "cmtc_observe", "observer did not preserve exact foreign chain/order")
        else:
            require(chain == state["baselineChain"], "foreign TCX baseline changed after observer cleanup")
        return chain

    def acquire_node_optin(self, cluster):
        state = self.report["clusters"][cluster]
        pointer = lambda key: key.replace("~", "~0").replace("/", "~1")
        for attempt in range(3):
            node = self.get(cluster, "node", cluster + "-worker")
            require(node["metadata"]["uid"] == state["nodeUID"], "worker node incarnation changed")
            labels, annotations = node["metadata"].get("labels", {}), node["metadata"].get("annotations", {})
            if annotations.get(OWNER) == self.run_id and labels.get(OPTIN) == "true":
                state["nodeOwned"] = True
                return
            require(OPTIN not in labels and OWNER not in annotations, "node opt-in acquired by another owner")
            patch = [{"op": "test", "path": "/metadata/uid", "value": state["nodeUID"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": node["metadata"]["resourceVersion"]}]
            if "annotations" not in node["metadata"]:
                patch.append({"op": "add", "path": "/metadata/annotations", "value": {}})
            patch += [{"op": "add", "path": "/metadata/annotations/" + pointer(OWNER), "value": self.run_id},
                      {"op": "add", "path": "/metadata/labels/" + pointer(OPTIN), "value": "true"}]
            state["nodeOptinAttempted"] = True
            result = self.kubectl(cluster, "patch", "node", cluster + "-worker", "--type=json", "-p", json.dumps(patch),
                                  check=False, label="atomic-node-optin")
            if not result.returncode:
                state["nodeOwned"] = True
                return
            # A readback on the next attempt resolves a lost response without
            # claiming another run's ownership or broadening the node selector.
            if attempt == 2:
                observed = self.get(cluster, "node", cluster + "-worker")
                require(observed["metadata"]["uid"] == state["nodeUID"] and
                        observed["metadata"].get("annotations", {}).get(OWNER) == self.run_id and
                        observed["metadata"].get("labels", {}).get(OPTIN) == "true", "atomic node opt-in failed")
                state["nodeOwned"] = True
                return
            time.sleep(0.2)

    def install(self, cluster):
        state = self.report["clusters"][cluster]
        configmap = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": DS + "-" + self.run_id, "namespace": SYSTEM}, "immutable": True,
            "data": {cluster + "-worker.json": json.dumps(state["config"])}}
        existing = self.get(cluster, "configmap", configmap["metadata"]["name"], SYSTEM, absent=True)
        if existing is None:
            self.create(cluster, configmap)
        else:
            require(existing["metadata"].get("labels", {}).get(OWNER) == self.run_id and existing.get("immutable") is True and existing["data"] == configmap["data"], "refuse changed or foreign frozen ConfigMap")
        if not state.get("nodeOwned"):
            self.acquire_node_optin(cluster)
        body = copy.deepcopy(self.template)
        body["metadata"].setdefault("labels", {})[OWNER] = self.run_id
        body["spec"]["template"]["metadata"]["labels"][OWNER] = self.run_id
        body["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"] = cluster + "-worker"
        container = body["spec"]["template"]["spec"]["containers"][0]
        container["image"] = self.args.image; container["imagePullPolicy"] = "Never"
        for env in container["env"]:
            if env["name"] == "CLUSTER_NAME": env["value"] = cluster
        body["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"] = DS + "-" + self.run_id
        self.create(cluster, body)
        pod = self.wait_observer(cluster)
        state["deployedObserver"] = pod
        version = self.kubectl(cluster, "-n", SYSTEM, "exec", pod["metadata"]["name"], "--", "/cmtc-bpf-observer", "--version", label="observer-binary-version").stdout.strip()
        require("enforcementAvailable=false" in version and re.search(r"revision=[0-9a-f]{40}\b", version), "observer binary source pin missing")
        if self.args.expected_revision:
            require("revision=" + self.args.expected_revision + " " in version, "observer binary source revision mismatch")
        state["observerBinaryVersion"] = version
        self.check_chain(cluster, True)
        self.capture_observer_logs(cluster, pod, "install")

    def kill_observer(self, cluster):
        state = self.report["clusters"][cluster]
        pod = self.wait_observer(cluster)
        status = pod["status"]["containerStatuses"][0]
        cid = status["containerID"].split("://", 1)[-1]
        require(re.fullmatch(r"[0-9a-f]{64}", cid), "unsafe/ambiguous observer containerID")
        info = json.loads(self.node(cluster, "crictl", "inspect", cid, label="observer-cri-inspect").stdout)
        cri = info["status"]; labels = cri.get("labels", {})
        require(cri.get("id") == cid and cri.get("metadata", {}).get("name") == "observer", "CRI container identity mismatch")
        require(labels.get("io.kubernetes.pod.uid") == pod["metadata"]["uid"] and labels.get("io.kubernetes.pod.namespace") == SYSTEM and labels.get("io.kubernetes.pod.name") == pod["metadata"]["name"], "CRI observer Pod ownership mismatch")
        pid = int(info["info"]["pid"])
        require(pid > 1, "refuse invalid observer PID")
        executable = self.node(cluster, "readlink", f"/proc/{pid}/exe", label="observer-executable").stdout.strip()
        require(executable == "/cmtc-bpf-observer", "refuse SIGKILL of unexpected executable")
        stat = self.node(cluster, "cat", f"/proc/{pid}/stat", label="observer-pid-starttime").stdout
        starttime = stat[stat.rfind(")") + 2:].split()[19]
        require(starttime.isdecimal(), "invalid PID starttime")
        # Only decimal PID/starttime and a fixed executable enter this script.
        script = f'test "$(readlink /proc/{pid}/exe)" = /cmtc-bpf-observer && test "$(awk \'{{print $22}}\' /proc/{pid}/stat)" = {starttime} && kill -9 {pid}'
        self.node(cluster, "sh", "-c", script, label="SIGKILL-owned-observer")
        restarted = self.wait_observer(cluster, status["restartCount"])
        self.observer_log_after_sigkill(cluster, pod, restarted)
        terminated = restarted["status"]["containerStatuses"][0].get("lastState", {}).get("terminated", {})
        require(terminated.get("exitCode") == 137 or terminated.get("signal") == 9, "no expected SIGKILL termination evidence")
        chain = self.check_chain(cluster, True)
        state["sigkillRecovery"] = {"containerID": cid, "pid": pid, "starttime": starttime, "termination": terminated, "newStatus": restarted["status"]["containerStatuses"][0], "chain": chain}
        before = self.metrics(cluster); self.traffic(cluster, "post-sigkill", repetitions=1); time.sleep(1.2); after = self.metrics(cluster)
        require(after["cmtc_datapath_observer_packets_total"] > before["cmtc_datapath_observer_packets_total"], "new observer process did not count real packets")
        state["postRestartCounterDelta"] = after["cmtc_datapath_observer_packets_total"] - before["cmtc_datapath_observer_packets_total"]

    def delete_owned(self, cluster, kind, namespace, name, uid):
        routes = {"Namespace": ("/api/v1", "namespaces"),
                  "Pod": ("/api/v1", "pods"), "ConfigMap": ("/api/v1", "configmaps"),
                  "DaemonSet": ("/apis/apps/v1", "daemonsets"),
                  "CiliumNetworkPolicy": ("/apis/cilium.io/v2", "ciliumnetworkpolicies")}
        prefix, resource = routes[kind]
        uri = prefix + ("/namespaces/" + namespace if namespace else "") + "/" + resource + "/" + name
        for attempt in range(3):
            current = self.get(cluster, kind, name, namespace, absent=True)
            if current is None:
                return
            require(current["metadata"]["uid"] == uid and current["metadata"].get("labels", {}).get(OWNER) == self.run_id,
                    "cleanup refuses object with changed UID/owner: " + name)
            options = {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
                       "preconditions": {"uid": uid, "resourceVersion": current["metadata"]["resourceVersion"]}}
            result = self.kubectl(cluster, "delete", "--raw", uri, "-f", "-", input=json.dumps(options),
                                  check=False, label="cleanup-" + kind)
            if not result.returncode:
                break
            require("Conflict" in result.stderr and attempt < 2, "atomic cleanup failed: " + result.stderr)
            time.sleep(0.2)
        def gone():
            remaining = self.get(cluster, kind, name, namespace, absent=True)
            if remaining is None:
                return True
            require(remaining["metadata"]["uid"] == uid, "replacement detected while waiting for deletion: " + name)
            return False
        self.poll("owned object removed: " + name, gone, timeout=90)

    def uninstall(self, cluster):
        resources = self.owned.get(cluster, [])
        for item in list(resources):
            if item[0] == "DaemonSet":
                self.delete_owned(cluster, *item); resources.remove(item)
        self.poll("observer fully removed", lambda: self.observer_pod(cluster) is None)
        self.observer_log_expect_detach(cluster)
        self.check_chain(cluster, False)
        state = self.report["clusters"][cluster]
        state["foreignChainAfterCleanup"] = self.tc(cluster)

    def replace_client(self, cluster):
        state = self.report["clusters"][cluster]
        resources = self.owned[cluster]
        old = next(item for item in resources if item[0] == "Pod")
        self.delete_owned(cluster, *old); resources.remove(old)
        new = self.create_client(cluster); new = self.wait_client(cluster)
        require(new["metadata"]["uid"] != state["config"]["podUID"], "client was not recreated")
        def unavailable():
            pod = self.observer_pod(cluster)
            if not pod: return False
            statuses = pod["status"].get("containerStatuses", [])
            return pod if statuses and not statuses[0].get("ready") else False
        failed = self.poll("old immutable config NotReady after client replacement", unavailable, timeout=45)
        require(not any(row.get("name") == "cmtc_observe" for row in self.tc(cluster)), "old observer anchor survived deleted client")
        self.observer_log_expect_stale_failure(cluster)
        state["oldConfigRejectedAfterPodReplacement"] = {"newPodUID": new["metadata"]["uid"], "observerStatus": failed["status"]}
        self.stop_monitor(cluster)
        # Preserve the original config/evidence. The new endpoint is used only
        # to verify policy after removing observer; never republish its anchor.
        result = self.agent_exec(cluster, "cilium-dbg", "endpoint", "list", "-o", "json", label="replacement-endpoint")
        matches = [ep for ep in json.loads(result.stdout) if any(a.get("ipv4") == new["status"]["podIP"] for a in ep.get("status", {}).get("networking", {}).get("addressing", []))]
        require(len(matches) == 1, "new client Cilium endpoint missing")
        state["endpoint"] = matches[0]
        self.start_monitor(cluster)

    def verify_foreign_links(self, cluster):
        state = self.report["clusters"][cluster]
        remaining = self.tc(cluster)
        # Cilium legitimately updates host programs on its retained links when
        # policy/endpoint state changes. Preserve link ownership/incarnation,
        # and record program updates; never relax the selected-veth check_chain.
        key = lambda row: (row.get("ifindex"), row.get("kind"), row.get("link_id"), row.get("name"))
        before = {key(row): row for row in state["foreignBaseline"]}
        after = {key(row): row for row in remaining}
        require(before.keys() <= after.keys(), "unrelated foreign TCX link disappeared")
        changes = [{"before": row, "after": after[identity]} for identity, row in before.items()
                   if row.get("prog_id") != after[identity].get("prog_id")]
        state.setdefault("foreignProgramUpdates", []).append(changes)
        state["finalForeignInventory"] = remaining
        if changes:
            logs = self.kubectl(cluster, "-n", "kube-system", "logs", state["agent"]["name"],
                                "--since-time=" + self.report["started"], label="native-cilium-program-updates").stdout
            validate_native_program_updates(changes, logs, self.report["started"])
        self.flush()

    def cleanup(self):
        for cluster in list(self.monitors):
            try: self.stop_monitor(cluster)
            except Exception as error: self.report["cleanupErrors"].append(f"monitor {cluster}: {error}")
        for cluster, resources in self.owned.items():
            # DS first, then ConfigMap/policy/Pod, Namespace last. Exact UID+owner
            # protects resources against replacement between task boundaries.
            order = {"DaemonSet": 0, "ConfigMap": 1, "CiliumNetworkPolicy": 2, "Pod": 3, "Namespace": 4}
            for item in sorted(resources, key=lambda value: order.get(value[0], 3)):
                try: self.delete_owned(cluster, *item)
                except Exception as error: self.report["cleanupErrors"].append(f"{cluster} {item}: {error}")
            state = self.report["clusters"][cluster]
            if state.get("nodeOwned") or state.get("nodeOptinAttempted"):
                try:
                    node = self.get(cluster, "node", cluster + "-worker")
                    require(node["metadata"]["uid"] == state["nodeUID"], "node incarnation changed")
                    owner = node["metadata"].get("annotations", {}).get(OWNER)
                    label = node["metadata"].get("labels", {}).get(OPTIN)
                    if owner is None and label is None:
                        state["nodeOptinReleased"] = True
                        continue
                    require(owner == self.run_id, "node opt-in ownership changed")
                    require(label in [None, "true"], "node opt-in label changed")
                    pointer = lambda key: key.replace("~", "~0").replace("/", "~1")
                    patch = [{"op": "test", "path": "/metadata/uid", "value": state["nodeUID"]},
                             {"op": "test", "path": "/metadata/annotations/" + pointer(OWNER), "value": self.run_id}]
                    if label is not None:
                        patch += [{"op": "test", "path": "/metadata/labels/" + pointer(OPTIN), "value": "true"},
                                  {"op": "remove", "path": "/metadata/labels/" + pointer(OPTIN)}]
                    patch.append({"op": "remove", "path": "/metadata/annotations/" + pointer(OWNER)})
                    self.kubectl(cluster, "patch", "node", cluster + "-worker", "--type=json", "-p", json.dumps(patch), label="cleanup-node-optin")
                    state["nodeOptinReleased"] = True
                except Exception as error: self.report["cleanupErrors"].append(f"{cluster} node cleanup: {error}")
        for cluster in self.owned:
            try:
                self.verify_foreign_links(cluster)
                self.report["clusters"][cluster]["foreignInventoryAfterFinalCleanup"] = self.report["clusters"][cluster]["finalForeignInventory"]
            except Exception as error:
                self.report["cleanupErrors"].append(f"{cluster} final foreign inventory: {error}")
        self.observer_log_close_all()
        self.flush()

    def prepare_cluster(self, cluster):
        self.create(cluster, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NS}})
        self.create_client(cluster); pod = self.wait_client(cluster)
        self.create(cluster, {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy", "metadata": {"name": "observer-native-egress", "namespace": NS},
            "spec": {"endpointSelector": {"matchLabels": {"app": "cmtc-observer-client"}}, "egress": [{"toEntities": ["all"], "toPorts": [{"ports": [{"port": "80", "protocol": "TCP"}, {"port": "8080", "protocol": "TCP"}]}]}]}})
        # CNP synchronization may lag API creation. Require denied31337
        # from this exact endpoint before accepting any phase evidence.
        self.discover(cluster, pod)
        self.start_monitor(cluster); self.traffic(cluster, "before-observer")
        self.install(cluster)

    def exercise_cluster(self, cluster):
        before = self.metrics(cluster); self.traffic(cluster, "during-observer", repetitions=self.args.repetitions); time.sleep(1.2); after = self.metrics(cluster)
        require(after["cmtc_datapath_observer_packets_total"] > before["cmtc_datapath_observer_packets_total"], "no actual observer packet delta")
        require(after["cmtc_datapath_observer_bytes_total"] > before["cmtc_datapath_observer_bytes_total"], "no actual observer byte delta")
        self.report["clusters"][cluster]["loadMetricSamples"] = {"before": before, "after": after}
        self.kill_observer(cluster)
        # Check foreign chain after observer deletion before deliberately
        # removing the veth needed for the immutable-config negative.
        self.uninstall(cluster)
        self.traffic(cluster, "after-observer")
        # Reinstall only the SAME frozen config, then remove its Pod.
        self.install(cluster)
        self.replace_client(cluster)
        # DS deletion cannot compare a deleted-veth chain; its foreign
        # preservation was already checked above while that veth lived.
        resources = self.owned[cluster]
        for item in list(resources):
            if item[0] == "DaemonSet": self.delete_owned(cluster, *item); resources.remove(item)
        self.poll("stale observer removed", lambda: self.observer_pod(cluster) is None)
        self.traffic(cluster, "after-old-config-rejection", repetitions=1)
        self.verify_foreign_links(cluster)

    def after_all_installed(self):
        """Optional telemetry hook; both exact worker observers remain installed."""
        pass

    def after_all_removed(self):
        """Optional absent-telemetry hook after both recovery phases removed DSs."""
        pass

    def execute(self):
        try:
            self.preflight()
            for cluster in ["cmtc-a", "cmtc-b"]: self.prepare_cluster(cluster)
            self.after_all_installed()
            for cluster in ["cmtc-a", "cmtc-b"]: self.exercise_cluster(cluster)
            self.after_all_removed()
            self.report["status"] = "checks-passed-cleanup-pending"
        except Exception as error:
            self.report["status"] = "failed"; self.report["error"] = str(error); self.report["traceback"] = traceback.format_exc()
        finally:
            self.cleanup()
            if self.report["cleanupErrors"]: self.report["status"] = "failed"
            elif self.report["status"] == "checks-passed-cleanup-pending": self.report["status"] = "passed"
            self.report["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat(); self.flush()
        return 0 if self.report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--kubeconfig", default="/private/tmp/cmtc-a-b-20261024.kubeconfig")
    parser.add_argument("--template", default="config/experimental/datapath-observer.yaml")
    parser.add_argument("--repetitions", type=int, default=4)
    parser.add_argument("--expected-revision", help="Full40-character committed observer source SHA")
    args = parser.parse_args()
    require(args.image.startswith("localhost/") and "@" not in args.image, "use explicit local observer image tag, already loaded by archive")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id), "image-id must be exact SHA256 config ID")
    require(1 <= args.repetitions <= 20, "repetitions must be1..20")
    require(not args.expected_revision or re.fullmatch(r"[0-9a-f]{40}", args.expected_revision), "expected-revision must be full source SHA")
    require(Path(args.kubeconfig).is_file(), "owned lab kubeconfig missing")
    harness = Harness(args)
    result = harness.execute()
    print(json.dumps({"status": harness.report["status"], "report": str(harness.out / "report.json"), "error": harness.report.get("error"), "cleanupErrors": harness.report["cleanupErrors"]}))
    return result


if __name__ == "__main__":
    sys.exit(main())
