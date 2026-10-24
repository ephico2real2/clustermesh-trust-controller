#!/usr/bin/env python3
"""Qualify Namespace UID propagation on the four live Cilium agents in cmtc-a/b.

This is a metadata-only test. It creates no Pods and does not enable ztunnel,
change encryption, or alter the Cilium compatibility guard. Run only after the
normal scripts/lab/test.sh suite has exited, because that suite recreates
payments-alpha and otherwise causes unrelated namespace-table churn.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path("/private/tmp/cilium-ztunnel-authorization-runtime")
ARTIFACTS = Path("/private/tmp/cmtc-namespace-uid-20261024")
EXPECTED_SOURCE = "4459d58ed3d98805f15c74298076025fc97dd540"
EXPECTED_IMAGE = "localhost/cilium:namespace-uid-4459d58ed3"
EXPECTED_CONFIG_ID = "78b0b8894d47f5ea49ac783421846303f4a8061aaefb6108bcc1b1ea919d2674"
EXPECTED_ARCH = "arm64"
NAMESPACE = "cmtc-namespace-uid-check"
OWNER_ANNOTATION = "security.cmtc.io/namespace-uid-qualification-run"
CLUSTERS = ("cmtc-a", "cmtc-b")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalized_config_id(value):
    value = str(value or "").strip()
    return value.removeprefix("sha256:").lower()


def digest(value):
    match = re.search(r"sha256:[0-9a-f]{64}", value or "")
    return match.group(0) if match else (value or "")


def parse_json_stream(text, source):
    """Parse db/show's concatenated, pretty-printed JSON objects."""
    decoder = json.JSONDecoder()
    position = 0
    objects = []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        value, position = decoder.raw_decode(text, position)
        require(isinstance(value, dict), f"{source}: expected JSON objects, got {type(value).__name__}")
        objects.append(value)
    return objects


def namespace_uid_map(objects, source):
    result = {}
    for item in objects:
        name = item.get("name")
        uid = item.get("uid")
        require(isinstance(name, str) and name, f"{source}: namespace entry has no name: {item!r}")
        require(isinstance(uid, str) and uid, f"{source}: namespace {name!r} has no live UID")
        require(name not in result, f"{source}: duplicate namespace entry {name!r}")
        result[name] = uid
    return result


def elf_architecture(path):
    with path.open("rb") as stream:
        header = stream.read(20)
    require(len(header) >= 20 and header[:4] == b"\x7fELF", f"{path}: not an ELF executable")
    byte_order = header[5]
    require(byte_order in (1, 2), f"{path}: unsupported ELF byte order {byte_order}")
    endian = "<" if byte_order == 1 else ">"
    machine = struct.unpack(endian + "H", header[18:20])[0]
    architectures = {62: "amd64", 183: "arm64"}
    require(machine in architectures, f"{path}: unsupported ELF machine id {machine}")
    return architectures[machine]


class Qualification:
    def __init__(self, args):
        self.args = args
        self.run_id = str(uuid.uuid4())
        self.out = Path(args.out).expanduser().resolve() if args.out else (
            ARTIFACTS / "evidence" / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + self.run_id[:8])
        )
        self.out.mkdir(parents=True, exist_ok=False)
        (self.out / "namespace-checks").mkdir()
        self.commands_path = self.out / "commands.ndjson"
        self.sequence = 0
        self.owned = {cluster: None for cluster in CLUSTERS}
        self.agent_inventory = {cluster: [] for cluster in CLUSTERS}
        self.report = {
            "schemaVersion": 1,
            "runID": self.run_id,
            "scope": "live-kubernetes-namespace-uid-projection",
            "startedAt": self.now(),
            "status": "running",
            "source": EXPECTED_SOURCE,
            "image": EXPECTED_IMAGE,
            "namespace": NAMESPACE,
            "podsCreated": 0,
            "clusters": {},
            "cleanupErrors": [],
        }
        self.write_report()

    @staticmethod
    def now():
        return dt.datetime.now(dt.timezone.utc).isoformat()

    def write_report(self):
        temp = self.out / ".results.tmp"
        temp.write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")
        temp.replace(self.out / "results.json")

    def emit(self, message):
        print(message, flush=True)
        with (self.out / "checks.txt").open("a") as stream:
            stream.write(message + "\n")

    def command(self, argv, *, input_text=None, check=True, timeout=45, label="command"):
        self.sequence += 1
        start = time.monotonic()
        try:
            result = subprocess.run(
                argv, input=input_text, text=True, capture_output=True,
                timeout=timeout, env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired as error:
            record = {
                "sequence": self.sequence, "at": self.now(), "label": label,
                "argv": argv, "exitCode": None,
                "elapsedSeconds": round(time.monotonic() - start, 3),
                "timeoutSeconds": timeout, "error": str(error),
            }
            with self.commands_path.open("a") as stream:
                stream.write(json.dumps(record) + "\n")
            raise RuntimeError(f"{label} timed out after {timeout}s") from error
        record = {
            "sequence": self.sequence, "at": self.now(), "label": label,
            "argv": argv, "exitCode": result.returncode,
            "elapsedSeconds": round(time.monotonic() - start, 3),
            "stdoutBytes": len(result.stdout.encode()),
            "stdoutSHA256": sha256_bytes(result.stdout.encode()),
            "stderrBytes": len(result.stderr.encode()),
            "stderrSHA256": sha256_bytes(result.stderr.encode()),
        }
        if input_text is not None:
            record["stdinBytes"] = len(input_text.encode())
            record["stdinSHA256"] = sha256_bytes(input_text.encode())
        with self.commands_path.open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        if check and result.returncode:
            detail = result.stderr.strip()[-1200:] or result.stdout.strip()[-1200:]
            raise RuntimeError(f"{label} failed with exit {result.returncode}: {detail}")
        return result

    def kubectl(self, cluster, *args, **kwargs):
        argv = ["kubectl", "--kubeconfig", str(self.args.kubeconfig), "--context", "kind-" + cluster, *args]
        return self.command(argv, **kwargs)

    def get_json(self, cluster, *args, **kwargs):
        result = self.kubectl(cluster, *args, "-o", "json", **kwargs)
        require(result.stdout.strip(), f"empty JSON response from kubectl: {args}")
        return json.loads(result.stdout)

    def colima_node(self, node, *args, **kwargs):
        argv = ["colima", "ssh", "--profile", "cmtc-cilium", "--", "docker", "exec", node, *args]
        return self.command(argv, **kwargs)

    def check_local_build(self):
        source = Path(self.args.cilium_source).resolve()
        agent_binary = source / "daemon" / "cilium-agent"
        image_metadata = Path(self.args.image_metadata).resolve()
        require(source.is_dir(), f"Cilium source checkout does not exist: {source}")
        require(agent_binary.is_file(), f"expected local daemon/cilium-agent is missing: {agent_binary}")
        require(image_metadata.is_file(), f"local Podman image metadata is missing: {image_metadata}")

        revision = self.command(["git", "-C", str(source), "rev-parse", "HEAD"], label="source-revision").stdout.strip()
        dirty = self.command(
            ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"],
            label="source-dirty-state",
        ).stdout.strip()
        require(revision == EXPECTED_SOURCE, f"Cilium source revision mismatch: {revision}")
        require(not dirty, f"Cilium source checkout is dirty: {dirty}")

        binary_hash = file_sha256(agent_binary)
        binary_arch = elf_architecture(agent_binary)
        require(binary_arch == EXPECTED_ARCH, f"local cilium-agent architecture is {binary_arch}, expected {EXPECTED_ARCH}")

        inspected = json.loads(image_metadata.read_text())
        require(isinstance(inspected, list) and len(inspected) == 1, "Podman image inspect artifact must contain exactly one image")
        image = inspected[0]
        image_id = normalized_config_id(image.get("Id"))
        require(image_id == EXPECTED_CONFIG_ID, f"local image config ID mismatch: {image.get('Id')}")
        require(image.get("Architecture") == EXPECTED_ARCH, f"local image architecture mismatch: {image.get('Architecture')}")
        labels = image.get("Labels") or {}
        require(labels.get("org.opencontainers.image.revision") == EXPECTED_SOURCE,
                "local image revision label does not match the expected full source SHA")
        require(EXPECTED_IMAGE in image.get("RepoTags", []), "local Podman image tag does not match the expected image")

        snapshot = Path(self.args.reference_snapshot).resolve()
        require(snapshot.is_file(), f"namespace reference snapshot is missing: {snapshot}")
        snapshot_rows = parse_json_stream(snapshot.read_text(), str(snapshot))
        snapshot_map = namespace_uid_map(snapshot_rows, str(snapshot))
        self.report["referenceSnapshot"] = {
            "path": str(snapshot), "sha256": file_sha256(snapshot),
            "namespaceCount": len(snapshot_map), "containsUIDs": True,
            "note": "format sanity reference only; live API and each agent StateDB are the runtime sources of truth",
        }
        self.report["expectedLocalImage"] = {
            "sourceRevision": revision,
            "image": EXPECTED_IMAGE,
            "configID": EXPECTED_CONFIG_ID,
            "architecture": binary_arch,
            "daemonCiliumAgentSHA256": binary_hash,
            "imageMetadataPath": str(image_metadata),
        }
        self.write_report()
        self.emit(f"PASS local source/image preflight: revision={revision}, image-config={EXPECTED_CONFIG_ID}, arch={binary_arch}, daemon/cilium-agent-sha256={binary_hash}")

    def check_test_suite_idle(self):
        result = self.command(["ps", "-axo", "pid=,command="], label="check-lab-suite-idle")
        active = []
        for line in result.stdout.splitlines():
            if "scripts/lab/test.sh" not in line or "verify-live-uid.py" in line:
                continue
            fields = line.strip().split(None, 1)
            if fields and fields[0] != str(os.getpid()):
                active.append(line.strip())
        require(not active, "scripts/lab/test.sh is still running; wait for its namespace recreation to finish before this test")
        self.emit("PASS lab exclusivity: scripts/lab/test.sh is not running")

    def check_contexts_and_image(self):
        contexts = self.command(
            ["kubectl", "--kubeconfig", str(self.args.kubeconfig), "config", "get-contexts", "-o", "name"],
            label="kube-contexts",
        ).stdout.splitlines()
        for cluster in CLUSTERS:
            require("kind-" + cluster in contexts, f"missing expected kube context kind-{cluster}")

        for cluster in CLUSTERS:
            values = json.loads(self.command(["helm", "--kube-context", "kind-"+cluster,
                "--kubeconfig", str(self.args.kubeconfig), "-n", "kube-system", "get", "values", "cilium", "-o", "json"], label="verify-encryption-disabled").stdout)
            require(values.get("encryption", {}).get("enabled") is False, cluster+": encryption unexpectedly enabled")
            active = self.get_json(cluster, "get", "pods", "-A").get("items", [])
            require(not any("ztunnel" in c.get("name", "") for pod in active for c in pod.get("spec", {}).get("containers", [])), cluster+": unexpected active ztunnel")
            nodes = self.get_json(cluster, "get", "nodes")
            node_names = sorted(item["metadata"]["name"] for item in nodes.get("items", []))
            cluster_nodes = [name for name in node_names if name.startswith(cluster + "-")]
            require(len(cluster_nodes) == 2, f"{cluster}: expected the existing two-node lab, found {cluster_nodes}")
            require(set(cluster_nodes) == {cluster + "-control-plane", cluster + "-worker"},
                    f"{cluster}: unexpected owned lab nodes {cluster_nodes}")

            daemonset = self.get_json(cluster, "-n", "kube-system", "get", "daemonset", "cilium")
            status = daemonset.get("status", {})
            require(status.get("desiredNumberScheduled") == 2 and status.get("numberReady") == 2,
                    f"{cluster}: Cilium DaemonSet is not Ready 2/2: {status}")
            pods = self.get_json(cluster, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium").get("items", [])
            require(len(pods) == 2, f"{cluster}: expected two Cilium agent Pods, found {len(pods)}")
            by_node = {pod.get("spec", {}).get("nodeName"): pod for pod in pods}
            require(set(by_node) == set(cluster_nodes), f"{cluster}: Cilium agents do not cover both lab nodes: {sorted(by_node)}")
            inventory = []
            for node in cluster_nodes:
                pod = by_node[node]
                meta = pod.get("metadata", {})
                require(not meta.get("deletionTimestamp"), f"{cluster}/{node}: Cilium agent is terminating")
                containers = pod.get("spec", {}).get("containers", [])
                statuses = pod.get("status", {}).get("containerStatuses", [])
                agent_spec = next((container for container in containers if container.get("name") == "cilium-agent"), None)
                agent_status = next((container for container in statuses if container.get("name") == "cilium-agent"), None)
                require(agent_spec is not None and agent_status is not None, f"{cluster}/{node}: cilium-agent container/status missing")
                require(agent_spec.get("image") == EXPECTED_IMAGE,
                        f"{cluster}/{node}: pod spec image {agent_spec.get('image')!r} != {EXPECTED_IMAGE!r}")
                require(agent_status.get("ready") is True, f"{cluster}/{node}: cilium-agent container not Ready")

                version = self.kubectl(
                    cluster, "-n", "kube-system", "exec", meta["name"], "-c", "cilium-agent", "--",
                    "/usr/bin/cilium-agent", "--version", label="deployed-agent-version",
                ).stdout.strip()
                require(EXPECTED_SOURCE[:10] in version,
                        f"{cluster}/{node}: deployed cilium-agent version does not contain {EXPECTED_SOURCE[:10]}: {version}")
                live_hash_output = self.kubectl(
                    cluster, "-n", "kube-system", "exec", meta["name"], "-c", "cilium-agent", "--",
                    "sha256sum", "/usr/bin/cilium-agent", label="deployed-agent-binary-sha256",
                ).stdout.strip()
                match = re.match(r"^([0-9a-f]{64})\s+", live_hash_output)
                require(match is not None, f"{cluster}/{node}: cannot parse deployed cilium-agent SHA-256: {live_hash_output!r}")
                live_hash = match.group(1)
                expected_hash = self.report["expectedLocalImage"]["daemonCiliumAgentSHA256"]
                require(live_hash == expected_hash,
                        f"{cluster}/{node}: deployed cilium-agent hash {live_hash} != local binary {expected_hash}")

                inspect_result = self.colima_node(
                    node, "crictl", "inspecti", EXPECTED_IMAGE, label="deployed-agent-image-config",
                )
                inspect = json.loads(inspect_result.stdout)
                actual_id = normalized_config_id((inspect.get("status") or {}).get("id"))
                require(actual_id == EXPECTED_CONFIG_ID,
                        f"{cluster}/{node}: runtime image config ID {actual_id} != {EXPECTED_CONFIG_ID}")
                architecture = (inspect.get("info") or {}).get("imageSpec", {}).get("architecture")
                require(architecture == EXPECTED_ARCH,
                        f"{cluster}/{node}: runtime image architecture {architecture!r} != {EXPECTED_ARCH!r}")
                image_digests = {
                    digest(reference)
                    for reference in (inspect.get("status") or {}).get("repoDigests", [])
                    if digest(reference)
                }
                running_digest = digest(agent_status.get("imageID", ""))
                require(running_digest and running_digest in image_digests,
                        f"{cluster}/{node}: running Pod imageID {agent_status.get('imageID')!r} does not resolve to the inspected local image")

                inventory.append({
                    "node": node,
                    "pod": meta["name"],
                    "podUID": meta.get("uid"),
                    "containerID": agent_status.get("containerID"),
                    "image": agent_spec.get("image"),
                    "imageID": agent_status.get("imageID"),
                    "imageConfigID": actual_id,
                    "architecture": architecture,
                    "agentVersion": version,
                    "binarySHA256": live_hash,
                })
            self.agent_inventory[cluster] = inventory
            self.report["clusters"][cluster] = {
                "agents": inventory,
                "namespaceUIDChecks": [],
                "uidTransition": {},
            }
            self.write_report()
            self.emit(f"PASS {cluster}: two agents match configID={EXPECTED_CONFIG_ID}, arch={EXPECTED_ARCH}, revision={EXPECTED_SOURCE}, binary SHA-256={self.report['expectedLocalImage']['daemonCiliumAgentSHA256']}")

    def get_namespace_json(self, cluster):
        result = self.kubectl(
            cluster, "get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "json",
            label="get-owned-namespace-json",
        )
        return json.loads(result.stdout) if result.stdout.strip() else None

    def get_live_namespaces(self, cluster):
        raw = self.get_json(cluster, "get", "namespaces")
        rows = raw.get("items", [])
        names = {}
        for item in rows:
            metadata = item.get("metadata", {})
            name, uid = metadata.get("name"), metadata.get("uid")
            require(isinstance(name, str) and name, f"{cluster}: Kubernetes Namespace has no name")
            require(isinstance(uid, str) and uid, f"{cluster}: Kubernetes Namespace {name!r} has no UID")
            require(name not in names, f"{cluster}: Kubernetes API returned duplicate namespace {name!r}")
            names[name] = uid
        return names

    def agent_pod_current(self, cluster, expected):
        pods = self.get_json(cluster, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium").get("items", [])
        by_node = {pod.get("spec", {}).get("nodeName"): pod for pod in pods}
        current = []
        for original in expected:
            pod = by_node.get(original["node"])
            require(pod is not None, f"{cluster}/{original['node']}: Cilium agent Pod disappeared")
            meta = pod.get("metadata", {})
            require(meta.get("uid") == original["podUID"],
                    f"{cluster}/{original['node']}: Cilium agent Pod incarnation changed during namespace test")
            require(not meta.get("deletionTimestamp"), f"{cluster}/{original['node']}: agent is terminating")
            current.append(pod)
        return current

    def dump_agent_namespace_table(self, cluster, agent):
        pod = agent["pod"]
        result = self.kubectl(
            cluster, "-n", "kube-system", "exec", pod, "-c", "cilium-agent", "--",
            "/usr/bin/cilium-dbg", "shell", "--", "db/show", "--format=json", "k8s-namespaces",
            label="cilium-db-show-k8s-namespaces",
        )
        objects = parse_json_stream(result.stdout, f"{cluster}/{pod} db/show k8s-namespaces")
        return namespace_uid_map(objects, f"{cluster}/{pod} db/show k8s-namespaces")

    def wait_for_namespace_convergence(self, cluster, stage, expected_fixture_uid=None, fixture_absent=False, timeout=90):
        deadline = time.monotonic() + timeout
        last_diff = None
        agents = self.agent_inventory[cluster]
        while time.monotonic() < deadline:
            api_uids = self.get_live_namespaces(cluster)
            if fixture_absent:
                require(NAMESPACE not in api_uids, f"{cluster}: fixture namespace still exists in Kubernetes API")
            if expected_fixture_uid is not None:
                require(api_uids.get(NAMESPACE) == expected_fixture_uid,
                        f"{cluster}: API fixture UID changed unexpectedly: {api_uids.get(NAMESPACE)!r}")
            diffs = []
            tables = []
            current_pods = self.agent_pod_current(cluster, agents)
            for agent, pod in zip(agents, current_pods):
                observed = self.dump_agent_namespace_table(cluster, agent)
                missing = sorted(set(api_uids) - set(observed))
                extra = sorted(set(observed) - set(api_uids))
                changed = {
                    name: {"apiUID": api_uids[name], "tableUID": observed[name]}
                    for name in sorted(set(api_uids) & set(observed))
                    if api_uids[name] != observed[name]
                }
                tables.append({
                    "node": agent["node"], "pod": agent["pod"], "podUID": agent["podUID"],
                    "namespaceUIDs": observed,
                    "matchesKubernetes": not missing and not extra and not changed,
                })
                if missing or extra or changed:
                    diffs.append({"node": agent["node"], "missing": missing, "extra": extra, "changedUIDs": changed})
            last_diff = {"missingOrChanged": diffs, "apiNamespaceCount": len(api_uids)}
            if not diffs:
                check = {
                    "stage": stage,
                    "observedAt": self.now(),
                    "apiNamespaceUIDs": api_uids,
                    "agentTables": tables,
                    "allAgentUIDMapsMatchKubernetes": True,
                    "agentCount": len(tables),
                }
                name = re.sub(r"[^a-zA-Z0-9_-]", "-", f"{cluster}-{stage}")
                path = self.out / "namespace-checks" / (name + ".json")
                path.write_text(json.dumps(check, indent=2, sort_keys=True) + "\n")
                self.report["clusters"][cluster]["namespaceUIDChecks"].append({
                    "stage": stage, "agentCount": len(tables), "namespaceCount": len(api_uids),
                    "allAgentUIDMapsMatchKubernetes": True, "evidence": str(path),
                })
                self.write_report()
                self.emit(f"PASS {cluster}/{stage}: all {len(tables)} Cilium agents match {len(api_uids)} live Kubernetes namespace UIDs")
                return check
            time.sleep(1)
        raise RuntimeError(f"{cluster}/{stage}: namespace UID tables failed to converge within {timeout}s; last={last_diff}")

    def pods_absent(self, cluster, stage):
        pods = self.get_json(cluster, "-n", NAMESPACE, "get", "pods").get("items", [])
        require(not pods, f"{cluster}/{stage}: expected no Pods in task-owned namespace, found {[p.get('metadata', {}).get('name') for p in pods]}")
        self.report["clusters"][cluster].setdefault("podAbsenceChecks", []).append({
            "stage": stage, "count": 0, "observedAt": self.now(),
        })
        self.write_report()

    def create_namespace(self, cluster, incarnation):
        manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": NAMESPACE,
                "labels": {"app.kubernetes.io/managed-by": "cmtc-namespace-uid-qualification"},
                "annotations": {OWNER_ANNOTATION: self.run_id},
            },
        }
        result = self.kubectl(
            cluster, "create", "-f", "-", "-o", "json", input_text=json.dumps(manifest),
            check=False, label="create-owned-namespace",
        )
        if result.returncode:
            # Resolve an uncertain create only if the exact unique run annotation is present.
            current = self.get_namespace_json(cluster)
            if not current or current.get("metadata", {}).get("annotations", {}).get(OWNER_ANNOTATION) != self.run_id:
                raise RuntimeError(f"{cluster}: namespace create failed and the existing object is not owned by this run: {result.stderr[-1000:]}")
        else:
            current = json.loads(result.stdout)
        metadata = current.get("metadata", {})
        uid = metadata.get("uid")
        resource_version = metadata.get("resourceVersion")
        require(uid and resource_version, f"{cluster}: API did not return Namespace UID/resourceVersion")
        require(metadata.get("name") == NAMESPACE, f"{cluster}: API created an unexpected namespace")
        require(metadata.get("annotations", {}).get(OWNER_ANNOTATION) == self.run_id,
                f"{cluster}: namespace ownership annotation mismatch")
        if incarnation == "A":
            require(self.owned[cluster] is None, f"{cluster}: internal ownership state already set")
        else:
            previous = self.report["clusters"][cluster]["uidTransition"].get("uidA")
            require(previous and uid != previous, f"{cluster}: recreated namespace UID did not change ({previous} -> {uid})")
        self.owned[cluster] = {"uid": uid, "ownerRunID": self.run_id}
        transition = self.report["clusters"][cluster]["uidTransition"]
        transition["uid" + incarnation] = uid
        transition["resourceVersion" + incarnation + "AtCreate"] = resource_version
        transition["createdAt" + incarnation] = self.now()
        self.report["clusters"][cluster]["uidTransition"] = transition
        self.write_report()
        self.pods_absent(cluster, "created-" + incarnation)
        return uid

    def wait_namespace_absent(self, cluster, expected_uid, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.get_namespace_json(cluster)
            if current is None:
                return
            metadata = current.get("metadata", {})
            require(metadata.get("uid") == expected_uid,
                    f"{cluster}: different namespace incarnation appeared during deletion: {metadata.get('uid')}")
            require(metadata.get("annotations", {}).get(OWNER_ANNOTATION) == self.run_id,
                    f"{cluster}: namespace ownership changed while waiting for deletion")
            time.sleep(1)
        raise RuntimeError(f"{cluster}: namespace UID {expected_uid} was not deleted within {timeout}s")

    def delete_owned_namespace(self, cluster, expected_uid, stage):
        uri = "/api/v1/namespaces/" + NAMESPACE
        for attempt in range(3):
            current = self.get_namespace_json(cluster)
            if current is None:
                self.owned[cluster] = None
                return
            metadata = current.get("metadata", {})
            require(metadata.get("uid") == expected_uid,
                    f"{cluster}/{stage}: cleanup refuses changed namespace UID {metadata.get('uid')!r}")
            require(metadata.get("annotations", {}).get(OWNER_ANNOTATION) == self.run_id,
                    f"{cluster}/{stage}: cleanup refuses changed namespace ownership")
            self.pods_absent(cluster, stage + "-before-delete")
            resource_version = metadata.get("resourceVersion")
            require(resource_version, f"{cluster}/{stage}: Namespace resourceVersion is missing")
            options = {
                "apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
                "preconditions": {"uid": expected_uid, "resourceVersion": resource_version},
            }
            result = self.kubectl(
                cluster, "delete", "--raw", uri, "-f", "-", input_text=json.dumps(options),
                check=False, label="delete-owned-namespace-with-preconditions",
            )
            if result.returncode:
                if "Conflict" in result.stderr and attempt < 2:
                    continue
                raise RuntimeError(f"{cluster}/{stage}: conditional namespace delete failed: {result.stderr[-1200:]}")
            self.wait_namespace_absent(cluster, expected_uid)
            self.owned[cluster] = None
            self.report["clusters"][cluster]["uidTransition"]["deletedUID" + stage] = expected_uid
            self.report["clusters"][cluster]["uidTransition"]["deleteResourceVersion" + stage] = resource_version
            self.write_report()
            self.emit(f"PASS {cluster}/{stage}: deleted owned namespace UID={expected_uid} with UID+resourceVersion preconditions")
            return
        raise RuntimeError(f"{cluster}/{stage}: namespace deletion conflicted three times")

    def preflight_absent_and_baseline(self):
        for cluster in CLUSTERS:
            existing = self.get_namespace_json(cluster)
            require(existing is None,
                    f"{cluster}: refusing to reuse pre-existing namespace {NAMESPACE}; no objects were changed")
            self.report["clusters"][cluster]["namespaceUIDChecks"] = []
        for cluster in CLUSTERS:
            self.wait_for_namespace_convergence(cluster, "baseline")
        self.emit(f"PASS preflight: {NAMESPACE} is absent from both existing mesh clusters; no Pods or namespaces were changed")

    def qualify(self):
        self.check_test_suite_idle()
        self.check_local_build()
        self.check_contexts_and_image()
        self.preflight_absent_and_baseline()

        # Create incarnation A in each cluster and wait for all four local Cilium agents.
        for cluster in CLUSTERS:
            self.create_namespace(cluster, "A")
        for cluster in CLUSTERS:
            uid_a = self.report["clusters"][cluster]["uidTransition"]["uidA"]
            self.wait_for_namespace_convergence(cluster, "created-A", expected_fixture_uid=uid_a)
            self.pods_absent(cluster, "created-A-converged")

        # Delete incarnation A with current UID and resourceVersion preconditions.
        for cluster in CLUSTERS:
            uid_a = self.report["clusters"][cluster]["uidTransition"]["uidA"]
            self.delete_owned_namespace(cluster, uid_a, "A")
        for cluster in CLUSTERS:
            self.wait_for_namespace_convergence(cluster, "deleted-A", fixture_absent=True)

        # Recreate the same namespace name, require a new UID B, and verify it in both agents.
        for cluster in CLUSTERS:
            self.create_namespace(cluster, "B")
        for cluster in CLUSTERS:
            uid_a = self.report["clusters"][cluster]["uidTransition"]["uidA"]
            uid_b = self.report["clusters"][cluster]["uidTransition"]["uidB"]
            require(uid_a != uid_b, f"{cluster}: Namespace UID did not change after delete/recreate")
            check = self.wait_for_namespace_convergence(cluster, "recreated-B", expected_fixture_uid=uid_b)
            for table in check["agentTables"]:
                require(table["namespaceUIDs"].get(NAMESPACE) == uid_b,
                        f"{cluster}/{table['node']}: agent did not observe recreated UID B")
            self.pods_absent(cluster, "recreated-B-converged")
            self.emit(f"PASS {cluster}: same name transitioned UID A={uid_a} -> UID B={uid_b} on both agents; Pods=0")

        # Clean up only this run's UID B. Preconditions bind the delete to its latest resourceVersion.
        for cluster in CLUSTERS:
            uid_b = self.report["clusters"][cluster]["uidTransition"]["uidB"]
            self.delete_owned_namespace(cluster, uid_b, "B-cleanup")
        for cluster in CLUSTERS:
            self.wait_for_namespace_convergence(cluster, "cleaned-B", fixture_absent=True)
            self.report["clusters"][cluster]["passed"] = True
        self.report["completedAt"] = self.now()
        self.report["status"] = "passed"
        self.report["qualification"] = {
            "allFourCiliumAgentsExactImageAndBinary": True,
            "namespaceTableJSONContainsUID": True,
            "allNamespaceUIDsComparedWithKubernetesAPI": True,
            "deleteRecreateChangesUIDOnBothAgentsInBothClusters": True,
            "podsCreated": 0,
            "ztunnelEnabled": False,
            "compatibilityGuardChanged": False,
        }
        self.write_report()
        self.emit("PASS qualification: namespace UID propagation/recreation verified across all four Cilium agents; no Pods created")

    def cleanup_owned(self):
        for cluster in reversed(CLUSTERS):
            owned = self.owned.get(cluster)
            if not owned:
                # Recover an uncertain create only if the exact run owner token exists.
                try:
                    current = self.get_namespace_json(cluster)
                    if current is None:
                        continue
                    metadata = current.get("metadata", {})
                    if metadata.get("annotations", {}).get(OWNER_ANNOTATION) != self.run_id:
                        continue
                    owned = {"uid": metadata.get("uid"), "ownerRunID": self.run_id}
                    self.owned[cluster] = owned
                except Exception as error:  # evidence cleanup failure, do not mask primary result
                    self.report["cleanupErrors"].append(f"{cluster}: unable to inspect possible owned namespace: {error}")
                    continue
            try:
                current = self.get_namespace_json(cluster)
                if current is None:
                    self.owned[cluster] = None
                    continue
                metadata = current.get("metadata", {})
                require(metadata.get("uid") == owned["uid"], f"{cluster}: cleanup refused changed UID")
                require(metadata.get("annotations", {}).get(OWNER_ANNOTATION) == self.run_id,
                        f"{cluster}: cleanup refused namespace without this run's owner token")
                self.delete_owned_namespace(cluster, owned["uid"], "finally-cleanup")
                self.wait_for_namespace_convergence(cluster, "finally-cleaned", fixture_absent=True)
            except Exception as error:  # never delete a foreign incarnation or hide cleanup failure
                self.report["cleanupErrors"].append(f"{cluster}: {error}")
        if self.report["cleanupErrors"]:
            self.report["status"] = "failed-cleanup"
        self.write_report()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True, help="Kubeconfig containing kind-cmtc-a and kind-cmtc-b")
    parser.add_argument("--cilium-source", default=str(ROOT), help="Clean local Cilium fork used to build the image")
    parser.add_argument("--image", default=EXPECTED_IMAGE)
    parser.add_argument("--image-id", default=EXPECTED_CONFIG_ID, help="Expected local image config ID (with or without sha256:)")
    parser.add_argument("--image-metadata", default=str(ARTIFACTS / "cilium-image.json"),
                        help="Podman image-inspect JSON produced by the local build")
    parser.add_argument("--reference-snapshot", default=str(ARTIFACTS / "namespaces-a.json"),
                        help="Existing db/show namespace JSON stream; used only to validate the stream format")
    parser.add_argument("--namespace", default=NAMESPACE, help="Dedicated disposable namespace name")
    parser.add_argument("--out", help="Fresh evidence directory; defaults to evidence/<run-id>")
    args = parser.parse_args()
    require(args.image == EXPECTED_IMAGE, f"this qualification requires the pinned local image tag {EXPECTED_IMAGE}")
    require(normalized_config_id(args.image_id) == EXPECTED_CONFIG_ID,
            f"this qualification requires local image config ID {EXPECTED_CONFIG_ID}")
    require(args.namespace == NAMESPACE, f"this qualification is scoped to {NAMESPACE}")
    args.kubeconfig = Path(args.kubeconfig).expanduser().resolve()
    require(args.kubeconfig.is_file(), f"kubeconfig does not exist: {args.kubeconfig}")
    return args


def main():
    args = parse_args()
    qualification = Qualification(args)
    error = None
    try:
        qualification.qualify()
    except Exception as caught:
        error = caught
        qualification.report["status"] = "failed"
        qualification.report["failure"] = {"type": type(caught).__name__, "message": str(caught), "at": qualification.now()}
        qualification.write_report()
        qualification.emit(f"FAIL qualification: {caught}")
    finally:
        qualification.cleanup_owned()
        qualification.report["finishedAt"] = qualification.now()
        if error and qualification.report["status"] == "passed":
            qualification.report["status"] = "failed"
        qualification.write_report()
    print(f"Evidence: {qualification.out}", flush=True)
    if error or qualification.report.get("cleanupErrors"):
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FATAL: {error}", file=sys.stderr)
        raise SystemExit(2)
