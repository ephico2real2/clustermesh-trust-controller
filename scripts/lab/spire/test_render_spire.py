#!/usr/bin/env python3
"""Parsed assertions for the standalone SPIRE renderer."""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import textwrap
import unittest
from pathlib import Path

import render_spire as spire

ROOT = Path(__file__).resolve().parent
SERVER_IMAGE = "ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384"
AGENT_IMAGE = "ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481"
BUSYBOX_IMAGE = "docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
LOG_LINE = re.compile(
    r"^stage=\S+ attempt=\d+ elapsed=\d+ deadline=\d+ backoff=\d+ error=.*$"
)
ENTRY_ID = "11111111-1111-1111-1111-111111111111"
OTHER_ID = "22222222-2222-2222-2222-222222222222"


def hcl_strings(text, key):
    return re.findall(
        rf'(?m)^[ \t]*{re.escape(key)}[ \t]*=[ \t]*"([^"]*)"',
        text,
    )


def one(docs, kind, name):
    found = [
        doc
        for doc in docs
        if doc["kind"] == kind and doc["metadata"]["name"] == name
    ]
    if len(found) != 1:
        raise AssertionError((kind, name, len(found)))
    return found[0]


def pod(workload):
    return workload["spec"]["template"]["spec"]


def container(workload, name):
    spec = pod(workload)
    found = [
        item
        for item in spec.get("containers", []) + spec.get("initContainers", [])
        if item["name"] == name
    ]
    if len(found) != 1:
        raise AssertionError(name)
    return found[0]


def volume(workload, name):
    found = [item for item in pod(workload)["volumes"] if item["name"] == name]
    if len(found) != 1:
        raise AssertionError(name)
    return found[0]


def script_of(docs):
    return one(docs, "ConfigMap", "spire-helpers")["data"]["register-agent-node.sh"]


def wait_of(docs):
    return one(docs, "ConfigMap", "spire-helpers")["data"]["wait-for-server.sh"]


def entry_text(domain, entry_id=ENTRY_ID, sa_selector="k8s_psat:agent_sa:spire-agent"):
    return "\n".join(
        [
            "Found 1 entry",
            "Entry ID         : " + entry_id,
            "SPIFFE ID        : spiffe://" + domain + "/ns/cilium-spire/sa/spire-agent",
            "Parent ID        : spiffe://" + domain + "/spire/server",
            "Selector         : k8s_psat:agent_ns:cilium-spire",
            "Selector         : " + sa_selector,
            "",
        ]
    )


def write_executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_shell(script_text, env, timeout):
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        path = directory / "script.sh"
        path.write_text(script_text)
        completed = subprocess.run(
            ["/bin/sh", str(path)],
            env=env,
            cwd=directory,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return completed


class ManifestTests(unittest.TestCase):
    def test_both_clusters_parse_and_stay_separate(self):
        rendered = {cluster: spire.render(cluster) for cluster in ("cmtc-a", "cmtc-b")}
        self.assertEqual(rendered["cmtc-a"], spire.render("cmtc-a"))
        roles = set()
        for cluster, domain in spire.CLUSTERS.items():
            docs = rendered[cluster]
            self.check_cluster(docs, cluster, domain)
            for doc in docs:
                if doc["kind"] == "ClusterRole":
                    roles.add(doc["metadata"]["name"])
        self.assertEqual(
            roles,
            {
                "cmtc-lab-spire-server-cmtc-a",
                "cmtc-lab-spire-agent-cmtc-a",
                "cmtc-lab-spire-server-cmtc-b",
                "cmtc-lab-spire-agent-cmtc-b",
            },
        )
        blob_a = json.dumps(rendered["cmtc-a"])
        blob_b = json.dumps(rendered["cmtc-b"])
        self.assertNotIn("cmtc-b.mesh.example", blob_a)
        self.assertNotIn("cmtc-a.mesh.example", blob_b)

    def check_cluster(self, docs, cluster, domain):
        self.assertEqual(len(docs), 18)
        identities = [
            (doc["apiVersion"], doc["kind"], doc["metadata"]["name"]) for doc in docs
        ]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertCountEqual(
            identities,
            [
                ("v1", "Namespace", "cilium-spire"),
                ("v1", "ServiceAccount", "spire-server"),
                ("v1", "ServiceAccount", "spire-agent"),
                ("v1", "ConfigMap", "spire-server"),
                ("v1", "ConfigMap", "spire-agent"),
                ("v1", "ConfigMap", "spire-bundle"),
                ("v1", "ConfigMap", "spire-helpers"),
                ("rbac.authorization.k8s.io/v1", "Role", "spire-server"),
                ("rbac.authorization.k8s.io/v1", "Role", "spire-upstreamauthority"),
                ("rbac.authorization.k8s.io/v1", "RoleBinding", "spire-server"),
                ("rbac.authorization.k8s.io/v1", "RoleBinding", "spire-upstreamauthority"),
                ("rbac.authorization.k8s.io/v1", "ClusterRole", "cmtc-lab-spire-server-" + cluster),
                ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "cmtc-lab-spire-server-" + cluster),
                ("rbac.authorization.k8s.io/v1", "ClusterRole", "cmtc-lab-spire-agent-" + cluster),
                ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "cmtc-lab-spire-agent-" + cluster),
                ("v1", "Service", "spire-server"),
                ("apps/v1", "StatefulSet", "spire-server"),
                ("apps/v1", "DaemonSet", "spire-agent"),
            ],
        )
        self.assert_labels(docs, cluster)
        self.assert_config(docs, cluster, domain)
        self.assert_rbac(docs, cluster)
        self.assert_server(docs, cluster, domain)
        self.assert_agent(docs, cluster, domain)
        self.assert_absent(docs, domain)

    def assert_labels(self, docs, cluster):
        expected_roles = {
            ("Namespace", "cilium-spire"): "namespace",
            ("ServiceAccount", "spire-server"): "spire-server-account",
            ("ServiceAccount", "spire-agent"): "spire-agent-account",
            ("ConfigMap", "spire-server"): "spire-server-config",
            ("ConfigMap", "spire-agent"): "spire-agent-config",
            ("ConfigMap", "spire-bundle"): "spire-bundle",
            ("ConfigMap", "spire-helpers"): "spire-helper",
            ("Role", "spire-server"): "spire-server-role",
            ("Role", "spire-upstreamauthority"): "spire-upstream-role",
            ("RoleBinding", "spire-server"): "spire-server-binding",
            ("RoleBinding", "spire-upstreamauthority"): "spire-upstream-binding",
            ("ClusterRole", "cmtc-lab-spire-server-" + cluster): "spire-server-clusterrole",
            ("ClusterRoleBinding", "cmtc-lab-spire-server-" + cluster): "spire-server-clusterbinding",
            ("ClusterRole", "cmtc-lab-spire-agent-" + cluster): "spire-agent-clusterrole",
            ("ClusterRoleBinding", "cmtc-lab-spire-agent-" + cluster): "spire-agent-clusterbinding",
            ("Service", "spire-server"): "spire-server-service",
            ("StatefulSet", "spire-server"): "spire-server",
            ("DaemonSet", "spire-agent"): "spire-agent",
        }
        for doc in docs:
            key = (doc["kind"], doc["metadata"]["name"])
            self.assertEqual(
                doc["metadata"]["labels"],
                {
                    "security.cmtc.io/pki-owner": "cmtc-lab-pki",
                    "security.cmtc.io/pki-cluster": cluster,
                    "security.cmtc.io/pki-role": expected_roles[key],
                    **({"app": doc["metadata"]["labels"]["app"]} if "app" in doc["metadata"]["labels"] else {}),
                    **({"trust": "enabled"} if doc["kind"] == "Namespace" else {}),
                },
            )
            if doc["kind"] in {"Namespace", "ClusterRole", "ClusterRoleBinding"}:
                self.assertNotIn("namespace", doc["metadata"])
            else:
                self.assertEqual(doc["metadata"]["namespace"], "cilium-spire")

    def assert_config(self, docs, cluster, domain):
        server = one(docs, "ConfigMap", "spire-server")["data"]["server.conf"]
        agent = one(docs, "ConfigMap", "spire-agent")["data"]["agent.conf"]
        self.assertEqual(hcl_strings(server, "trust_domain"), [domain])
        self.assertEqual(hcl_strings(server, "common_name"), [cluster + " SPIRE CA"])
        self.assertEqual(hcl_strings(server, "ca_key_type"), ["rsa-4096"])
        self.assertEqual(hcl_strings(server, "socket_path"), ["/tmp/spire-server/private/api.sock"])
        self.assertEqual(hcl_strings(server, "connection_string"), ["/run/spire/data/datastore.sqlite3"])
        self.assertEqual(hcl_strings(server, "keys_path"), ["/run/spire/data/keys.json"])
        self.assertEqual(hcl_strings(server, "data_dir"), ["/run/spire/data"])
        self.assertEqual(hcl_strings(server, "issuer_name"), [cluster + "-spire-intermediate"])
        self.assertEqual(hcl_strings(server, "issuer_kind"), ["ClusterIssuer"])
        self.assertEqual(hcl_strings(server, "issuer_group"), ["cert-manager.io"])
        self.assertEqual(hcl_strings(server, "namespace"), ["cilium-spire", "cilium-spire"])
        self.assertEqual(hcl_strings(server, "live_path"), ["/live"])
        self.assertEqual(hcl_strings(server, "ready_path"), ["/ready"])
        self.assertEqual(hcl_strings(server, "bind_port"), ["8081", "8080"])
        self.assertEqual(server.count('UpstreamAuthority "cert-manager"'), 1)
        self.assertEqual(server.count('DataStore "sql"'), 1)
        self.assertEqual(server.count('KeyManager "disk"'), 1)
        self.assertIn('use_token_review_api_validation = true', server)
        self.assertIn(
            '"' + cluster + '" = {\n          use_token_review_api_validation = true',
            server,
        )
        self.assertNotIn('"' + domain + '" = {', server)
        self.assertIn('service_account_allow_list = ["cilium-spire:spire-agent"]', server)
        for absent in ("pathLen", "pathlen", "max_path_len", "admin_ids"):
            self.assertNotIn(absent, server)

        self.assertEqual(hcl_strings(agent, "trust_domain"), [domain])
        self.assertEqual(hcl_strings(agent, "cluster"), [cluster])
        self.assertNotEqual(cluster, domain)
        self.assertEqual(hcl_strings(agent, "token_path"), ["/var/run/secrets/tokens/spire-agent"])
        self.assertEqual(hcl_strings(agent, "server_address"), ["spire-server.cilium-spire.svc"])
        self.assertEqual(hcl_strings(agent, "server_port"), ["8081"])
        self.assertEqual(hcl_strings(agent, "socket_path"), ["/run/spire/sockets/agent/agent.sock"])
        self.assertEqual(hcl_strings(agent, "bind_port"), ["4251"])
        self.assertEqual(hcl_strings(agent, "live_path"), ["/live"])
        self.assertEqual(hcl_strings(agent, "ready_path"), ["/ready"])
        self.assertIn("skip_kubelet_verification = true", agent)
        self.assertNotIn("skip_kubelet_verification = false", agent)
        self.assertNotIn("admin_socket_path", agent)
        self.assertNotIn("authorized_delegates", agent)
        self.assertEqual(agent.count('WorkloadAttestor "k8s"'), 1)
        self.assertEqual(agent.count('KeyManager "memory"'), 1)

    def assert_rbac(self, docs, cluster):
        bundle = one(docs, "Role", "spire-server")["rules"]
        self.assertEqual(
            bundle,
            [
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "resourceNames": ["spire-bundle"],
                    "verbs": ["get", "patch"],
                }
            ],
        )
        upstream = one(docs, "Role", "spire-upstreamauthority")["rules"]
        self.assertEqual(
            upstream,
            [
                {
                    "apiGroups": ["cert-manager.io"],
                    "resources": ["certificaterequests"],
                    "verbs": ["create", "get", "list", "watch", "delete"],
                }
            ],
        )
        server_role = one(docs, "ClusterRole", "cmtc-lab-spire-server-" + cluster)
        self.assertEqual(
            server_role["rules"],
            [
                {
                    "apiGroups": ["authentication.k8s.io"],
                    "resources": ["tokenreviews"],
                    "verbs": ["create"],
                },
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["nodes", "nodes/proxy"], "verbs": ["get"]},
            ],
        )
        agent_role = one(docs, "ClusterRole", "cmtc-lab-spire-agent-" + cluster)
        self.assertEqual(
            agent_role["rules"],
            [
                {
                    "apiGroups": [""],
                    "resources": ["pods", "nodes", "nodes/proxy"],
                    "verbs": ["get"],
                }
            ],
        )
        for kind, name, role_name, subject in (
            ("RoleBinding", "spire-server", "spire-server", "spire-server"),
            ("RoleBinding", "spire-upstreamauthority", "spire-upstreamauthority", "spire-server"),
            ("ClusterRoleBinding", "cmtc-lab-spire-server-" + cluster, "cmtc-lab-spire-server-" + cluster, "spire-server"),
            ("ClusterRoleBinding", "cmtc-lab-spire-agent-" + cluster, "cmtc-lab-spire-agent-" + cluster, "spire-agent"),
        ):
            body = one(docs, kind, name)
            self.assertEqual(body["roleRef"]["name"], role_name)
            self.assertEqual(
                body["subjects"],
                [{"kind": "ServiceAccount", "name": subject, "namespace": "cilium-spire"}],
            )
        verbs = []
        for doc in docs:
            for rule in doc.get("rules", []):
                verbs.extend(rule["verbs"])
                self.assertNotIn("*", rule["verbs"])
                self.assertNotIn("secrets", rule["resources"])
        self.assertNotIn("approve", verbs)
        self.assertNotIn("*", verbs)

    def assert_server(self, docs, cluster, domain):
        sts = one(docs, "StatefulSet", "spire-server")
        self.assertEqual(sts["spec"]["replicas"], 1)
        self.assertEqual(sts["spec"]["serviceName"], "spire-server")
        self.assertEqual(sts["spec"]["selector"], {"matchLabels": {"app": "spire-server"}})
        spec = pod(sts)
        self.assertEqual(spec["serviceAccountName"], "spire-server")
        self.assertEqual(spec["priorityClassName"], "system-node-critical")
        self.assertIs(spec["hostUsers"], True)
        self.assertEqual(
            spec["securityContext"],
            {
                "runAsUser": 1000,
                "runAsGroup": 1000,
                "fsGroup": 1000,
                "fsGroupChangePolicy": "OnRootMismatch",
                "runAsNonRoot": True,
            },
        )
        self.assertNotIn("hostPID", spec)
        self.assertNotIn("hostNetwork", spec)
        # Kept private on purpose (#41): with a shared namespace the busybox sidecar, uid 1000 like the
        # server, could read the server's filesystem (the datastore and its keys) through
        # /proc/<pid>/root. The sidecar's own PID 1 reaps instead (ReapingTests).
        self.assertNotIn("shareProcessNamespace", spec)
        self.assertEqual(
            sts["spec"]["template"]["metadata"]["labels"],
            {
                "security.cmtc.io/pki-owner": "cmtc-lab-pki",
                "security.cmtc.io/pki-cluster": cluster,
                "security.cmtc.io/pki-role": "spire-server",
                "app": "spire-server",
            },
        )
        server = container(sts, "spire-server")
        self.assertEqual(server["image"], SERVER_IMAGE)
        self.assertEqual(server["imagePullPolicy"], "IfNotPresent")
        self.assertEqual(server["args"], ["-config", "/run/spire/config/server.conf"])
        self.assertEqual(server["ports"][0]["containerPort"], 8081)
        self.assertEqual(server["ports"][1]["name"], "http")
        self.assertEqual(server["ports"][1]["containerPort"], 8080)
        self.assertEqual(server["startupProbe"]["httpGet"], {"path": "/live", "port": "http"})
        self.assertEqual(server["startupProbe"]["failureThreshold"], 30)
        self.assertEqual(server["startupProbe"]["periodSeconds"], 5)
        self.assertEqual(server["livenessProbe"]["httpGet"]["path"], "/live")
        self.assertEqual(server["livenessProbe"]["failureThreshold"], 2)
        self.assertEqual(server["livenessProbe"]["initialDelaySeconds"], 15)
        self.assertEqual(server["livenessProbe"]["periodSeconds"], 60)
        self.assertEqual(server["livenessProbe"]["timeoutSeconds"], 3)
        self.assertEqual(server["readinessProbe"]["httpGet"], {"path": "/ready", "port": "http"})
        self.assertEqual(server["readinessProbe"]["initialDelaySeconds"], 5)
        self.assertEqual(server["readinessProbe"]["periodSeconds"], 5)
        mounts = {item["name"]: item for item in server["volumeMounts"]}
        self.assertEqual(mounts["spire-data"]["mountPath"], "/run/spire/data")
        self.assertIs(mounts["spire-data"].get("readOnly", False), False)
        self.assertEqual(mounts["spire-server-socket"]["mountPath"], "/tmp/spire-server/private")
        claim = sts["spec"]["volumeClaimTemplates"][0]
        self.assertEqual(
            claim["metadata"]["labels"],
            {
                "security.cmtc.io/pki-owner": "cmtc-lab-pki",
                "security.cmtc.io/pki-cluster": cluster,
                "security.cmtc.io/pki-role": "spire-data",
            },
        )
        self.assertNotIn("namespace", claim["metadata"])
        self.assertEqual(claim["spec"]["storageClassName"], "standard")
        self.assertEqual(claim["spec"]["accessModes"], ["ReadWriteOnce"])
        self.assertEqual(claim["spec"]["resources"]["requests"]["storage"], "1Gi")
        self.assertNotIn("emptyDir", claim["spec"])
        self.assertNotIn("spire-data", {item["name"] for item in spec["volumes"]})
        socket = volume(sts, "spire-server-socket")
        self.assertEqual(socket, {"name": "spire-server-socket", "emptyDir": {}})
        cli = volume(sts, "spire-server-cli")
        self.assertEqual(cli["image"]["reference"], SERVER_IMAGE)
        self.assertEqual(cli["image"]["pullPolicy"], "IfNotPresent")
        helper = container(sts, "register-agent-node")
        self.assertEqual(helper["image"], BUSYBOX_IMAGE)
        self.assertEqual(helper["command"], ["/bin/sh", "/opt/cmtc/register-agent-node.sh"])
        env = {item["name"]: item["value"] for item in helper["env"]}
        self.assertEqual(env["SPIRE_SERVER_BIN"], "/spire-cli/opt/spire/bin/spire-server")
        self.assertEqual(env["SPIRE_SOCKET"], "/tmp/spire-server/private/api.sock")
        self.assertEqual(env["SPIRE_DEADLINE"], "90")
        self.assertEqual(env["SPIRE_MAX_ATTEMPTS"], "8")
        self.assertEqual(env["SPIRE_BACKOFF_START"], "1")
        self.assertEqual(env["SPIRE_BACKOFF_CAP"], "8")
        self.assertEqual(env["SPIRE_HOLD"], "1")
        self.assertEqual(
            {item["name"] for item in helper["volumeMounts"]},
            {"spire-helpers", "spire-server-socket", "spire-server-cli", "spire-registration"},
        )
        script = script_of(docs)
        agent_id = "spiffe://" + domain + "/ns/cilium-spire/sa/spire-agent"
        self.assertIn("id='" + agent_id + "'", script)
        self.assertIn("sel_ns='k8s_psat:agent_ns:cilium-spire'", script)
        self.assertIn("sel_sa='k8s_psat:agent_sa:spire-agent'", script)
        self.assertEqual(script.count("entry create"), 1)
        self.assertIn("-node", script)
        self.assertNotIn("-parentID", script)
        self.assertIn('while [ "$attempt" -lt "$max_attempts" ]', script)
        self.assertNotIn("while true", script)
        self.assertNotIn("grep", script)
        self.assertNotIn("/proc", script)
        service = one(docs, "Service", "spire-server")
        self.assertEqual(service["spec"]["ports"], [
            {"name": "grpc", "port": 8081, "targetPort": "grpc", "protocol": "TCP"}
        ])
        self.assertIsInstance(service["spec"]["ports"][0]["port"], int)

    def assert_agent(self, docs, cluster, domain):
        ds = one(docs, "DaemonSet", "spire-agent")
        self.assertNotIn("replicas", ds["spec"])
        self.assertEqual(ds["spec"]["selector"], {"matchLabels": {"app": "spire-agent"}})
        spec = pod(ds)
        self.assertEqual(spec["serviceAccountName"], "spire-agent")
        self.assertEqual(spec["priorityClassName"], "system-node-critical")
        self.assertIs(spec["hostUsers"], True)
        self.assertIs(spec["hostPID"], True)
        self.assertIs(spec["hostNetwork"], True)
        self.assertEqual(spec["dnsPolicy"], "ClusterFirstWithHostNet")
        self.assertNotIn("nodeSelector", spec)
        self.assertNotIn("nodeName", spec)
        self.assertEqual(spec["securityContext"]["runAsUser"], 1000)
        self.assertEqual(spec["securityContext"]["fsGroup"], 1000)
        self.assertEqual(
            spec["tolerations"],
            [
                {"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule"},
                {"key": "node-role.kubernetes.io/master", "effect": "NoSchedule"},
                {"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"},
                {
                    "key": "node.cloudprovider.kubernetes.io/uninitialized",
                    "effect": "NoSchedule",
                    "value": "true",
                },
                {"key": "CriticalAddonsOnly", "operator": "Exists"},
                {"key": "node.cilium.io/agent-not-ready", "effect": "NoSchedule"},
            ],
        )
        self.assertEqual(
            ds["spec"]["template"]["metadata"]["labels"]["security.cmtc.io/pki-owner"],
            "cmtc-lab-pki",
        )
        self.assertEqual(
            ds["spec"]["template"]["metadata"]["labels"]["security.cmtc.io/pki-cluster"],
            cluster,
        )
        agent = container(ds, "spire-agent")
        self.assertEqual(agent["image"], AGENT_IMAGE)
        self.assertEqual(agent["imagePullPolicy"], "IfNotPresent")
        self.assertEqual(agent["ports"], [{"name": "http", "containerPort": 4251, "protocol": "TCP"}])
        self.assertIsInstance(agent["ports"][0]["containerPort"], int)
        self.assertEqual(agent["startupProbe"]["httpGet"], {"path": "/live", "port": "http"})
        self.assertEqual(agent["livenessProbe"]["httpGet"], {"path": "/live", "port": "http"})
        self.assertEqual(agent["readinessProbe"]["httpGet"], {"path": "/ready", "port": "http"})
        self.assertEqual(agent["readinessProbe"]["initialDelaySeconds"], 5)
        self.assertEqual(agent["readinessProbe"]["periodSeconds"], 5)
        self.assertEqual(agent["livenessProbe"]["failureThreshold"], 2)
        token = volume(ds, "spire-token")["projected"]["sources"][0]["serviceAccountToken"]
        self.assertEqual(token["path"], "spire-agent")
        self.assertEqual(token["audience"], "spire-server")
        self.assertEqual(token["expirationSeconds"], 600)
        self.assertIsInstance(token["expirationSeconds"], int)
        token_mount = next(item for item in agent["volumeMounts"] if item["name"] == "spire-token")
        self.assertEqual(token_mount["mountPath"], "/var/run/secrets/tokens")
        self.assertIs(token_mount["readOnly"], True)
        socket = volume(ds, "spire-agent-socket")
        self.assertEqual(socket, {"name": "spire-agent-socket", "emptyDir": {}})
        account = one(docs, "ServiceAccount", "spire-agent")
        self.assertEqual(account["metadata"]["namespace"], "cilium-spire")
        waiter = container(ds, "wait-for-server")
        self.assertEqual(waiter["image"], BUSYBOX_IMAGE)
        env = {item["name"]: item["value"] for item in waiter["env"]}
        self.assertEqual(env["SPIRE_WAIT_ATTEMPTS"], "60")
        self.assertEqual(env["SPIRE_WAIT_DEADLINE"], "60")
        self.assertEqual(env["SPIRE_WAIT_BACKOFF"], "1")
        self.assertEqual(env["SPIRE_SERVER_HOST"], "spire-server.cilium-spire.svc")
        self.assertEqual(env["SPIRE_SERVER_PORT"], "8081")
        waiting = wait_of(docs)
        self.assertIn('while [ "$attempt" -lt "$max" ]', waiting)
        self.assertNotIn("while true", waiting)
        self.assertIn("spire-server.cilium-spire.svc", waiting)
        self.assertEqual(domain.split(".", 1)[0], cluster)

    def assert_absent(self, docs, domain):
        blob = json.dumps(docs)
        self.assertEqual(blob.count("spiffe://"), 4)
        self.assertEqual(blob.count("spiffe://" + domain + "/ns/cilium-spire/sa/spire-agent"), 1)
        for item in (
            "cluster-intermediate",
            "cmtc-lab-intermediate",
            "cmtc-mtls",
            "clustermesh-apiserver",
            "cilium-agent",
            "cilium-operator",
            "ztunnel",
            "Protected",
            "experimental",
            "requireMtls",
            "workload-registrar",
            "hostPath",
            "pgrep",
            "/proc/",
            "while true",
            "enable-ipsec",
            "enable-wireguard",
            "enable-ztunnel",
            "cmtc-spire-cluster-ca",
        ):
            self.assertNotIn(item, blob)
        kinds = {doc["kind"] for doc in docs}
        self.assertTrue(
            kinds.isdisjoint(
                {"Secret", "ClusterIssuer", "StorageClass", "Certificate", "CertificateRequest", "Job"}
            )
        )
        empty_dirs = []
        for doc in docs:
            for item in pod(doc)["volumes"] if doc["kind"] in {"StatefulSet", "DaemonSet"} else []:
                if "emptyDir" in item:
                    empty_dirs.append(item["name"])
        self.assertEqual(sorted(empty_dirs), ["spire-agent-data", "spire-agent-socket", "spire-registration", "spire-server-socket"])

    def test_mutation_does_not_change_the_next_render(self):
        docs = spire.render("cmtc-a")
        docs[0]["metadata"]["name"] = "changed"
        self.assertEqual(spire.render("cmtc-a")[0]["metadata"]["name"], "cilium-spire")

    def test_issuer_is_the_cluster_intermediate_of_the_cmtc_chart(self):
        # charts/cmtc/templates/trust.yaml names the ClusterIssuer <clusterName>-spire-intermediate.
        expected = {"cmtc-a": "cmtc-a-spire-intermediate", "cmtc-b": "cmtc-b-spire-intermediate"}
        for cluster, issuer in expected.items():
            server = one(spire.render(cluster), "ConfigMap", "spire-server")["data"]["server.conf"]
            self.assertEqual(hcl_strings(server, "issuer_name"), [issuer])


class RefusalTests(unittest.TestCase):
    def test_foreign_cluster_domain_and_images_are_refused(self):
        pins = dict(spire.PINNED_IMAGES)
        cases = [
            ("cmtc-mtls", None, None),
            ("kind-cmtc-a", None, None),
            ("cmtc-a.mesh.example", None, None),
            ("../cmtc-a", None, None),
            ("", None, None),
            (None, None, None),
            ("cmtc-a", "cmtc-a", None),
            ("cmtc-a", "cmtc-b.mesh.example", None),
            ("cmtc-a", "spiffe://cmtc-a.mesh.example", None),
            ("cmtc-a", "cmtc-a.mesh.example/ns/orders/sa/api", None),
            ("cmtc-b", "cmtc-b", None),
            ("cmtc-a", "cmtc-a.mesh.example.", None),
            ("cmtc-a", None, "busybox:latest"),
            ("cmtc-a", None, {"server": SERVER_IMAGE}),
            (
                "cmtc-a",
                None,
                {
                    "server": "ghcr.io/spiffe/spire-server:1.15.4",
                    "agent": AGENT_IMAGE,
                    "busybox": BUSYBOX_IMAGE,
                },
            ),
            (
                "cmtc-a",
                None,
                {
                    "server": SERVER_IMAGE.replace("584a9c5cc95b9457", "0000000000000000"),
                    "agent": AGENT_IMAGE,
                    "busybox": BUSYBOX_IMAGE,
                },
            ),
            (
                "cmtc-a",
                None,
                {
                    "server": SERVER_IMAGE,
                    "agent": "ghcr.io/spiffe/spire-agent:latest",
                    "busybox": BUSYBOX_IMAGE,
                },
            ),
            (
                "cmtc-a",
                None,
                {
                    "server": SERVER_IMAGE,
                    "agent": AGENT_IMAGE,
                    "busybox": "docker.io/library/busybox:1.36.1",
                },
            ),
            (
                "cmtc-a",
                None,
                {
                    "server": "localhost/cmtc:issuer-7e606195f5",
                    "agent": AGENT_IMAGE,
                    "busybox": BUSYBOX_IMAGE,
                },
            ),
            (
                "cmtc-a",
                None,
                {
                    "server": SERVER_IMAGE,
                    "agent": AGENT_IMAGE,
                    "busybox": BUSYBOX_IMAGE,
                    "extra": BUSYBOX_IMAGE,
                },
            ),
        ]
        for cluster, domain, images in cases:
            with self.subTest(cluster=cluster, domain=domain, images=images):
                with self.assertRaises(spire.Refusal):
                    spire.render(cluster, domain, images)
        self.assertEqual(spire.render("cmtc-a", "cmtc-a.mesh.example", pins)[0]["metadata"]["name"], "cilium-spire")

    def test_renderer_source_has_no_cluster_client(self):
        text = Path(spire.__file__).read_text()
        for word in (
            "import subprocess",
            "import urllib",
            "import requests",
            "import kubernetes",
            "import socket",
            "http.client",
            "kubectl",
        ):
            self.assertNotIn(word, text)


class RegistrationTests(unittest.TestCase):
    def test_registration_confirms_exact_entry_once_per_cluster(self):
        for cluster, domain in spire.CLUSTERS.items():
            with self.subTest(cluster=cluster):
                script = script_of(spire.render(cluster))
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    log = directory / "calls"
                    created = directory / "created"
                    found = directory / "found"
                    found.write_text(entry_text(domain))
                    stub = directory / "spire-server"
                    write_executable(
                        stub,
                        textwrap.dedent(
                            """\
                            #!/bin/sh
                            printf '%s\\n' "$*" >> "$STUB_LOG"
                            case "$1 $2" in
                              "entry create")
                                printf '1\\n' >> "$STUB_CREATED"
                                exit 0
                                ;;
                              "entry show")
                                if printf '%s' "$*" | grep -q -- '-entryID'; then
                                  cat "$STUB_FOUND"
                                  exit 0
                                fi
                                if [ -s "$STUB_CREATED" ]; then
                                  cat "$STUB_FOUND"
                                  exit 0
                                fi
                                printf '%s\\n' 'Found 0 entries'
                                exit 0
                                ;;
                            esac
                            printf 'unexpected %s\\n' "$*" >&2
                            exit 1
                            """
                        ),
                    )
                    env = self.env(directory, stub, log, created, found)
                    first = run_shell(script, env, 5)
                    self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
                    self.assertEqual(first.stderr, "")
                    self.assert_log_lines(first.stdout)
                    self.assertIn("stage=entry-create ", first.stdout)
                    self.assertIn("stage=entry-confirm ", first.stdout)
                    self.assertIn("error=\n", first.stdout)
                    calls = log.read_text()
                    agent_id = "spiffe://" + domain + "/ns/cilium-spire/sa/spire-agent"
                    self.assertEqual(calls.count("entry create"), 1)
                    self.assertIn("-node", calls)
                    self.assertIn("-spiffeID " + agent_id, calls)
                    self.assertIn("-selector k8s_psat:agent_ns:cilium-spire", calls)
                    self.assertIn("-selector k8s_psat:agent_sa:spire-agent", calls)
                    self.assertIn("-entryID " + ENTRY_ID, calls)
                    second = run_shell(script, env, 5)
                    self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
                    self.assertNotIn("stage=entry-create ", second.stdout)
                    self.assertEqual(log.read_text().count("entry create"), 1)

    def test_show_failure_is_bounded_and_logs_retry_fields(self):
        script = script_of(spire.render("cmtc-a"))
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            log = directory / "calls"
            stub = directory / "spire-server"
            write_executable(
                stub,
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOG\"\necho connection refused >&2\nexit 1\n",
            )
            env = self.env(directory, stub, log, directory / "created", directory / "found")
            env["SPIRE_MAX_ATTEMPTS"] = "2"
            env["SPIRE_DEADLINE"] = "30"
            env["SPIRE_BACKOFF_START"] = "1"
            env["SPIRE_BACKOFF_CAP"] = "8"
            completed = run_shell(script, env, 10)
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assert_log_lines(completed.stdout)
            self.assertEqual(completed.stdout.count("stage=entry-show "), 2)
            self.assertIn("error=connection refused", completed.stdout)
            self.assertIn("backoff=1", completed.stdout)
            self.assertIn("backoff=2", completed.stdout)
            self.assertIn("deadline=30", completed.stdout)
            self.assertIn("error=attempt limit", completed.stdout)
            self.assertNotIn("entry create", log.read_text())
            self.assertNotIn("PRIVATE", completed.stdout)

    def test_wrong_selectors_do_not_create(self):
        script = script_of(spire.render("cmtc-a"))
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            log = directory / "calls"
            found = directory / "found"
            found.write_text(entry_text("cmtc-a.mesh.example", sa_selector="k8s_psat:agent_sa:other"))
            stub = directory / "spire-server"
            write_executable(
                stub,
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOG\"\ncat \"$STUB_FOUND\"\nexit 0\n",
            )
            env = self.env(directory, stub, log, directory / "created", found)
            completed = run_shell(script, env, 5)
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertIn("error=selectors do not match", completed.stdout)
            self.assertNotIn("entry create", log.read_text())

    def test_entry_id_query_must_match(self):
        script = script_of(spire.render("cmtc-a"))
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            log = directory / "calls"
            found = directory / "found"
            other = directory / "other"
            found.write_text(entry_text("cmtc-a.mesh.example"))
            other.write_text(entry_text("cmtc-a.mesh.example", entry_id=OTHER_ID))
            stub = directory / "spire-server"
            write_executable(
                stub,
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    printf '%s\\n' "$*" >> "$STUB_LOG"
                    if printf '%s' "$*" | grep -q -- '-entryID'; then
                      cat "$STUB_OTHER"
                      exit 0
                    fi
                    cat "$STUB_FOUND"
                    exit 0
                    """
                ),
            )
            env = self.env(directory, stub, log, directory / "created", found)
            env["STUB_OTHER"] = str(other)
            completed = run_shell(script, env, 5)
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertIn("error=entry id query did not match", completed.stdout)
            self.assertIn("-entryID " + ENTRY_ID, log.read_text())
            self.assertNotIn("entry create", log.read_text())

    def test_wait_script_succeeds_and_stops_at_attempt_limit(self):
        script = wait_of(spire.render("cmtc-b"))
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            nc = directory / "nc"
            write_executable(nc, "#!/bin/sh\nexit 0\n")
            env = {"PATH": str(directory) + ":/bin:/usr/bin", "SPIRE_WAIT_ATTEMPTS": "2"}
            success = run_shell(script, env, 5)
            self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
            self.assert_log_lines(success.stdout)
            self.assertIn("stage=wait-server ", success.stdout)
            self.assertIn("error=\n", success.stdout)
            write_executable(nc, "#!/bin/sh\nexit 1\n")
            env.update(
                {
                    "SPIRE_WAIT_ATTEMPTS": "2",
                    "SPIRE_WAIT_DEADLINE": "30",
                    "SPIRE_WAIT_BACKOFF": "1",
                }
            )
            failure = run_shell(script, env, 10)
            self.assertEqual(failure.returncode, 1, failure.stdout + failure.stderr)
            self.assert_log_lines(failure.stdout)
            self.assertEqual(failure.stdout.count("stage=wait-server "), 3)
            self.assertIn("error=spire server is not reachable", failure.stdout)
            self.assertIn("error=attempt limit", failure.stdout)
            self.assertIn("deadline=30", failure.stdout)
            self.assertIn("backoff=1", failure.stdout)

    def env(self, directory, stub, log, created, found):
        return {
            "PATH": "/opt/homebrew/bin:/bin:/usr/bin",
            "SPIRE_ACK_FILE":str(directory / "ack"),
            "SPIRE_HOLD": "0",
            "SPIRE_SERVER_BIN": str(stub),
            "SPIRE_SOCKET": "/tmp/spire-server/private/api.sock",
            "SPIRE_DEADLINE": "90",
            "SPIRE_MAX_ATTEMPTS": "8",
            "SPIRE_BACKOFF_START": "1",
            "SPIRE_BACKOFF_CAP": "8",
            "STUB_LOG": str(log),
            "STUB_CREATED": str(created),
            "STUB_FOUND": str(found),
        }

    def assert_log_lines(self, text):
        lines = [line for line in text.splitlines() if line]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line, LOG_LINE)


class SecurityRegressionTests(unittest.TestCase):
    def test_real_rbac_schema_and_owned_writable_data(self):
        for cluster in spire.CLUSTERS:
            docs=spire.render(cluster)
            for doc in docs:
                if doc['apiVersion']=='rbac.authorization.k8s.io/v1':
                    self.assertNotIn('spec',doc)
                    if doc['kind'] in ('Role','ClusterRole'):
                        self.assertIsInstance(doc['rules'],list)
                        self.assertTrue(doc['rules'])
                        self.assertFalse(any('secrets' in r['resources'] for r in doc['rules']))
                    else:
                        self.assertIn('roleRef',doc)
                        self.assertEqual(doc['subjects'][0]['namespace'],spire.NAMESPACE)
            agent=one(docs,'DaemonSet','spire-agent')
            mounts={v['name']:v for v in container(agent,'spire-agent')['volumeMounts']}
            self.assertEqual(mounts['spire-agent-data']['mountPath'],'/run/spire/data')
            self.assertIn('emptyDir',volume(agent,'spire-agent-data'))
            self.assertEqual(pod(agent)['securityContext']['fsGroup'],1000)
            sts=one(docs,'StatefulSet','spire-server')
            self.assertEqual(sts['spec']['persistentVolumeClaimRetentionPolicy'],{'whenDeleted':'Retain','whenScaled':'Retain'})
            probe=container(sts,'register-agent-node')['readinessProbe']
            self.assertIn('SPIRE_CHECK_ONLY=1',probe['exec']['command'][-1])
        self.assertFalse(hasattr(spire,'verify_exact_pin'))
        self.assertFalse(hasattr(spire,'select_spire_ca'))
    def test_failure_with_hold_enabled_exits_and_clears_stale_ack(self):
        with tempfile.TemporaryDirectory() as raw:
            d=Path(raw);stub=d/'spire-server';write_executable(stub,'#!/bin/sh\necho unavailable >&2\nexit 1\n')
            env=RegistrationTests().env(d,stub,d/'calls',d/'created',d/'found')
            env.update(SPIRE_HOLD='1',SPIRE_MAX_ATTEMPTS='1')
            (d/'ack').write_text('stale-success')
            result=run_shell(script_of(spire.render('cmtc-a')),env,3)
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            self.assertFalse((d/'ack').exists())
    def test_actual_hanging_cli_is_killed_by_remaining_deadline(self):
        with tempfile.TemporaryDirectory() as raw:
            d=Path(raw);stub=d/'spire-server';write_executable(stub,'#!/bin/sh\nexec sleep 20\n')
            env=RegistrationTests().env(d,stub,d/'calls',d/'created',d/'found')
            env.update(SPIRE_DEADLINE='1',SPIRE_MAX_ATTEMPTS='1')
            start=time.monotonic();result=run_shell(script_of(spire.render('cmtc-a')),env,4)
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            self.assertLess(time.monotonic()-start,3.5)
            self.assertFalse((d/'ack').exists())
    def test_live_readiness_refuses_missing_changed_parent_or_selector(self):
        with tempfile.TemporaryDirectory() as raw:
            d=Path(raw);stub=d/'spire-server';found=d/'found';log=d/'calls'
            write_executable(stub,'#!/bin/sh\nprintf "%s\\n" "$*" >> "$STUB_LOG"\ncat "$STUB_FOUND"\n')
            env=RegistrationTests().env(d,stub,log,d/'created',found)
            script=script_of(spire.render('cmtc-a'))
            good=entry_text('cmtc-a.mesh.example').replace('Found 1 entry','  Found 1 entry')
            found.write_text(good)
            result=run_shell(script,env,3)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            check=dict(env,SPIRE_CHECK_ONLY='1',SPIRE_DEADLINE='2')
            self.assertEqual(run_shell(script,check,3).returncode,0)
            for bad in [good.replace('/spire/server','/not-the-server'),
                        good.replace('k8s_psat:agent_sa:spire-agent','evil:k8s_psat:agent_sa:spire-agent'),
                        good.replace(ENTRY_ID,OTHER_ID),'Found 0 entries\n']:
                found.write_text(bad)
                self.assertEqual(run_shell(script,check,3).returncode,1)
            self.assertNotIn('entry create',log.read_text())
    def test_suffix_selector_forgery_never_receives_startup_ack(self):
        with tempfile.TemporaryDirectory() as raw:
            d=Path(raw);stub=d/'spire-server';found=d/'found'
            write_executable(stub,'#!/bin/sh\ncat "$STUB_FOUND"\n')
            found.write_text(entry_text('cmtc-a.mesh.example',sa_selector='evil:k8s_psat:agent_sa:spire-agent'))
            env=RegistrationTests().env(d,stub,d/'calls',d/'created',found)
            result=run_shell(script_of(spire.render('cmtc-a')),env,3)
            self.assertEqual(result.returncode,1)
            self.assertFalse((d/'ack').exists())


def processes():
    """(pid, ppid, command) of every process; `ps -A -o` is POSIX, so BSD/macOS and procps read it alike."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            rows.append((int(parts[0]), int(parts[1]), Path(parts[2]).name))
    return rows


def children_named(ppid, name):
    return [pid for pid, parent, command in processes() if parent == ppid and command == name]


def docker_available():
    if not shutil.which("docker"):
        return False
    try:
        probe = subprocess.run(["docker", "version", "--format", "{{.Server.Os}}"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0 and probe.stdout.strip() == "linux"


# One line per process in the container: "<pid> <ppid> <state> <comm>", read from /proc (busybox ps has no state column).
PROCESS_LIST = ('for p in /proc/[0-9]*; do s=$(sed -n "s/^State:.\\(.\\).*/\\1/p" "$p/status" 2>/dev/null); '
                '[ -n "$s" ] && echo "${p#/proc/} $(sed -n "s/^PPid:.//p" "$p/status") $s $(cat "$p/comm")"; done; true')


class ReapingTests(unittest.TestCase):
    """PID 1 of the register-agent-node sidecar must reap the readiness probe's orphans (#41).

    busybox timeout (coreutils/timeout.c) daemonizes its watcher, so every probe leaves one orphan
    for PID 1. `exec tail -f /dev/null` never waited: 19,091 zombies in 26 h, then the PID limit,
    the sidecar NotReady and the spire-server Service without an endpoint on both labs.
    """

    def holding_env(self, d):
        stub = d / "spire-server"
        found = d / "found"
        write_executable(stub, '#!/bin/sh\ncat "$STUB_FOUND"\n')
        found.write_text(entry_text("cmtc-a.mesh.example"))
        env = RegistrationTests().env(d, stub, d / "calls", d / "created", found)
        env["SPIRE_HOLD"] = "1"
        return env

    def test_hold_stays_in_the_shell_and_waits(self):
        script = script_of(spire.render("cmtc-a"))
        code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("tail -f", code)
        self.assertNotIn("exec tail", code)
        hold = code[code.index("\nhold() {"):]
        hold = hold[:hold.index("\n}\n")]
        self.assertIn('wait "$sleeper"', hold)
        self.assertIn("trap 'kill \"$sleeper\" 2>/dev/null; exit 0' TERM INT", hold)
        self.assertNotIn("exec ", hold)

    def test_hold_reaps_while_it_waits_and_ends_on_term_at_once(self):
        with tempfile.TemporaryDirectory() as raw:
            d = Path(raw)
            env = self.holding_env(d)
            path = d / "script.sh"
            path.write_text(script_of(spire.render("cmtc-a")))
            proc = subprocess.Popen(["/bin/sh", str(path)], env=env, cwd=d, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not ((d / "ack").exists() and children_named(proc.pid, "sleep")):
                    self.assertIsNone(proc.poll(), "the script exited instead of holding")
                    self.assertLess(time.monotonic(), deadline, "no sleeper child within 5 s")
                    time.sleep(0.05)
                sleepers = children_named(proc.pid, "sleep")
                self.assertEqual(len(sleepers), 1, sleepers)
                started = time.monotonic()
                proc.terminate()
                out, _ = proc.communicate(timeout=3)
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(proc.returncode, 0, out)
                self.assertIn("stage=entry-confirm", out)
                deadline = time.monotonic() + 2
                while any(pid == sleepers[0] for pid, _, _ in processes()):
                    self.assertLess(time.monotonic(), deadline, "the sleeper outlived the hold")
                    time.sleep(0.05)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    @unittest.skipUnless(docker_available(), "a Linux docker engine is not reachable")
    def test_pid1_of_the_pinned_busybox_reaps_the_probe_orphans(self):
        script = script_of(spire.render("cmtc-a"))
        self.assertIn("\n    hold\n", script)
        leaking = script.replace("\n    hold\n", "\n    exec tail -f /dev/null\n")
        # The control proves the harness sees the leak: one zombie per probe, plus the watchers of the
        # two startup cli calls (entry show, entry show -entryID), which exit after `exec tail`.
        pid1, control = self.zombies_after_probes(leaking, 6)
        self.assertEqual(pid1, "tail")
        self.assertEqual(len(control), 6 + 2, control)
        self.assertTrue(all(ppid == "1" and comm == "timeout" for _, ppid, comm in control), control)
        self.assertEqual(self.zombies_after_probes(script, 20), ("sh", []))

    def zombies_after_probes(self, script, probes):
        docs = spire.render("cmtc-a")
        sidecar = container(one(docs, "StatefulSet", "spire-server"), "register-agent-node")
        self.assertEqual(sidecar["command"], ["/bin/sh", "/opt/cmtc/register-agent-node.sh"])
        probe = sidecar["readinessProbe"]["exec"]["command"]
        env = {item["name"]: item["value"] for item in sidecar["env"]}
        env.update(SPIRE_SERVER_BIN="/opt/cmtc/spire-server", SPIRE_ACK_FILE="/tmp/entry", STUB_FOUND="/opt/cmtc/found")
        name = "cmtc-reap-test-%d-%d" % (os.getpid(), int(time.monotonic() * 1000))
        with tempfile.TemporaryDirectory() as raw:
            d = Path(raw) / "cmtc"
            d.mkdir()
            (d / "register-agent-node.sh").write_text(script)
            write_executable(d / "spire-server", '#!/bin/sh\ncat "$STUB_FOUND"\n')
            (d / "spire-server").chmod(0o755)  # docker cp makes root the owner; uid 1000 runs it
            (d / "found").write_text(entry_text("cmtc-a.mesh.example"))
            create = ["create", "--name", name, "--user", "1000:1000", "--tmpfs", "/opt/cmtc:exec,uid=1000,gid=1000,mode=0755"]  # docker mounts a tmpfs noexec by default
            for key, value in sorted(env.items()):
                create += ["-e", key + "=" + value]
            # docker cp cannot create /opt; the bootstrap copies the files and then execs the sidecar command.
            create += [sidecar["image"], "/bin/sh", "-c", 'cp /tmp/cmtc/* /opt/cmtc/ && exec "$@"', "sh"] + sidecar["command"]
            try:
                self.docker(*create, timeout=300)
                self.docker("cp", str(d), name + ":/tmp/cmtc")
                self.docker("start", name)
                deadline = time.monotonic() + 15
                while subprocess.run(["docker", "exec", name, "test", "-s", "/tmp/entry"], capture_output=True, check=False).returncode != 0:
                    self.assertEqual(self.docker("inspect", "-f", "{{.State.Running}}", name).strip(), "true", self.docker("logs", name))
                    self.assertLess(time.monotonic(), deadline, "the sidecar did not confirm the entry in 15 s: " + self.docker("logs", name))
                    time.sleep(0.2)
                pid1 = self.docker("exec", name, "cat", "/proc/1/comm").strip()
                for _ in range(probes):
                    self.docker("exec", name, *probe)
                time.sleep(4)  # every watcher has exited: the probe deadline is 3 s
                rows = [line.split(None, 3) for line in self.docker("exec", name, "sh", "-c", PROCESS_LIST).splitlines() if line.strip()]
                live = [row for row in rows if row[2] != "Z"]
                self.assertNotIn("timeout", [comm for _, _, _, comm in live], live)
                self.assertLessEqual(len(live), 4, live)  # PID 1, its sleeper (fix only), this listing's sh and sed/cat
                return pid1, [(pid, ppid, comm) for pid, ppid, state, comm in rows if state == "Z"]
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, check=False)

    def docker(self, *args, check=True, timeout=60):
        completed = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
        if check and completed.returncode != 0:
            raise AssertionError("docker %s: rc=%d %s%s" % (args[0], completed.returncode, completed.stdout, completed.stderr))
        return completed.stdout


class CliTests(unittest.TestCase):
    def test_json_list_matches_the_renderer(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "render_spire.py"), "cmtc-a", "--format", "json"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["apiVersion"], "v1")
        self.assertEqual(payload["kind"], "List")
        self.assertEqual(payload["items"], spire.render("cmtc-a"))
        self.assertIsInstance(payload["items"][0]["metadata"]["labels"]["security.cmtc.io/pki-owner"], str)

    def test_foreign_cluster_exits_without_objects(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "render_spire.py"), "cmtc-mtls", "--format", "json"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("unknown cluster", completed.stderr)

    def test_yaml_documents_or_missing_pyyaml(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "render_spire.py"), "cmtc-b", "--format", "yaml"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        try:
            import yaml
        except ImportError:
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, "")
            self.assertIn("PyYAML is not installed", completed.stderr)
            return
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(list(yaml.safe_load_all(completed.stdout)), spire.render("cmtc-b"))


if __name__ == "__main__":
    unittest.main()
