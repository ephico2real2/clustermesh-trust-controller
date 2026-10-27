#!/usr/bin/env python3
"""Render standalone SPIRE server and agent objects for one cluster.

The function returns Kubernetes dictionaries. It does not contact a cluster.
Image pins come from Cilium commit 53c65b478e0f57a475a53dbf1b98f39436ac2d75,
install/kubernetes/cilium/values.yaml. The server image is lines 4524-4528.
The agent image is lines 4469-4473. The init image is lines 4454-4458.
The chart helper cilium.image joins repository, tag, and digest.
"""

import argparse
import json
import re
import sys

OWNER = "cmtc-lab-pki"
NAMESPACE = "cilium-spire"
SERVER_ACCOUNT = "spire-server"
AGENT_ACCOUNT = "spire-agent"
STORAGE_CLASS = "standard"
STORAGE_PROVISIONER = "rancher.io/local-path"
SERVER_IMAGE = "ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384"
AGENT_IMAGE = "ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481"
BUSYBOX_IMAGE = "docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
PINNED_IMAGES = {
    "server": SERVER_IMAGE,
    "agent": AGENT_IMAGE,
    "busybox": BUSYBOX_IMAGE,
}
CLUSTERS = {
    "cmtc-a": "cmtc-a.mesh.example",
    "cmtc-b": "cmtc-b.mesh.example",
}
# install/kubernetes/cilium/templates/spire/server/configmap.yaml
SERVER_SOCKET_DIR = "/tmp/spire-server/private"
SERVER_SOCKET = SERVER_SOCKET_DIR + "/api.sock"
SERVER_DATA = "/run/spire/data"
# install/kubernetes/cilium/values.yaml agentSocketPath
AGENT_SOCKET_DIR = "/run/spire/sockets"
AGENT_SOCKET = AGENT_SOCKET_DIR + "/agent/agent.sock"
# SPIRE 1.15.5 pkg/agent/plugin/nodeattestor/k8spsat/psat.go defaultTokenPath.
# The chart projects the token at this path with audience spire-server.
TOKEN_PATH = "/var/run/secrets/tokens/spire-agent"
TOKEN_AUDIENCE = "spire-server"
# files/spire/init.bash uses this binary and these two node selectors.
SERVER_BINARY = "/opt/spire/bin/spire-server"
CLI_MOUNT = "/spire-cli"
CLI_BINARY = CLI_MOUNT + SERVER_BINARY
SELECTOR_NS = "k8s_psat:agent_ns:" + NAMESPACE
SELECTOR_SA = "k8s_psat:agent_sa:" + AGENT_ACCOUNT
REGISTER_DEADLINE_SECONDS = 90
REGISTER_MAX_ATTEMPTS = 8
REGISTER_BACKOFF_START_SECONDS = 1
REGISTER_BACKOFF_CAP_SECONDS = 8
WAIT_ATTEMPTS = 60
WAIT_DEADLINE_SECONDS = 60
WAIT_BACKOFF_SECONDS = 1
# Chart probes from the server StatefulSet and the agent DaemonSet.
LIVE_FAILURE_THRESHOLD = 2
LIVE_INITIAL_DELAY_SECONDS = 15
LIVE_PERIOD_SECONDS = 60
LIVE_TIMEOUT_SECONDS = 3
READY_INITIAL_DELAY_SECONDS = 5
READY_PERIOD_SECONDS = 5
START_FAILURE_THRESHOLD = 30
START_PERIOD_SECONDS = 5
START_TIMEOUT_SECONDS = 3
FORBIDDEN_NAMES = {
    "cluster-intermediate",
    "cmtc-lab-intermediate",
    "cmtc-mtls",
    "clustermesh-apiserver",
    "cilium-ca",
}
FORBIDDEN_TEXT = (
    "cluster-intermediate",
    "cmtc-lab-intermediate",
    "cmtc-mtls",
    "clustermesh-apiserver",
    "cilium-agent",
    "cilium-operator",
    "ztunnel",
    "Protected",
    "enable-ipsec",
    "enable-wireguard",
    "enable-ztunnel",
    "encryption.enabled",
    "pgrep",
    "/proc/",
    "while true",
    "experimental",
    "requireMtls",
    "require-mtls",
    "workload-registrar",
    "hostPath",
)
# values.yaml agent tolerations plus the DaemonSet agent-not-ready toleration.
AGENT_TOLERATIONS = [
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
]
POD_SECURITY = {
    "runAsUser": 1000,
    "runAsGroup": 1000,
    "fsGroup": 1000,
    "fsGroupChangePolicy": "OnRootMismatch",
    "runAsNonRoot": True,
}

REGISTER_SCRIPT = r"""#!/bin/sh
# Confirm the agent node entry. Stop at the attempt limit or the deadline.
set -f
set -u
bin="${SPIRE_SERVER_BIN:-__CLI_BINARY__}"
sock="${SPIRE_SOCKET:-__SERVER_SOCKET__}"
id='__SPIFFE_ID__'
sel_ns='__SELECTOR_NS__'
sel_sa='__SELECTOR_SA__'
deadline="${SPIRE_DEADLINE:-__DEADLINE__}"
max_attempts="${SPIRE_MAX_ATTEMPTS:-__MAX_ATTEMPTS__}"
backoff="${SPIRE_BACKOFF_START:-__BACKOFF_START__}"
backoff_cap="${SPIRE_BACKOFF_CAP:-__BACKOFF_CAP__}"
hold="${SPIRE_HOLD:-1}"
ack="${SPIRE_ACK_FILE:-/run/cmtc-registration/entry}"
check_only="${SPIRE_CHECK_ONLY:-0}"
if [ "$check_only" != "1" ]; then rm -f "$ack"; fi
umask 077
start=$(date +%s)
attempt=0
created=0

log_event() {
  stage_name=$1
  err=$(printf '%s' "$2" | tr '\n' ' ' | tr '\r' ' ')
  now=$(date +%s)
  elapsed=$((now - start))
  printf 'stage=%s attempt=%s elapsed=%s deadline=%s backoff=%s error=%s\n' \
    "$stage_name" "$attempt" "$elapsed" "$deadline" "$backoff" "$err"
}

finish() {
  code=$1
  if [ "$code" -ne 0 ]; then rm -f "$ack"; exit "$code"; fi
  if [ "$hold" = "1" ]; then
    exec tail -f /dev/null
  fi
  exit "$code"
}

cli() {
  now=$(date +%s)
  remaining=$((deadline - (now - start)))
  if [ "$remaining" -le 0 ]; then return 124; fi
  limit=$remaining
  if [ "$limit" -gt 10 ]; then limit=10; fi
  timeout -s KILL "$limit" "$bin" "$@"
}

grow_backoff() {
  next=$1
  cap=$2
  if [ "$next" -lt "$cap" ]; then
    next=$((next * 2))
  fi
  if [ "$next" -gt "$cap" ]; then
    next=$cap
  fi
  printf '%s\n' "$next"
}

sleep_backoff() {
  if [ "$attempt" -lt "$max_attempts" ]; then
    now=$(date +%s)
    remaining=$((deadline - (now - start)))
    pause=$backoff
    if [ "$pause" -gt "$remaining" ]; then pause=$remaining; fi
    if [ "$pause" -gt 0 ]; then sleep "$pause"; fi
    backoff=$(grow_backoff "$backoff" "$backoff_cap")
  fi
}

line_is() {
  text=$1
  want=$2
  old_ifs=$IFS
  IFS='
'
  for line in $text; do
    trimmed=$line
    i=0
    while [ "$i" -lt 40 ]; do
      i=$((i + 1))
      case $trimmed in
        " "*) trimmed=${trimmed# } ;;
        *) break ;;
      esac
    done
    if [ "$trimmed" = "$want" ]; then
      IFS=$old_ifs
      return 0
    fi
  done
  IFS=$old_ifs
  return 1
}

take_field() {
  text=$1
  label=$2
  old_ifs=$IFS
  IFS='
'
  value=
  for line in $text; do
    case $line in
      "$label "*)
        value=$line
        break
        ;;
    esac
  done
  IFS=$old_ifs
  value=${value#"$label"}
  i=0
  while [ "$i" -lt 40 ]; do
    i=$((i + 1))
    case $value in
      " "*) value=${value# } ;;
      ":"*) value=${value#:} ;;
      *) break ;;
    esac
  done
  printf '%s' "$value"
}

selector_ok() {
  text=$1
  ns=0
  sa=0
  count=0
  old_ifs=$IFS
  IFS='
'
  for line in $text; do
    case $line in
      "Selector "*)
        count=$((count + 1))
        value=$(take_field "$line" "Selector")
        if [ "$value" = "$sel_ns" ]; then ns=$((ns + 1)); fi
        if [ "$value" = "$sel_sa" ]; then sa=$((sa + 1)); fi
        ;;
    esac
  done
  IFS=$old_ifs
  [ "$count" -eq 2 ] && [ "$ns" -eq 1 ] && [ "$sa" -eq 1 ]
}

if [ "$check_only" = "1" ]; then
  attempt=1
  if [ ! -s "$ack" ]; then exit 1; fi
  acknowledged=$(cat "$ack")
  result=$(cli entry show -socketPath "$sock" -entryID "$acknowledged" 2>&1)
  rc=$?
  if [ "$rc" -ne 0 ]; then log_event readiness "$result"; exit 1; fi
  result=$(printf '%s' "$result" | tr -d '\r')
  if ! line_is "$result" "Found 1 entry" || ! selector_ok "$result" ||
     [ "$(take_field "$result" "Entry ID")" != "$acknowledged" ] ||
     [ "$(take_field "$result" "SPIFFE ID")" != "$id" ] ||
     [ "$(take_field "$result" "Parent ID")" != '__PARENT_ID__' ]; then
    log_event readiness "exact node alias changed or unavailable"
    exit 1
  fi
  exit 0
fi

while [ "$attempt" -lt "$max_attempts" ]; do
  now=$(date +%s)
  elapsed=$((now - start))
  if [ "$elapsed" -ge "$deadline" ]; then
    log_event deadline "deadline exceeded"
    finish 1
  fi
  attempt=$((attempt + 1))
  show_out=$(cli entry show -socketPath "$sock" -spiffeID "$id" -selector "$sel_ns" -selector "$sel_sa" 2>&1)
  show_rc=$?
  show_out=$(printf '%s' "$show_out" | tr -d '\r')
  if [ "$show_rc" -ne 0 ]; then
    log_event entry-show "$show_out"
    sleep_backoff
    continue
  fi
  if line_is "$show_out" "Found 0 entries"; then
    if [ "$created" -eq 0 ]; then
      log_event entry-create ""
      create_out=$(cli entry create -socketPath "$sock" -spiffeID "$id" -selector "$sel_ns" -selector "$sel_sa" -node 2>&1)
      create_rc=$?
      create_out=$(printf '%s' "$create_out" | tr -d '\r')
      if [ "$create_rc" -ne 0 ]; then
        log_event entry-create "$create_out"
        sleep_backoff
        continue
      fi
      created=1
    else
      log_event entry-show "entry is not visible yet"
      sleep_backoff
    fi
    continue
  fi
  if ! line_is "$show_out" "Found 1 entry"; then
    log_event entry-confirm "entry count is not 1"
    finish 1
  fi
  if ! selector_ok "$show_out"; then
    log_event entry-confirm "selectors do not match"
    finish 1
  fi
  got_id=$(take_field "$show_out" "Entry ID")
  got_spiffe=$(take_field "$show_out" "SPIFFE ID")
  if [ -z "$got_id" ] || [ "$got_spiffe" != "$id" ] ||
     [ "$(take_field "$show_out" "Parent ID")" != '__PARENT_ID__' ]; then
    log_event entry-confirm "entry id or SPIFFE ID does not match"
    finish 1
  fi
  id_out=$(cli entry show -socketPath "$sock" -entryID "$got_id" 2>&1)
  id_rc=$?
  id_out=$(printf '%s' "$id_out" | tr -d '\r')
  if [ "$id_rc" -ne 0 ]; then
    log_event entry-confirm "$id_out"
    finish 1
  fi
  again_id=$(take_field "$id_out" "Entry ID")
  again_spiffe=$(take_field "$id_out" "SPIFFE ID")
  if ! line_is "$id_out" "Found 1 entry" || [ "$again_id" != "$got_id" ] || [ "$again_spiffe" != "$id" ] ||
     [ "$(take_field "$id_out" "Parent ID")" != '__PARENT_ID__' ] || ! selector_ok "$id_out"; then
    log_event entry-confirm "entry id query did not match"
    finish 1
  fi
  if ! printf '%s\n' "$got_id" > "$ack.tmp" || ! mv "$ack.tmp" "$ack"; then
    log_event entry-confirm "acknowledgment file unavailable"
    finish 1
  fi
  log_event entry-confirm ""
  finish 0
done
log_event deadline "attempt limit"
finish 1
"""

WAIT_SCRIPT = r"""#!/bin/sh
set -f
set -u
attempt=0
max="${SPIRE_WAIT_ATTEMPTS:-__WAIT_ATTEMPTS__}"
deadline="${SPIRE_WAIT_DEADLINE:-__WAIT_DEADLINE__}"
backoff="${SPIRE_WAIT_BACKOFF:-__WAIT_BACKOFF__}"
host="${SPIRE_SERVER_HOST:-spire-server.__NAMESPACE__.svc}"
port="${SPIRE_SERVER_PORT:-8081}"
start=$(date +%s)
while [ "$attempt" -lt "$max" ]; do
  now=$(date +%s)
  elapsed=$((now - start))
  if [ "$elapsed" -ge "$deadline" ]; then
    printf 'stage=wait-server attempt=%s elapsed=%s deadline=%s backoff=%s error=%s\n' \
      "$attempt" "$elapsed" "$deadline" "$backoff" "deadline exceeded"
    exit 1
  fi
  attempt=$((attempt + 1))
  now=$(date +%s)
  elapsed=$((now - start))
  if nc -z -w 3 "$host" "$port"; then
    printf 'stage=wait-server attempt=%s elapsed=%s deadline=%s backoff=%s error=%s\n' \
      "$attempt" "$elapsed" "$deadline" "$backoff" ""
    exit 0
  fi
  printf 'stage=wait-server attempt=%s elapsed=%s deadline=%s backoff=%s error=%s\n' \
    "$attempt" "$elapsed" "$deadline" "$backoff" "spire server is not reachable"
  if [ "$attempt" -lt "$max" ]; then
    sleep "$backoff"
  fi
done
now=$(date +%s)
elapsed=$((now - start))
printf 'stage=wait-server attempt=%s elapsed=%s deadline=%s backoff=%s error=%s\n' \
  "$attempt" "$elapsed" "$deadline" "$backoff" "attempt limit"
exit 1
"""


class Refusal(ValueError):
    """The input or the certificate record is outside this slice."""


def labels(cluster, role):
    return {
        "security.cmtc.io/pki-owner": OWNER,
        "security.cmtc.io/pki-cluster": cluster,
        "security.cmtc.io/pki-role": role,
    }


def metadata(name, cluster, role, namespace=NAMESPACE):
    if not isinstance(name, str) or name in FORBIDDEN_NAMES or not name:
        raise Refusal("refusing object name")
    body = {"name": name, "labels": labels(cluster, role)}
    if namespace is not None:
        body["namespace"] = namespace
    return body


def resource(api_version, kind, name, cluster, role, namespace=NAMESPACE, spec=None, data=None):
    body = {
        "apiVersion": api_version,
        "kind": kind,
        "metadata": metadata(name, cluster, role, namespace),
    }
    if spec is not None:
        if api_version == "rbac.authorization.k8s.io/v1":
            body.update(spec)
        else:
            body["spec"] = spec
    if data is not None:
        body["data"] = data
    return body


def env_var(name, value):
    return {"name": name, "value": str(value)}


def http_probe(path, **fields):
    body = {"httpGet": {"path": path, "port": "http"}}
    body.update(fields)
    return body


def startup_probe():
    return http_probe(
        "/live",
        failureThreshold=START_FAILURE_THRESHOLD,
        periodSeconds=START_PERIOD_SECONDS,
        timeoutSeconds=START_TIMEOUT_SECONDS,
    )


def liveness_probe():
    return http_probe(
        "/live",
        failureThreshold=LIVE_FAILURE_THRESHOLD,
        initialDelaySeconds=LIVE_INITIAL_DELAY_SECONDS,
        periodSeconds=LIVE_PERIOD_SECONDS,
        timeoutSeconds=LIVE_TIMEOUT_SECONDS,
    )


def readiness_probe():
    return http_probe(
        "/ready",
        initialDelaySeconds=READY_INITIAL_DELAY_SECONDS,
        periodSeconds=READY_PERIOD_SECONDS,
    )


def agent_spiffe_id(domain):
    return "spiffe://" + domain + "/ns/" + NAMESPACE + "/sa/" + AGENT_ACCOUNT


def server_config(cluster, domain):
    return f'''server {{
  bind_address = "0.0.0.0"
  bind_port = "8081"
  socket_path = "{SERVER_SOCKET}"
  trust_domain = "{domain}"
  data_dir = "{SERVER_DATA}"
  log_level = "INFO"
  ca_key_type = "rsa-4096"
  ca_subject = {{
    country = ["US"],
    organization = ["SPIRE"],
    common_name = "{cluster} SPIRE CA",
  }}
}}

plugins {{
  DataStore "sql" {{
    plugin_data {{
      database_type = "sqlite3"
      connection_string = "{SERVER_DATA}/datastore.sqlite3"
    }}
  }}

  NodeAttestor "k8s_psat" {{
    plugin_data {{
      clusters = {{
        "{cluster}" = {{
          use_token_review_api_validation = true
          service_account_allow_list = ["{NAMESPACE}:{AGENT_ACCOUNT}"]
        }}
      }}
    }}
  }}

  KeyManager "disk" {{
    plugin_data {{
      keys_path = "{SERVER_DATA}/keys.json"
    }}
  }}

  UpstreamAuthority "cert-manager" {{
    plugin_data {{
      namespace = "{NAMESPACE}"
      # The CMTC chart (charts/cmtc, trust.*) creates this ClusterIssuer.
      issuer_name = "{cluster}-spire-intermediate"
      issuer_kind = "ClusterIssuer"
      issuer_group = "cert-manager.io"
    }}
  }}

  Notifier "k8sbundle" {{
    plugin_data {{
      namespace = "{NAMESPACE}"
    }}
  }}
}}

health_checks {{
  listener_enabled = true
  bind_address = "0.0.0.0"
  bind_port = "8080"
  live_path = "/live"
  ready_path = "/ready"
}}
'''


def agent_config(cluster, domain):
    return f'''agent {{
  data_dir = "/run/spire/data"
  log_level = "ERROR"
  server_address = "spire-server.{NAMESPACE}.svc"
  server_port = "8081"
  socket_path = "{AGENT_SOCKET}"
  trust_bundle_path = "/run/spire/bundle/bundle.crt"
  trust_domain = "{domain}"
}}

plugins {{
  NodeAttestor "k8s_psat" {{
    plugin_data {{
      cluster = "{cluster}"
      token_path = "{TOKEN_PATH}"
    }}
  }}

  KeyManager "memory" {{
    plugin_data {{
    }}
  }}

  WorkloadAttestor "k8s" {{
    plugin_data {{
      skip_kubelet_verification = true
    }}
  }}
}}

health_checks {{
  listener_enabled = true
  bind_address = "0.0.0.0"
  bind_port = "4251"
  live_path = "/live"
  ready_path = "/ready"
}}
'''


def register_script(domain):
    script = REGISTER_SCRIPT
    replacements = {
        "__CLI_BINARY__": CLI_BINARY,
        "__SERVER_SOCKET__": SERVER_SOCKET,
        "__SPIFFE_ID__": agent_spiffe_id(domain),
        "__SELECTOR_NS__": SELECTOR_NS,
        "__PARENT_ID__": "spiffe://" + domain + "/spire/server",
        "__SELECTOR_SA__": SELECTOR_SA,
        "__DEADLINE__": str(REGISTER_DEADLINE_SECONDS),
        "__MAX_ATTEMPTS__": str(REGISTER_MAX_ATTEMPTS),
        "__BACKOFF_START__": str(REGISTER_BACKOFF_START_SECONDS),
        "__BACKOFF_CAP__": str(REGISTER_BACKOFF_CAP_SECONDS),
    }
    for token, value in replacements.items():
        if token not in script:
            raise Refusal("registration script is missing " + token)
        script = script.replace(token, value)
    if "__" in script:
        raise Refusal("registration script has an open token")
    return script


def wait_script():
    script = WAIT_SCRIPT
    replacements = {
        "__WAIT_ATTEMPTS__": str(WAIT_ATTEMPTS),
        "__WAIT_DEADLINE__": str(WAIT_DEADLINE_SECONDS),
        "__WAIT_BACKOFF__": str(WAIT_BACKOFF_SECONDS),
        "__NAMESPACE__": NAMESPACE,
    }
    for token, value in replacements.items():
        if token not in script:
            raise Refusal("wait script is missing " + token)
        script = script.replace(token, value)
    if "__" in script:
        raise Refusal("wait script has an open token")
    return script


def require_cluster(cluster, domain):
    if not isinstance(cluster, str) or cluster not in CLUSTERS:
        raise Refusal("unknown cluster")
    if domain is None:
        domain = CLUSTERS[cluster]
    if not isinstance(domain, str):
        raise Refusal("domain is not a string")
    if domain == cluster:
        raise Refusal("trust domain and cluster name must differ")
    if domain != CLUSTERS[cluster]:
        raise Refusal("domain does not match cluster")
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise Refusal("domain contains an unsupported character")
    return domain


def approved_server_image(value):
    """Validate an independent administrator pin; never discover it from a Pod.

    The caller must first verify the exact local image/source/config and imported
    per-node CRI manifests. Syntax validation is not that source verification.
    """
    pattern = (r"(?:localhost|[a-z0-9][a-z0-9.-]*)(?::[1-9][0-9]{0,4})?/"
               r"(?:[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*/)*"
               r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
               r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}")
    if not isinstance(value, str) or len(value) > 512 or not re.fullmatch(pattern, value):
        raise Refusal("explicit full registry/repository@sha256 server image required")
    registry = value.split("/", 1)[0]
    host, separator, port = registry.partition(":")
    if separator and int(port) > 65535:
        raise Refusal("invalid image registry port")
    labels = host.split(".")
    if host != "localhost" and (len(labels) < 2 or any(len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)):
        raise Refusal("canonical explicit image registry required")
    return value


def require_images(images, *, server_image=SERVER_IMAGE):
    approved = dict(PINNED_IMAGES)
    approved["server"] = approved_server_image(server_image)
    if images is None:
        return approved
    if not isinstance(images, dict) or set(images) != set(PINNED_IMAGES):
        raise Refusal("image map keys are not server, agent, and busybox")
    for name, pinned in approved.items():
        value = images[name]
        if not isinstance(value, str) or value != pinned:
            raise Refusal(name + " image is not the pinned digest")
    return approved


def server_cluster_role_name(cluster):
    return "cmtc-lab-spire-server-" + cluster


def agent_cluster_role_name(cluster):
    return "cmtc-lab-spire-agent-" + cluster


def role_binding(name, cluster, role, role_name, subject):
    return resource(
        "rbac.authorization.k8s.io/v1",
        "RoleBinding",
        name,
        cluster,
        role,
        spec={
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": role_name,
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": subject, "namespace": NAMESPACE}
            ],
        },
    )


def cluster_binding(name, cluster, role, subject):
    return resource(
        "rbac.authorization.k8s.io/v1",
        "ClusterRoleBinding",
        name,
        cluster,
        role,
        namespace=None,
        spec={
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": name,
            },
            "subjects": [
                {"kind": "ServiceAccount", "name": subject, "namespace": NAMESPACE}
            ],
        },
    )


def server_stateful_set(cluster, domain, images):
    pod_labels = labels(cluster, "spire-server")
    pod_labels["app"] = "spire-server"
    workload_labels = labels(cluster, "spire-server")
    workload_labels["app"] = "spire-server"
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "spire-server",
            "namespace": NAMESPACE,
            "labels": workload_labels,
        },
        "spec": {
            "replicas": 1,
            "serviceName": "spire-server",
            "persistentVolumeClaimRetentionPolicy": {"whenDeleted":"Retain","whenScaled":"Retain"},
            "selector": {"matchLabels": {"app": "spire-server"}},
            "template": {
                "metadata": {"labels": pod_labels},
                "spec": {
                    "serviceAccountName": SERVER_ACCOUNT,
                    "priorityClassName": "system-node-critical",
                    "hostUsers": True,
                    "securityContext": dict(POD_SECURITY),
                    "containers": [
                        {
                            "name": "spire-server",
                            "image": images["server"],
                            "imagePullPolicy": "IfNotPresent",
                            "args": ["-config", "/run/spire/config/server.conf"],
                            "ports": [
                                {"name": "grpc", "containerPort": 8081, "protocol": "TCP"},
                                {"name": "http", "containerPort": 8080, "protocol": "TCP"},
                            ],
                            "startupProbe": startup_probe(),
                            "livenessProbe": liveness_probe(),
                            "readinessProbe": readiness_probe(),
                            "volumeMounts": [
                                {"name": "spire-config", "mountPath": "/run/spire/config", "readOnly": True},
                                {"name": "spire-data", "mountPath": SERVER_DATA},
                                {"name": "spire-server-socket", "mountPath": SERVER_SOCKET_DIR},
                            ],
                        },
                        {
                            "name": "register-agent-node",
                            "image": images["busybox"],
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "/opt/cmtc/register-agent-node.sh"],
                            "env": [
                                env_var("SPIRE_SERVER_BIN", CLI_BINARY),
                                env_var("SPIRE_SOCKET", SERVER_SOCKET),
                                env_var("SPIRE_DEADLINE", REGISTER_DEADLINE_SECONDS),
                                env_var("SPIRE_MAX_ATTEMPTS", REGISTER_MAX_ATTEMPTS),
                                env_var("SPIRE_BACKOFF_START", REGISTER_BACKOFF_START_SECONDS),
                                env_var("SPIRE_BACKOFF_CAP", REGISTER_BACKOFF_CAP_SECONDS),
                                env_var("SPIRE_HOLD", "1"),
                                env_var("SPIRE_ACK_FILE", "/run/cmtc-registration/entry"),
                            ],
                            "readinessProbe": {"exec":{"command":["/bin/sh","-ec",
                                "SPIRE_CHECK_ONLY=1 SPIRE_HOLD=0 SPIRE_DEADLINE=3 exec /bin/sh /opt/cmtc/register-agent-node.sh"]},
                                "initialDelaySeconds":1,"periodSeconds":5,"timeoutSeconds":4,"failureThreshold":1},
                            "volumeMounts": [
                                {"name":"spire-registration","mountPath":"/run/cmtc-registration"},
                                {"name": "spire-helpers", "mountPath": "/opt/cmtc", "readOnly": True},
                                {"name": "spire-server-socket", "mountPath": SERVER_SOCKET_DIR},
                                {"name": "spire-server-cli", "mountPath": CLI_MOUNT, "readOnly": True},
                            ],
                        },
                    ],
                    "volumes": [
                        {"name": "spire-config", "configMap": {"name": "spire-server"}},
                        {"name": "spire-server-socket", "emptyDir": {}},
                        {"name":"spire-registration","emptyDir":{"sizeLimit":"16Ki"}},
                        {
                            "name": "spire-server-cli",
                            "image": {
                                "reference": images["server"],
                                "pullPolicy": "IfNotPresent",
                            },
                        },
                        {"name": "spire-helpers", "configMap": {"name": "spire-helpers", "defaultMode": 0o444}},
                    ],
                },
            },
            "volumeClaimTemplates": [
                {
                    "metadata": metadata("spire-data", cluster, "spire-data", namespace=None),
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "storageClassName": STORAGE_CLASS,
                        "resources": {"requests": {"storage": "1Gi"}},
                    },
                }
            ],
        },
    }


def agent_daemon_set(cluster, images):
    pod_labels = labels(cluster, "spire-agent")
    pod_labels["app"] = "spire-agent"
    workload_labels = labels(cluster, "spire-agent")
    workload_labels["app"] = "spire-agent"
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": "spire-agent",
            "namespace": NAMESPACE,
            "labels": workload_labels,
        },
        "spec": {
            "selector": {"matchLabels": {"app": "spire-agent"}},
            "template": {
                "metadata": {"labels": pod_labels},
                "spec": {
                    "serviceAccountName": AGENT_ACCOUNT,
                    "priorityClassName": "system-node-critical",
                    "hostUsers": True,
                    "hostPID": True,
                    "hostNetwork": True,
                    "dnsPolicy": "ClusterFirstWithHostNet",
                    "securityContext": dict(POD_SECURITY),
                    "tolerations": [dict(item) for item in AGENT_TOLERATIONS],
                    "initContainers": [
                        {
                            "name": "wait-for-server",
                            "image": images["busybox"],
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "/opt/cmtc/wait-for-server.sh"],
                            "env": [
                                env_var("SPIRE_WAIT_ATTEMPTS", WAIT_ATTEMPTS),
                                env_var("SPIRE_WAIT_DEADLINE", WAIT_DEADLINE_SECONDS),
                                env_var("SPIRE_WAIT_BACKOFF", WAIT_BACKOFF_SECONDS),
                                env_var("SPIRE_SERVER_HOST", "spire-server." + NAMESPACE + ".svc"),
                                env_var("SPIRE_SERVER_PORT", "8081"),
                            ],
                            "volumeMounts": [
                                {"name": "spire-helpers", "mountPath": "/opt/cmtc", "readOnly": True}
                            ],
                        }
                    ],
                    "containers": [
                        {
                            "name": "spire-agent",
                            "image": images["agent"],
                            "imagePullPolicy": "IfNotPresent",
                            "args": ["-config", "/run/spire/config/agent.conf"],
                            "ports": [
                                {"name": "http", "containerPort": 4251, "protocol": "TCP"}
                            ],
                            "startupProbe": startup_probe(),
                            "livenessProbe": liveness_probe(),
                            "readinessProbe": readiness_probe(),
                            "volumeMounts": [
                                {"name": "spire-config", "mountPath": "/run/spire/config", "readOnly": True},
                                {"name": "spire-bundle", "mountPath": "/run/spire/bundle","readOnly":True},
                                {"name":"spire-agent-data","mountPath":"/run/spire/data"},
                                {"name": "spire-agent-socket", "mountPath": AGENT_SOCKET_DIR},
                                {
                                    "name": "spire-token",
                                    "mountPath": "/var/run/secrets/tokens",
                                    "readOnly": True,
                                },
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "spire-config", "configMap": {"name": "spire-agent"}},
                        {"name": "spire-bundle", "configMap": {"name": "spire-bundle"}},
                        {"name": "spire-agent-socket", "emptyDir": {}},
                        {"name":"spire-agent-data","emptyDir":{"sizeLimit":"64Mi"}},
                        {"name": "spire-helpers", "configMap": {"name": "spire-helpers", "defaultMode": 0o444}},
                        {
                            "name": "spire-token",
                            "projected": {
                                "sources": [
                                    {
                                        "serviceAccountToken": {
                                            "path": "spire-agent",
                                            "expirationSeconds": 600,
                                            "audience": TOKEN_AUDIENCE,
                                        }
                                    }
                                ]
                            },
                        },
                    ],
                },
            },
        },
    }


def render(cluster, domain=None, images=None, *, server_image=SERVER_IMAGE):
    """Return the SPIRE dependency objects for one cluster."""
    domain = require_cluster(cluster, domain)
    images = require_images(images, server_image=server_image)
    server_role = server_cluster_role_name(cluster)
    agent_role = agent_cluster_role_name(cluster)
    namespace = resource("v1", "Namespace", NAMESPACE, cluster, "namespace", namespace=None)
    # Opts in to the mesh root ConfigMap (charts/cmtc trust.bundle): SPIRE verifies with the mesh root.
    namespace["metadata"]["labels"]["trust"] = "enabled"
    docs = [
        namespace,
        resource("v1", "ServiceAccount", SERVER_ACCOUNT, cluster, "spire-server-account"),
        resource("v1", "ServiceAccount", AGENT_ACCOUNT, cluster, "spire-agent-account"),
        resource(
            "v1",
            "ConfigMap",
            "spire-server",
            cluster,
            "spire-server-config",
            data={"server.conf": server_config(cluster, domain)},
        ),
        resource(
            "v1",
            "ConfigMap",
            "spire-agent",
            cluster,
            "spire-agent-config",
            data={"agent.conf": agent_config(cluster, domain)},
        ),
        resource("v1", "ConfigMap", "spire-bundle", cluster, "spire-bundle", data={}),
        resource(
            "v1",
            "ConfigMap",
            "spire-helpers",
            cluster,
            "spire-helper",
            data={
                "register-agent-node.sh": register_script(domain),
                "wait-for-server.sh": wait_script(),
            },
        ),
        resource(
            "rbac.authorization.k8s.io/v1",
            "Role",
            "spire-server",
            cluster,
            "spire-server-role",
            spec={
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "resourceNames": ["spire-bundle"],
                        "verbs": ["get", "patch"],
                    }
                ]
            },
        ),
        resource(
            "rbac.authorization.k8s.io/v1",
            "Role",
            "spire-upstreamauthority",
            cluster,
            "spire-upstream-role",
            spec={
                "rules": [
                    {
                        "apiGroups": ["cert-manager.io"],
                        "resources": ["certificaterequests"],
                        "verbs": ["create", "get", "list", "watch", "delete"],
                    }
                ]
            },
        ),
        role_binding("spire-server", cluster, "spire-server-binding", "spire-server", SERVER_ACCOUNT),
        role_binding(
            "spire-upstreamauthority",
            cluster,
            "spire-upstream-binding",
            "spire-upstreamauthority",
            SERVER_ACCOUNT,
        ),
        resource(
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            server_role,
            cluster,
            "spire-server-clusterrole",
            namespace=None,
            spec={
                "rules": [
                    {
                        "apiGroups": ["authentication.k8s.io"],
                        "resources": ["tokenreviews"],
                        "verbs": ["create"],
                    },
                    {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
                    {
                        "apiGroups": [""],
                        "resources": ["nodes", "nodes/proxy"],
                        "verbs": ["get"],
                    },
                ]
            },
        ),
        cluster_binding(server_role, cluster, "spire-server-clusterbinding", SERVER_ACCOUNT),
        resource(
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            agent_role,
            cluster,
            "spire-agent-clusterrole",
            namespace=None,
            spec={
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "nodes", "nodes/proxy"],
                        "verbs": ["get"],
                    }
                ]
            },
        ),
        cluster_binding(agent_role, cluster, "spire-agent-clusterbinding", AGENT_ACCOUNT),
        resource(
            "v1",
            "Service",
            "spire-server",
            cluster,
            "spire-server-service",
            spec={
                "type": "ClusterIP",
                "selector": {"app": "spire-server"},
                "ports": [
                    {"name": "grpc", "port": 8081, "targetPort": "grpc", "protocol": "TCP"}
                ],
            },
        ),
        server_stateful_set(cluster, domain, images),
        agent_daemon_set(cluster, images),
    ]
    encoded = json.dumps(docs)
    for item in FORBIDDEN_TEXT:
        if item in encoded:
            raise Refusal("rendered output contains " + item)
    for doc in docs:
        if doc["kind"] in {"Secret", "ClusterIssuer", "StorageClass", "Certificate", "CertificateRequest"}:
            raise Refusal("rendered kind is outside this slice")
        if doc["metadata"]["name"] in FORBIDDEN_NAMES:
            raise Refusal("rendered object uses a forbidden name")
    return docs


def dump_json(documents):
    payload = {"apiVersion": "v1", "kind": "List", "items": documents}
    return json.dumps(payload, indent=2) + "\n"


def dump_yaml(documents):
    try:
        import yaml
    except ImportError as exc:
        raise Refusal("PyYAML is not installed") from exc
    return yaml.safe_dump_all(documents, sort_keys=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Render standalone SPIRE dependencies.")
    parser.add_argument("cluster")
    parser.add_argument("--format", choices=("json", "yaml"), default="json")
    parser.add_argument("--server-image", default=SERVER_IMAGE, help="Independent approved digest-qualified server/CLI image; verify source/config and all-node CRI imports first")
    args = parser.parse_args(argv)
    try:
        documents = render(args.cluster, server_image=args.server_image)
        if args.format == "json":
            sys.stdout.write(dump_json(documents))
        else:
            sys.stdout.write(dump_yaml(documents))
    except Refusal as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
