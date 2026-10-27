#!/usr/bin/env bash
# Install, on TARGET, the read-only credential of SOURCE's API that TARGET's issuer approval arbiter reads SOURCE's
# public evidence with (ADR-012, cross-cluster path). The administrator step, scripted once:
#   1. on SOURCE, a kubernetes.io/service-account-token Secret for the ServiceAccount cmtc-peer-reader (rendered by the
#      CMTC chart with controller.issuerApproval.peerReader.enabled); the token is durable and revoked by deleting it;
#   2. a kubeconfig with SOURCE's CA and the API endpoint TARGET's Pods reach (--server), written under umask 077;
#   3. on TARGET, the Secret SECRET (key kubeconfig) in cmtc-system, the peerSecret of SOURCE's cluster entry.
# Nothing of the token is printed. The kubeconfig is checked from this host before it is installed: the reader can get
# Certificates and cannot get Secrets. Idempotent: a second run reuses the token Secret and replaces the kubeconfig.
#
# Usage: peer-reader-credential.sh --source CONTEXT --target CONTEXT --server https://IP:6443 --secret NAME
#        (KUBECONFIG names the admin kubeconfig that holds both contexts)
set -euo pipefail
export LC_ALL=C
source_ctx="" target_ctx="" server="" secret="" namespace=cmtc-system sa=cmtc-peer-reader
while [ $# -gt 0 ]; do
  case "$1" in
    --source) source_ctx=$2; shift 2;;
    --target) target_ctx=$2; shift 2;;
    --server) server=$2; shift 2;;
    --secret) secret=$2; shift 2;;
    --namespace) namespace=$2; shift 2;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$source_ctx" ] && [ -n "$target_ctx" ] && [ -n "$server" ] && [ -n "$secret" ] || { sed -n '2,12p' "$0" >&2; exit 2; }

umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
token_secret="$sa-token"

# 1. The durable token on SOURCE (the kubelet-less remote-credential pattern of Istio and Linkerd).
kubectl --context "$source_ctx" -n "$namespace" get serviceaccount "$sa" > /dev/null
kubectl --context "$source_ctx" -n "$namespace" create secret generic "$token_secret" --type kubernetes.io/service-account-token \
  --dry-run=client -o json | python3 -c '
import json, sys
s = json.load(sys.stdin)
s["metadata"]["annotations"] = {"kubernetes.io/service-account.name": sys.argv[1]}
print(json.dumps(s))' "$sa" | kubectl --context "$source_ctx" apply -f - > /dev/null
# The token controller fills the Secret after creation; wait for it, without printing it.
for _ in $(seq 1 30); do
  if [ "$(kubectl --context "$source_ctx" -n "$namespace" get secret "$token_secret" -o go-template='{{if .data.token}}ok{{end}}')" = ok ]; then break; fi
  sleep 1
done
[ "$(kubectl --context "$source_ctx" -n "$namespace" get secret "$token_secret" -o go-template='{{if .data.token}}ok{{end}}')" = ok ] || { echo "token not issued for $sa on $source_ctx" >&2; exit 1; }

# 2. The kubeconfig: SOURCE's CA from the admin kubeconfig (public), the token straight from the API into the file.
kubectl --context "$source_ctx" config view --minify --raw -o go-template='{{(index .clusters 0).cluster "certificate-authority-data"}}' | base64 -d > "$work/ca.crt"
kubectl --context "$source_ctx" -n "$namespace" get secret "$token_secret" -o go-template='{{.data.token}}' | base64 -d > "$work/token"
cluster_name=${source_ctx#kind-}
python3 - "$work" "$server" "$cluster_name" <<'EOF'
import json, pathlib, sys
work, server, name = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
ca = work.joinpath("ca.crt").read_text()
token = work.joinpath("token").read_text().strip()
import base64
cfg = {"apiVersion": "v1", "kind": "Config", "current-context": name,
       "clusters": [{"name": name, "cluster": {"server": server, "certificate-authority-data": base64.b64encode(ca.encode()).decode()}}],
       "users": [{"name": "cmtc-peer-reader", "user": {"token": token}}],
       "contexts": [{"name": name, "context": {"cluster": name, "user": "cmtc-peer-reader"}}]}
work.joinpath("kubeconfig").write_text(json.dumps(cfg))
EOF
rm -f "$work/token"

# The reader is checked before it is installed: evidence readable, Secrets not. --server is checked from this host only
# when it is reachable here; a kind control-plane IP is not, so that check is the runbook's, from a Pod on TARGET.
local_server=$(kubectl --context "$source_ctx" config view --minify -o go-template='{{(index .clusters 0).cluster.server}}')
check() {
  python3 - "$work/kubeconfig" "$1" <<'EOF'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); c = json.loads(p.read_text()); c["clusters"][0]["cluster"]["server"] = sys.argv[2]; p.write_text(json.dumps(c))
EOF
}
check "$local_server"
[ "$(kubectl --kubeconfig "$work/kubeconfig" auth can-i get certificates.cert-manager.io -n cert-manager)" = yes ] || { echo "the reader cannot get Certificates" >&2; exit 1; }
[ "$(kubectl --kubeconfig "$work/kubeconfig" auth can-i get secrets -n cert-manager)" = no ] || { echo "the reader can get Secrets; refusing" >&2; exit 1; }
check "$server"

# 3. The peer Secret on TARGET, replaced in place (the controller mounts it; a change rolls nothing, the file updates).
kubectl --context "$target_ctx" -n "$namespace" create secret generic "$secret" --from-file=kubeconfig="$work/kubeconfig" \
  --dry-run=client -o json | kubectl --context "$target_ctx" apply -f - > /dev/null
echo "installed $namespace/$secret on $target_ctx: cmtc-peer-reader of $source_ctx at $server (token Secret $namespace/$token_secret on $source_ctx)"
