#!/usr/bin/env bash
# Imports one intermediate that make-intermediate.sh made into a cluster, for cert-manager's CA issuer:
#   Secret cert-manager/<CLUSTER>-<KIND>-intermediate (tls.crt, tls.key, ca.crt = the root certificate)
#   ClusterIssuer <CLUSTER>-<KIND>-intermediate, which signs from that Secret
# The root key stays in DIR. Nothing secret is printed.
# Usage: install-intermediate.sh DIR CONTEXT CLUSTER KIND
set -euo pipefail
dir=${1:?usage: install-intermediate.sh DIR CONTEXT CLUSTER KIND}
context=${2:?usage: install-intermediate.sh DIR CONTEXT CLUSTER KIND}
cluster=${3:?usage: install-intermediate.sh DIR CONTEXT CLUSTER KIND}
kind=${4:?usage: install-intermediate.sh DIR CONTEXT CLUSTER KIND}
name="$cluster-$kind-intermediate"
k() { kubectl --context "$context" "$@"; }

# Checks before anything is written. The first one also proves the cluster can be reached, so a "not found" below
# means absent, not unreachable.
k get namespace cert-manager >/dev/null
openssl verify -CAfile "$dir/root.crt" "$dir/$name.crt" >/dev/null
if [ "$(openssl pkey -in "$dir/$name.key" -pubout)" != "$(openssl x509 -in "$dir/$name.crt" -noout -pubkey)" ]; then
  echo "$name.key does not belong to $name.crt" >&2
  exit 1
fi
if k -n cert-manager get secret "$name" >/dev/null 2>&1; then
  echo "$context: Secret cert-manager/$name already exists; refusing to replace it" >&2
  exit 1
fi
# A cert-manager Certificate of this name would overwrite the imported Secret at its next renewal.
if k -n cert-manager get certificates.cert-manager.io "$name" >/dev/null 2>&1; then
  echo "$context: Certificate cert-manager/$name exists and would overwrite the import; remove it first" >&2
  exit 1
fi

k -n cert-manager create secret generic "$name" --type=kubernetes.io/tls \
  --from-file=tls.crt="$dir/$name.crt" --from-file=tls.key="$dir/$name.key" --from-file=ca.crt="$dir/root.crt"
k apply -f - <<YAML
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: $name
spec:
  ca:
    secretName: $name
YAML
k wait "clusterissuer/$name" --for=condition=Ready --timeout=2m
