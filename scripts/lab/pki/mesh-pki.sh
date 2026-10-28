#!/usr/bin/env bash
# Build the mesh PKI of ADR-011 on any set of clusters that run cert-manager:
#   1. cert-manager in the control cluster mints a 10-year root (${PREFIX}-mesh-root-ca);
#   2. its Secret, key included, is copied to every member cluster, as Cilium's Cluster Mesh guide copies cilium-ca;
#   3. every cluster signs its own ClusterMesh intermediate from that root, with a key made in-cluster;
#   4. each intermediate backs a ClusterIssuer of the same name, which signs that cluster's leaves.
# Every per-cluster CA is named after its cluster (<cluster>-clustermesh-intermediate, and
# <cluster>-ingress-intermediate for the cluster's Ingress certificates), so a leaf's issuerRef names the
# cluster that signed it, and one cluster's CA can be renewed or revoked alone. The SPIRE intermediate
# (<cluster>-spire-intermediate) and the mesh root ConfigMap are owned by the CMTC chart (charts/cmtc, trust.*).
# The public root certificate is written to --root-out for the clusters' trust bundle (Cilium tls.caBundle).
#
# A cluster is NAME or NAME=CONTEXT. NAME is the cluster name in object names; CONTEXT is its kubeconfig context,
# by default --context-prefix followed by NAME (kind-NAME).
#
# Idempotent: a rerun applies the same objects. It refuses, and changes nothing more, when a cluster already holds a
# different root, or an issuer of these names that points at another Secret. No private key is printed or written to
# disk: the root Secret moves between clusters through a pipe, and only public certificates are read.
#
# Usage: mesh-pki.sh [--prefix NAME] [--context-prefix PREFIX] --root-out FILE CONTROL [MEMBER...]
#        mesh-pki.sh [--prefix NAME] --render CLUSTER    print the manifests for one cluster
set -euo pipefail
cd "$(dirname "$0")/../../.."
prefix=cmtc context_prefix=kind- root_out="" render=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix=$2; shift 2;;
    --context-prefix) context_prefix=$2; shift 2;;
    --root-out) root_out=$2; shift 2;;
    --render) render=$2; shift 2;;
    -h|--help) sed -n '2,22p' "$0"; exit 0;;
    -*) echo "unknown option $1" >&2; exit 2;;
    *) break;;
  esac
done
dns_label='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
names=() contexts=()
for arg in ${render:+"$render"} "$@"; do
  name=${arg%%=*}
  [[ $name =~ $dns_label ]] || { echo "not a DNS label: $name" >&2; exit 2; }
  names+=("$name")
  if [[ $arg == *=* ]]; then contexts+=("${arg#*=}"); else contexts+=("$context_prefix$name"); fi
done
[[ $prefix =~ $dns_label ]] || { echo "not a DNS label: $prefix" >&2; exit 2; }

# Substitutes ${PREFIX} and ${CLUSTER}; any other placeholder is an error.
render_file() {
  python3 - "$1" "$prefix" "$2" <<'PY'
import pathlib,string,sys
print(string.Template(pathlib.Path(sys.argv[1]).read_text()).substitute(PREFIX=sys.argv[2],CLUSTER=sys.argv[3]))
PY
}
manifests() { # cluster, is-control
  [ "$2" = 1 ] && { render_file config/lab-pki/root-control.yaml "$1"; echo ---; }
  render_file config/lab-pki/clustermesh.yaml "$1"; echo ---
  render_file config/lab-pki/clustermesh-leaf-issuer.yaml "$1"; echo ---
  render_file config/lab-pki/ingress.yaml "$1"
}
if [ -n "$render" ]; then manifests "$render" 1; exit 0; fi
[ ${#names[@]} -ge 1 ] && [ -n "$root_out" ] || { echo "usage: mesh-pki.sh [options] --root-out FILE CONTROL [MEMBER...]" >&2; exit 2; }

k() { local c=$1; shift; kubectl --context "$c" "$@"; }
log() { printf '%s mesh-pki: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
cert_of() { k "$1" -n cert-manager get secret "$2" -o jsonpath='{.data.tls\.crt}' | base64 -d; }
der_sha() { openssl x509 -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1; }
ready() { k "$1" "${@:2}" --for=condition=Ready --timeout=3m >/dev/null; }
cas_of() { # cluster name: its intermediates, each also the name of its Secret and ClusterIssuer
  echo "$1-clustermesh-intermediate"
  echo "$1-ingress-intermediate"
}

# Refuse an issuer that already signs from another Secret: repointing a live issuer is a planned cutover.
check_issuer() { # context, issuer, expected secret
  local current
  current=$(k "$1" get clusterissuer "$2" -o jsonpath='{.spec.ca.secretName}' 2>/dev/null || true)
  if [ -n "$current" ] && [ "$current" != "$3" ]; then
    echo "$1: ClusterIssuer $2 signs from Secret $current, not $3; refusing to repoint it" >&2
    exit 1
  fi
}

# The unknown-root and repoint refusals are checked before the first write. A member holding a different root can only
# be compared once the control root exists, so that refusal leaves the control root in place (an idempotent object).
control=${contexts[0]}
root_secret=$prefix-mesh-root-ca
if k "$control" -n cert-manager get secret "$root_secret" >/dev/null 2>&1 \
   && ! k "$control" -n cert-manager get certificate "$root_secret" >/dev/null 2>&1; then
  echo "$control: Secret $root_secret exists without its Certificate; refusing to adopt an unknown root" >&2; exit 1
fi
for i in "${!names[@]}"; do
  check_issuer "${contexts[$i]}" "$prefix-mesh-root" "$root_secret"
  for ca in $(cas_of "${names[$i]}"); do check_issuer "${contexts[$i]}" "$ca" "$ca"; done
done

# 1. The root, minted by cert-manager in the control cluster.
render_file config/lab-pki/root-control.yaml "${names[0]}" | k "$control" apply -f - >/dev/null
ready "$control" -n cert-manager wait "certificate/$root_secret"
root_sha=$(cert_of "$control" "$root_secret" | der_sha)
log "${names[0]}: root $root_secret ready, certificate sha256 $root_sha"

# 2. The copy, key included, to every member. Only a matching root is accepted on a rerun.
for i in "${!names[@]}"; do
  member=${contexts[$i]}
  [ "$member" != "$control" ] || continue
  if k "$member" -n cert-manager get secret "$root_secret" >/dev/null 2>&1; then
    have=$(cert_of "$member" "$root_secret" | der_sha)
    [ "$have" = "$root_sha" ] || { echo "$member: Secret $root_secret holds root $have, not $root_sha; refusing" >&2; exit 1; }
    log "${names[$i]}: root copy present"
    continue
  fi
  k "$control" -n cert-manager get secret "$root_secret" -o json | python3 -c '
import json,sys
s=json.load(sys.stdin)
# Identity, ownership and resourceVersion stay behind; only the key pair and its type move.
json.dump({"apiVersion":"v1","kind":"Secret","metadata":{"name":s["metadata"]["name"],"namespace":"cert-manager"},"type":s["type"],"data":s["data"]},sys.stdout)' \
    | k "$member" create -f - >/dev/null
  [ "$(cert_of "$member" "$root_secret" | der_sha)" = "$root_sha" ] || { echo "$member: copied root differs" >&2; exit 1; }
  log "${names[$i]}: root copied"
done

# 3. and 4. Every cluster: its intermediates and their issuers.
for i in "${!names[@]}"; do
  name=${names[$i]} ctx=${contexts[$i]}
  manifests "$name" 0 | k "$ctx" apply -f - >/dev/null
  ready "$ctx" wait "clusterissuer/$prefix-mesh-root"
  cas=()
  for ca in $(cas_of "$name"); do
    ready "$ctx" -n cert-manager wait "certificate/$ca"
    openssl verify -CAfile <(cert_of "$ctx" "$root_secret") <(cert_of "$ctx" "$ca") >/dev/null \
      || { echo "$name: $ca does not chain to the mesh root" >&2; exit 1; }
    ready "$ctx" wait "clusterissuer/$ca"
    cas+=("$ca")
  done
  log "$name: ${cas[*]} chain to the root; their issuers are ready"
done

cert_of "$control" "$root_secret" > "$root_out"
log "root certificate written to $root_out"
