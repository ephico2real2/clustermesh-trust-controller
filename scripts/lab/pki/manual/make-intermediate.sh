#!/usr/bin/env bash
# Creates one cluster's intermediate CA, signed by the root that make-root.sh made (ECDSA P-256, 3 years):
#   DIR/<CLUSTER>-<KIND>-intermediate.key and .crt
# KIND is clustermesh (signs Cilium ClusterMesh and ztunnel leaves) or spire (signs SPIRE's X509 CA).
# Usage: make-intermediate.sh DIR CLUSTER KIND
set -euo pipefail
dir=${1:?usage: make-intermediate.sh DIR CLUSTER KIND}
cluster=${2:?usage: make-intermediate.sh DIR CLUSTER KIND}
kind=${3:?usage: make-intermediate.sh DIR CLUSTER KIND}
cnf="$(dirname "$0")/ca.cnf"

case $kind in
  clustermesh) cn="$cluster ClusterMesh intermediate CA" ;;
  spire) cn="$cluster SPIRE intermediate CA" ;;
  *) echo "KIND must be clustermesh or spire, not $kind" >&2; exit 2 ;;
esac
name="$cluster-$kind-intermediate"
if [ ! -e "$dir/root.key" ]; then
  echo "$dir/root.key not found; run make-root.sh first" >&2
  exit 1
fi
if [ -e "$dir/$name.key" ] || [ -e "$dir/$name.crt" ]; then
  echo "$dir/$name already exists; refusing to replace it" >&2
  exit 1
fi
umask 077
# A failed step leaves nothing behind, so the next run is not refused.
trap 'rm -f "$dir/$name.key" "$dir/$name.csr" "$dir/$name.crt"' ERR

# named_curve: LibreSSL otherwise writes explicit curve parameters, which OpenSSL 3, Go and rustls reject.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$dir/$name.key"
openssl req -new -key "$dir/$name.key" -subj "/CN=$cn" -config "$cnf" -out "$dir/$name.csr"
# A random 128-bit serial, so no serial file has to be kept next to the root.
openssl x509 -req -in "$dir/$name.csr" -CA "$dir/root.crt" -CAkey "$dir/root.key" \
  -set_serial "0x$(openssl rand -hex 16)" -days 1095 -sha256 -extfile "$cnf" -extensions "$kind" -out "$dir/$name.crt"
rm "$dir/$name.csr"

openssl verify -CAfile "$dir/root.crt" "$dir/$name.crt"
openssl x509 -in "$dir/$name.crt" -noout -subject -issuer -enddate
