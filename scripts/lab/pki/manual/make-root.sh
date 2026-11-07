#!/usr/bin/env bash
# Creates the mesh root CA with openssl: DIR/root.key and DIR/root.crt (ECDSA P-256, 10 years).
# Keep DIR offline and out of git. The root key is never imported into a cluster.
# Usage: make-root.sh DIR [PREFIX]    PREFIX names the root "<PREFIX> mesh root CA" (default cmtc)
set -euo pipefail
dir=${1:?usage: make-root.sh DIR [PREFIX]}
prefix=${2:-cmtc}
cnf="$(dirname "$0")/ca.cnf"

if [ -e "$dir/root.key" ] || [ -e "$dir/root.crt" ]; then
  echo "$dir already holds a root; refusing to replace it" >&2
  exit 1
fi
mkdir -p "$dir"
umask 077
# A failed step leaves nothing behind, so the next run is not refused.
trap 'rm -f "$dir/root.key" "$dir/root.crt"' ERR

# named_curve: LibreSSL otherwise writes explicit curve parameters, which OpenSSL 3, Go and rustls reject.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$dir/root.key"
openssl req -x509 -new -key "$dir/root.key" -subj "/CN=$prefix mesh root CA" -days 3650 -sha256 \
  -config "$cnf" -extensions root -out "$dir/root.crt"

echo "created $dir/root.crt:"
openssl x509 -in "$dir/root.crt" -noout -subject -enddate -fingerprint -sha256
