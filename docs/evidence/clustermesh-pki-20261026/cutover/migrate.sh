#!/usr/bin/env bash
# Move one kube-system Certificate from ClusterIssuer cmtc-lab-intermediate to <cluster>-clustermesh-intermediate.
# The issuerRef change makes cert-manager reissue (measured 2026-10-26: revision +1 in 2 s, key kept under
# rotationPolicy Never). Proves revision +1, Ready at the current generation, the chain to the mesh root.
# Usage: migrate.sh CLUSTER CERTIFICATE ROOT_PEM
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig LC_ALL=C
c=$1 name=$2 root=$3 new=$1-clustermesh-intermediate
K=(kubectl --context "kind-$c" -n kube-system)
uid=$("${K[@]}" get certificate "$name" -o jsonpath='{.metadata.uid}')
rv=$("${K[@]}" get certificate "$name" -o jsonpath='{.metadata.resourceVersion}')
rev0=$("${K[@]}" get certificate "$name" -o jsonpath='{.status.revision}')
secret=$("${K[@]}" get certificate "$name" -o jsonpath='{.spec.secretName}')
[ -n "$uid" ] && [ -n "$rv" ] && [ -n "$rev0" ] && [ -n "$secret" ] || { echo "$c $name: incomplete read" >&2; exit 1; }
spki() { "${K[@]}" get secret "$secret" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1; }
spki0=$(spki)
"${K[@]}" patch certificate "$name" --type json -p "[{\"op\":\"test\",\"path\":\"/metadata/uid\",\"value\":\"$uid\"},{\"op\":\"test\",\"path\":\"/metadata/resourceVersion\",\"value\":\"$rv\"},{\"op\":\"test\",\"path\":\"/spec/issuerRef/name\",\"value\":\"cmtc-lab-intermediate\"},{\"op\":\"replace\",\"path\":\"/spec/issuerRef/name\",\"value\":\"$new\"}]" >/dev/null
rev=$rev0
for _ in $(seq 120); do
  IFS=/ read -r rev ready og gen < <("${K[@]}" get certificate "$name" -o jsonpath='{.status.revision}/{.status.conditions[?(@.type=="Ready")].status}/{.status.conditions[?(@.type=="Ready")].observedGeneration}/{.metadata.generation}{"\n"}')
  [ "$rev" = $((rev0 + 1)) ] && [ "$ready" = True ] && [ "$og" = "$gen" ] && break
  sleep 1
done
[ "$rev" = $((rev0 + 1)) ] && [ "$ready" = True ] || { echo "$c $name: revision $rev ready $ready, expected $((rev0 + 1)) True" >&2; exit 1; }
chain=$(mktemp)
"${K[@]}" get secret "$secret" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$chain"
openssl verify -CAfile "$root" -untrusted "$chain" "$chain" >/dev/null || { echo "$c $name: does not chain to the mesh root" >&2; rm -f "$chain"; exit 1; }
echo "$c $name: issuerRef cmtc-lab-intermediate -> $new; revision $rev0 -> $rev; $(openssl x509 -in "$chain" -noout -issuer); notAfter $(openssl x509 -in "$chain" -noout -enddate | cut -d= -f2); spki ${spki0:0:16} -> $(spki | cut -c1-16)"
rm -f "$chain"
