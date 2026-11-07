#!/usr/bin/env bash
# Does a Certificate's issuerRef change make cert-manager reissue, and does rotationPolicy Never keep the key?
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig LC_ALL=C
K=(kubectl --context kind-cmtc-a -n cert-manager)
OL=/private/tmp/cmtc-opus-final-20261025/review/issuer-rotation/live/operations.log
sk() { "${K[@]}" get secret issuerref-test -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -c1-16; }
state() { echo "rev $("${K[@]}" get certificate issuerref-test -o jsonpath='{.status.revision}') spki $(sk) $("${K[@]}" get secret issuerref-test -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -issuer)"; }
echo "$(date -u +%FT%TZ) claude b744973a: test: does an issuerRef change reissue? throwaway cert-manager/issuerref-test (cmtc-a)" >> $OL
trap '"${K[@]}" delete certificate issuerref-test --ignore-not-found >/dev/null; "${K[@]}" delete secret issuerref-test --ignore-not-found >/dev/null; echo "$(date -u +%FT%TZ) claude b744973a: test end: issuerref-test deleted" >> $OL' EXIT
"${K[@]}" apply -f - >/dev/null <<'Y'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: issuerref-test}
spec:
  secretName: issuerref-test
  commonName: issuerref test
  duration: 1h
  privateKey: {algorithm: ECDSA, size: 256, rotationPolicy: Never}
  issuerRef: {name: cmtc-lab-intermediate, kind: ClusterIssuer, group: cert-manager.io}
Y
"${K[@]}" wait certificate/issuerref-test --for=condition=Ready --timeout=1m >/dev/null
echo "before: $(state)"
"${K[@]}" patch certificate issuerref-test --type merge -p '{"spec":{"issuerRef":{"name":"cmtc-a-clustermesh-intermediate"}}}' >/dev/null
r=1; for i in $(seq 30); do r=$("${K[@]}" get certificate issuerref-test -o jsonpath='{.status.revision}'); [ "$r" = 2 ] && break; sleep 1; done
sleep 2; echo "after ${i}s: $(state)"
