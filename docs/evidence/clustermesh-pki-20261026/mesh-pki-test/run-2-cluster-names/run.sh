#!/usr/bin/env bash
# Functional test of scripts/lab/pki/mesh-pki.sh on the live labs, under isolated names (prefix pkitest,
# clusters pkitest-a/pkitest-b on contexts kind-cmtc-a/kind-cmtc-b). Fails on the first wrong result.
set -euo pipefail
cd /Users/olasumbo/gitRepos/clustermest-trust-controller
S=$(dirname "$0"); P=pkitest A=kind-cmtc-a B=kind-cmtc-b
run() { bash scripts/lab/pki/mesh-pki.sh --prefix $P --root-out "$S/root.crt" pkitest-a=$A pkitest-b=$B; }
count() { for c in $A $B; do kubectl --context $c get certificate,secret,issuer,clusterissuer -A --no-headers 2>/dev/null; done | grep -c "$P" || true; }
fail() { echo "FAIL: $*"; exit 1; }

echo "A1 refuse an issuer that points at another Secret"
kubectl --context $B apply -f - >/dev/null <<Y
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: pkitest-b-spire-intermediate}
spec: {ca: {secretName: somebody-else}}
Y
run > "$S/A1.out" 2>&1 && fail "A1 ran"; cat "$S/A1.out"
[ "$(count)" = 1 ] || fail "A1 wrote objects"; kubectl --context $B delete clusterissuer pkitest-b-spire-intermediate >/dev/null

echo "A2 refuse an unknown root Secret on the control cluster"
kubectl --context $A -n cert-manager create secret generic pkitest-mesh-root-ca --from-literal=x=y >/dev/null
run > "$S/A2.out" 2>&1 && fail "A2 ran"; cat "$S/A2.out"
[ "$(count)" = 1 ] || fail "A2 wrote objects"; kubectl --context $A -n cert-manager delete secret pkitest-mesh-root-ca >/dev/null

echo "B1 create"; s=$(date +%s); run; echo "took $(( $(date +%s)-s ))s"
echo "B2 rerun"; run
openssl x509 -in "$S/root.crt" -noout -subject -enddate -ext basicConstraints
for c in a b; do
  ctx=kind-cmtc-$c
  for ca in clustermesh spire; do
    kubectl --context $ctx -n cert-manager get secret pkitest-$c-$ca-intermediate -o jsonpath='{.data.tls\.crt}' | base64 -d \
      | openssl x509 -noout -subject -issuer -enddate -ext basicConstraints | tr '\n' ' '; echo
  done
done

echo "B3 a leaf from each cluster's ClusterMesh issuer verifies against the root alone, in both clusters"
for c in a b; do
  kubectl --context kind-cmtc-$c apply -f - >/dev/null <<Y
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: pkitest-leaf, namespace: cert-manager}
spec:
  secretName: pkitest-leaf
  commonName: pkitest-$c leaf
  duration: 1h
  privateKey: {algorithm: ECDSA, size: 256}
  issuerRef: {name: pkitest-$c-clustermesh-intermediate, kind: ClusterIssuer, group: cert-manager.io}
Y
  kubectl --context kind-cmtc-$c -n cert-manager wait certificate/pkitest-leaf --for=condition=Ready --timeout=2m >/dev/null
  kubectl --context kind-cmtc-$c -n cert-manager get secret pkitest-leaf -o jsonpath='{.data.tls\.crt}' | base64 -d > "$S/leaf-$c.pem"
  echo "leaf-$c: $(grep -c 'BEGIN CERT' "$S/leaf-$c.pem") certs in tls.crt; $(openssl x509 -in "$S/leaf-$c.pem" -noout -issuer)"
done
for c in a b; do for at in a b; do
  kubectl --context kind-cmtc-$at -n cert-manager get secret pkitest-mesh-root-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > "$S/root-at-$at.pem"
  openssl verify -CAfile "$S/root-at-$at.pem" -untrusted "$S/leaf-$c.pem" "$S/leaf-$c.pem" >/dev/null || fail "leaf-$c vs root at $at"
  echo "leaf-$c verifies against the root held by pkitest-$at"
done; done

echo "B4 SPIRE depth: an isCA certificate from the SPIRE issuer (SPIRE's own CA), then a leaf below it"
kubectl --context $A apply -f - >/dev/null <<Y
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: pkitest-spire-ca, namespace: cert-manager}
spec:
  isCA: true
  secretName: pkitest-spire-ca
  commonName: pkitest-a SPIRE X509 CA (test)
  duration: 24h
  privateKey: {algorithm: ECDSA, size: 256}
  issuerRef: {name: pkitest-a-spire-intermediate, kind: ClusterIssuer, group: cert-manager.io}
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: pkitest-spire-ca, namespace: cert-manager}
spec: {ca: {secretName: pkitest-spire-ca}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: pkitest-svid, namespace: cert-manager}
spec:
  secretName: pkitest-svid
  uris: [spiffe://pkitest-a.mesh.example/test]
  duration: 1h
  privateKey: {algorithm: ECDSA, size: 256}
  issuerRef: {name: pkitest-spire-ca, kind: Issuer, group: cert-manager.io}
Y
kubectl --context $A -n cert-manager wait certificate/pkitest-spire-ca certificate/pkitest-svid --for=condition=Ready --timeout=2m >/dev/null
kubectl --context $A -n cert-manager get secret pkitest-svid -o jsonpath='{.data.tls\.crt}' | base64 -d > "$S/svid.pem"
echo "svid tls.crt: $(grep -c 'BEGIN CERT' "$S/svid.pem") certs"
openssl verify -CAfile "$S/root-at-b.pem" -untrusted "$S/svid.pem" "$S/svid.pem" || fail "svid chain"
echo "B5 issuance count per cluster CA (sum of Certificate status.revision by issuerRef)"
for c in $A $B; do kubectl --context $c get certificates -A -o json | python3 -c '
import json,sys,collections
n=collections.Counter()
for c in json.load(sys.stdin)["items"]: n[c["spec"]["issuerRef"]["name"]]+=c.get("status",{}).get("revision",0)
print(sys.argv[1],dict(n))' $c; done
echo PASS
