#!/usr/bin/env bash
set -euo pipefail
cd /private/tmp/cmtc-spire-workload-qualification
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
for pod in $(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}'); do
 node=$(kubectl -n kube-system get pod "$pod" -o jsonpath="{.spec.nodeName}")
 docker exec "$node" curl -fsS http://127.0.0.1:15000/config_dump | python3 -c '
import sys,json,pathlib,base64
j=json.load(sys.stdin)
certs=j["certificates"]
assert certs
for c in certs:
 for item in c["certChain"]+c["rootCerts"]:
  pem=base64.b64decode(item["pem"])
  assert b"PRIVATE KEY" not in pem and b"BEGIN CERTIFICATE" in pem
out=pathlib.Path("artifacts/mtls-spike/authenticated-only-f052d127")
(out/(sys.argv[1]+"-public-certificates.json")).write_text(json.dumps({"certificates":certs},indent=2)+"\n")
for c in certs:
 if "/ns/mtls-spike/sa/" not in c["identity"]: continue
 name=c["identity"].rsplit("/",1)[1]
 assert name in {"client","server"},name
 chain=[base64.b64decode(x["pem"]) for x in c["certChain"]]
 (out/(name+"-svid-leaf.crt")).write_bytes(chain[0])
 (out/(name+"-svid-intermediates.crt")).write_bytes(b"".join(chain[1:]))
 print(c["identity"],c["state"],"certificates",len(chain))
' "$pod"
 kubectl -n kube-system logs "$pod" --since=15m > "artifacts/mtls-spike/authenticated-only-f052d127/$pod-agent.log"
done
for name in client server; do
 openssl verify -purpose sslclient -CAfile artifacts/mtls-spike/authenticated-only-f052d127/root.crt -untrusted "artifacts/mtls-spike/authenticated-only-f052d127/$name-svid-intermediates.crt" "artifacts/mtls-spike/authenticated-only-f052d127/$name-svid-leaf.crt"
 openssl verify -purpose sslserver -CAfile artifacts/mtls-spike/authenticated-only-f052d127/root.crt -untrusted "artifacts/mtls-spike/authenticated-only-f052d127/$name-svid-intermediates.crt" "artifacts/mtls-spike/authenticated-only-f052d127/$name-svid-leaf.crt"
 openssl x509 -in "artifacts/mtls-spike/authenticated-only-f052d127/$name-svid-leaf.crt" -noout -subject -issuer -ext subjectAltName
 done
