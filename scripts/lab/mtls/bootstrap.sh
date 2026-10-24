#!/usr/bin/env bash
# Isolated CMTC-101 fixture: organizational root outside, issuer/ADS keys inside.
set -euo pipefail
cd "$(dirname "$0")/../../.."
cluster=cmtc-mtls
context=kind-$cluster
out=artifacts/mtls-spike
mkdir -p "$out" .tmp/mtls-spike
for tool in kind kubectl helm docker openssl python3; do command -v "$tool" >/dev/null; done
if kind get clusters | grep -qx "$cluster"; then echo "Refusing to replace existing $cluster" >&2; exit 1; fi
export KUBECONFIG=${CMTC_MTLS_KUBECONFIG:-/home/olasumbo.guest/.kube/cmtc-mtls-spike}
fixture_image=${CMTC_MTLS_FIXTURE_IMAGE:-localhost/cmtc:spire-podman}
fixture_archive=${CMTC_MTLS_FIXTURE_ARCHIVE:?build with scripts/lab/mtls/build.sh and supply its image archive}
[ -f "$fixture_archive" ]
# Bootstrap CNI with the qualified fork bundle; enable the new SPIRE agent only
# after cert-manager and its ADS TLS server identity are ready.
python3 scripts/cilium/prepare.py config/cilium-images.lock.json .tmp/mtls-spike/bootstrap-image-values.json
cat > .tmp/mtls-spike/kind.yaml <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
  podSubnet: 10.30.0.0/16
  serviceSubnet: 10.31.0.0/16
nodes:
  - role: control-plane
  - role: worker
YAML
kind create cluster --name "$cluster" --config .tmp/mtls-spike/kind.yaml --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed --wait 0
printf '%s\n' "$cluster" > .tmp/mtls-spike/created-cluster
chart=${CILIUM_SOURCE_DIR:?exact local SPIRE source checkout required}/install/kubernetes/cilium
helm install cilium "$chart" -n kube-system -f .tmp/mtls-spike/bootstrap-image-values.json \
  --set cluster.name="$cluster" --set cluster.id=0 --set ipam.mode=kubernetes \
  --set kubeProxyReplacement=true --set k8sServiceHost="$cluster-control-plane" --set k8sServicePort=6443 \
  --set bpf.masquerade=true --set operator.replicas=1 --set hubble.enabled=false \
  --set encryption.enabled=false --wait --timeout 10m
kubectl wait nodes --all --for=condition=Ready --timeout=5m
helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade --install cert-manager jetstack/cert-manager --version v1.21.1 -n cert-manager --create-namespace --set crds.enabled=true --wait --timeout 5m
kind load image-archive "$fixture_archive" --name "$cluster"
kubectl -n kube-system create serviceaccount lab-identity-init
for ns in cert-manager kube-system; do
  kubectl -n "$ns" apply -f - <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: lab-identity-init}
rules: [{apiGroups: [''], resources: [secrets], verbs: [create]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: lab-identity-init}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: lab-identity-init}
subjects: [{kind: ServiceAccount, name: lab-identity-init, namespace: kube-system}]
YAML
done
kubectl -n kube-system apply -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata: {name: lab-identity-init}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: lab-identity-init
      containers:
        - name: init
          image: $fixture_image
          imagePullPolicy: IfNotPresent
          command: [/lab-identity-init]
          env: [{name: CLUSTER_NAME, value: $cluster}]
YAML
kubectl -n kube-system wait job/lab-identity-init --for=condition=Complete --timeout=2m
kubectl -n kube-system logs job/lab-identity-init > "$out/public-requests.json"
umask 077
pki=$(mktemp -d "$PWD/.tmp/mtls-spike/pki.XXXXXX")
trap 'rm -f "$pki/root.key"' EXIT
python3 - "$out/public-requests.json" "$pki" <<'PY'
import json,pathlib,sys
requests=json.loads(pathlib.Path(sys.argv[1]).read_text())
p=pathlib.Path(sys.argv[2])
(p/'cluster.csr').write_text(requests['clusterIssuerCSR'])
(p/'ads.csr').write_text(requests['adsServerCSR'])
PY
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/root.key"
openssl req -x509 -new -key "$pki/root.key" -out "$pki/root.crt" -days 4 -subj '/CN=CMTC-101 isolated test root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:2' -addext 'keyUsage=critical,keyCertSign,cRLSign'
printf 'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n' > "$pki/issuer.ext"
openssl x509 -req -in "$pki/cluster.csr" -CA "$pki/root.crt" -CAkey "$pki/root.key" -CAcreateserial -out "$pki/cluster.crt" -days 3 -extfile "$pki/issuer.ext"
cat "$pki/cluster.crt" "$pki/root.crt" > "$pki/cluster.chain.crt"
openssl verify -CAfile "$pki/root.crt" "$pki/cluster.crt"
python3 - "$pki" "$out" <<'PY'
import pathlib,sys,json,base64,shutil
p=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2])
# This patch contains public certificates only. No private issuer key leaves its Secret.
(out/'issuer-public-patch.json').write_text(json.dumps({'data':{'tls.crt':base64.b64encode((p/'cluster.chain.crt').read_bytes()).decode()}}))
shutil.copy2(p/'root.crt',out/'root.crt');shutil.copy2(p/'cluster.chain.crt',out/'cluster-issuer-chain.crt')
(out/'ads-certificate-request.json').write_text(json.dumps({'apiVersion':'cert-manager.io/v1','kind':'CertificateRequest','metadata':{'name':'ztunnel-ads-server','namespace':'kube-system'},'spec':{'request':base64.b64encode((p/'ads.csr').read_bytes()).decode(),'duration':'48h','usages':['digital signature','server auth'],'issuerRef':{'name':'cmtc-spike-intermediate','kind':'ClusterIssuer','group':'cert-manager.io'}}}))
PY
kubectl -n cert-manager patch secret cluster-intermediate --type merge --patch-file "$out/issuer-public-patch.json"
kubectl apply -f - <<'YAML'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: cmtc-spike-intermediate}
spec:
  ca: {secretName: cluster-intermediate}
YAML
kubectl wait clusterissuer/cmtc-spike-intermediate --for=condition=Ready --timeout=2m
rm "$pki/root.key"
kubectl apply -f "$out/ads-certificate-request.json"
kubectl -n kube-system wait certificaterequest/ztunnel-ads-server --for=condition=Ready --timeout=2m
kubectl -n kube-system get certificaterequest ztunnel-ads-server -o json > "$out/ads-certificate-response.json"
python3 - "$out" <<'PY'
import pathlib,sys,json,base64
out=pathlib.Path(sys.argv[1]);request=json.loads((out/'ads-certificate-response.json').read_text())
chain=base64.b64decode(request['status']['certificate'])+(out/'cluster-issuer-chain.crt').read_bytes()
(out/'ads-server-chain.crt').write_bytes(chain)
(out/'ads-public-patch.json').write_text(json.dumps({'data':{'bootstrap-root.crt':base64.b64encode(chain).decode()}}))
PY
kubectl -n kube-system patch secret cilium-ztunnel-secrets --type merge --patch-file "$out/ads-public-patch.json"
kubectl -n kube-system delete job/lab-identity-init serviceaccount/lab-identity-init
for ns in cert-manager kube-system; do kubectl -n "$ns" delete rolebinding/lab-identity-init role/lab-identity-init; done
openssl verify -CAfile "$out/root.crt" -untrusted "$out/cluster-issuer-chain.crt" "$out/ads-server-chain.crt"
printf '%s\n' "$KUBECONFIG" > .tmp/mtls-spike/kubeconfig-path
printf 'Bootstrap ready: cluster issuer and ADS leaf key remain in-cluster; protected root key removed.\n'
