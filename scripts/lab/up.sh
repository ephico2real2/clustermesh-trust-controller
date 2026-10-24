#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
image=${CMTC_IMAGE:-cmtc:dev}
node_image=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
mkdir -p .tmp artifacts
for tool in docker kind kubectl helm openssl python3; do command -v "$tool" >/dev/null; done
docker info >/dev/null
bash scripts/cilium/prepare.sh
cilium_chart=$(cat .tmp/cilium-chart-path)
for cluster in cmtc-a cmtc-b; do
  if kind get clusters | grep -qx "$cluster"; then echo "Refusing to replace existing $cluster" >&2; exit 1; fi
done
: > .tmp/created-clusters
for cluster in cmtc-a cmtc-b; do
  if [ "$cluster" = cmtc-a ]; then pod=10.10.0.0/16; service=10.11.0.0/16; else pod=10.20.0.0/16; service=10.21.0.0/16; fi
  cat > ".tmp/$cluster.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $cluster
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
  podSubnet: $pod
  serviceSubnet: $service
nodes:
  - role: control-plane
    image: $node_image
  - role: worker
    image: $node_image
EOF
  echo "$cluster" >> .tmp/created-clusters
  kind create cluster --config ".tmp/$cluster.yaml" --wait 0
done
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update
for cluster in cmtc-a cmtc-b; do
  id=1; [ "$cluster" = cmtc-b ] && id=2
  helm install cilium "$cilium_chart" -f .tmp/cilium-image-values.json -n kube-system --kube-context "kind-$cluster" \
    --set "cluster.name=$cluster" --set "cluster.id=$id" --set ipam.mode=kubernetes \
    --set kubeProxyReplacement=true --set "k8sServiceHost=$cluster-control-plane" --set k8sServicePort=6443 \
    --set operator.replicas=1 --set hubble.enabled=false --set encryption.enabled=false \
    --wait --timeout 10m
  kubectl --context "kind-$cluster" wait nodes --all --for=condition=Ready --timeout=5m
  kind load docker-image "$image" --name "$cluster"
  helm upgrade --install cert-manager jetstack/cert-manager --version v1.21.1 --namespace cert-manager --create-namespace \
    --kube-context "kind-$cluster" --set crds.enabled=true --wait --timeout 5m
done
# Disposable test authority: root key remains on this runner, never in a cluster or artifact.
# Each intermediate key is generated inside its own cluster; only CSRs leave it.
umask 077
pki=$(mktemp -d "$PWD/.tmp/pki.XXXXXX")
echo "$pki" > .tmp/pki-directory
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/root.key"
openssl req -x509 -new -key "$pki/root.key" -out "$pki/root.crt" -days 3 -subj '/CN=CMTC disposable lab root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' -addext 'keyUsage=critical,keyCertSign,cRLSign'
for cluster in cmtc-a cmtc-b; do
  kubectl --context "kind-$cluster" -n cert-manager apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: lab-ca-init}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: lab-ca-init}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: lab-ca-init}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: lab-ca-init}
subjects: [{kind: ServiceAccount, name: lab-ca-init, namespace: cert-manager}]
---
apiVersion: batch/v1
kind: Job
metadata: {name: lab-ca-init}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: lab-ca-init
      containers:
        - name: init
          image: $image
          imagePullPolicy: IfNotPresent
          command: [/lab-ca-init]
          env: [{name: CLUSTER_NAME, value: $cluster}]
EOF
  kubectl --context "kind-$cluster" -n cert-manager wait job/lab-ca-init --for=condition=Complete --timeout=2m
  kubectl --context "kind-$cluster" -n cert-manager logs job/lab-ca-init > "$pki/$cluster.csr"
  printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n' > "$pki/intermediate.ext"
  openssl x509 -req -in "$pki/$cluster.csr" -CA "$pki/root.crt" -CAkey "$pki/root.key" -CAcreateserial \
    -out "$pki/$cluster.crt" -days 2 -extfile "$pki/intermediate.ext"
  cat "$pki/$cluster.crt" "$pki/root.crt" > "$pki/$cluster.chain.crt"
  python3 - "$pki/$cluster.chain.crt" > "$pki/public-certificate-patch.json" <<'PY'
import base64,json,pathlib,sys
# Secret.type is immutable. cert-manager's CA issuer consumes tls.crt/tls.key
# from the existing Opaque Secret; only this public chain is added here.
print(json.dumps({'data':{'tls.crt':base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode()}}))
PY
  kubectl --context "kind-$cluster" -n cert-manager patch secret cluster-intermediate --type merge --patch-file "$pki/public-certificate-patch.json"
  kubectl --context "kind-$cluster" -n cert-manager delete job/lab-ca-init rolebinding/lab-ca-init role/lab-ca-init sa/lab-ca-init
  kubectl --context "kind-$cluster" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: cmtc-lab-intermediate}
spec:
  ca: {secretName: cluster-intermediate}
EOF
  kubectl --context "kind-$cluster" wait clusterissuer/cmtc-lab-intermediate --for=condition=Ready --timeout=2m
done
rm "$pki/root.key"
ip_a=$(docker inspect cmtc-a-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
ip_b=$(docker inspect cmtc-b-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
python3 - "$pki/root.crt" "$ip_a" "$ip_b" <<'PY'
import json,pathlib,sys
values={'tls':{'caBundle':{'enabled':True,'name':'cmtc-public-root','key':'ca.crt','useSecret':False,'content':pathlib.Path(sys.argv[1]).read_text()}},'clustermesh':{'useAPIServer':True,'apiserver':{'service':{'type':'NodePort'},'tls':{'auto':{'enabled':True,'method':'certmanager','certValidityDuration':1,'certManagerIssuerRef':{'group':'cert-manager.io','kind':'ClusterIssuer','name':'cmtc-lab-intermediate'}}}},'config':{'enabled':True,'clusters':[{'name':'cmtc-a','ips':[sys.argv[2]],'port':32379},{'name':'cmtc-b','ips':[sys.argv[3]],'port':32379}]}}}
pathlib.Path('.tmp/mesh-values.json').write_text(json.dumps(values))
PY
for cluster in cmtc-a cmtc-b; do
  helm upgrade cilium "$cilium_chart" -f .tmp/cilium-image-values.json -n kube-system --kube-context "kind-$cluster" --reuse-values \
    -f .tmp/mesh-values.json --wait --timeout 10m
  kubectl --context "kind-$cluster" -n kube-system wait certificates --all --for=condition=Ready --timeout=3m
done
for cluster in cmtc-a cmtc-b; do
  cilium clustermesh status --context "kind-$cluster" --wait --wait-duration 10m
  kubectl kustomize config/default | sed "s/CLUSTER_NAME/$cluster/g; s|image: cmtc:dev|image: $image|g" | kubectl --context "kind-$cluster" apply -f -
  kubectl --context "kind-$cluster" wait crd/namespacemtlspolicies.security.cmtc.io --for=condition=Established --timeout=60s
  kubectl --context "kind-$cluster" -n cmtc-system rollout status deployment/cmtc-controller --timeout=3m
  kubectl --context "kind-$cluster" -n cmtc-system rollout status ds/cmtc-node-agent --timeout=3m
  kubectl --context "kind-$cluster" apply -f config/samples/namespace-mtls-policy.yaml
done
python3 scripts/cilium/verify.py
bash scripts/lab/monitoring.sh "$ip_a"
