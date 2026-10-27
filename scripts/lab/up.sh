#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
image=${CMTC_IMAGE:-cmtc:dev}
node_image=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
mkdir -p .tmp artifacts
for tool in docker kind kubectl helm openssl python3; do command -v "$tool" >/dev/null; done
docker info >/dev/null
# A Colima guest needs a single wall-clock owner before mesh TLS runs on it; a no-op elsewhere.
bash scripts/lab/colima-timekeeping.sh --apply
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
# Mesh PKI (ADR-011, MESH_PKI.md): cert-manager in cmtc-a, the control cluster, mints the 10-year mesh root; its Secret
# is copied to cmtc-b; each cluster signs its own <cluster>-clustermesh-intermediate and <cluster>-spire-intermediate.
# Only the public root certificate is written here, for the trust bundle.
umask 077
pki=$(mktemp -d "$PWD/.tmp/pki.XXXXXX")
echo "$pki" > .tmp/pki-directory
bash scripts/lab/pki/mesh-pki.sh --root-out "$pki/root.crt" cmtc-a cmtc-b
ips_a=$(python3 scripts/lab/kind-node-ips.py cmtc-a)
ips_b=$(python3 scripts/lab/kind-node-ips.py cmtc-b)
ip_a=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])[0])' "$ips_a")
python3 - "$pki/root.crt" "$ips_a" "$ips_b" <<'PY'
import json,pathlib,sys
# A peer's ztunnel-origin-config pins the server certificate's key (spki-sha256), so cert-manager must renew the
# server certificate with the same key; the client certificates keep cert-manager's default (a new key each time).
# Charts before the fork's auto.server.privateKey value ignore it; they also predate the pin.
values={'tls':{'caBundle':{'enabled':True,'name':'cmtc-public-root','key':'ca.crt','useSecret':False,'content':pathlib.Path(sys.argv[1]).read_text()}},'clustermesh':{'useAPIServer':True,'apiserver':{'service':{'type':'NodePort'},'tls':{'auto':{'enabled':True,'method':'certmanager','certValidityDuration':365,'certManagerIssuerRef':{'group':'cert-manager.io','kind':'ClusterIssuer'},'server':{'privateKey':{'rotationPolicy':'Never'}}}}},'config':{'enabled':True,'clusters':[{'name':'cmtc-a','ips':json.loads(sys.argv[2]),'port':32379},{'name':'cmtc-b','ips':json.loads(sys.argv[3]),'port':32379}]}}}
pathlib.Path('.tmp/mesh-values.json').write_text(json.dumps(values))
PY
for cluster in cmtc-a cmtc-b; do
  # Each cluster's leaves are signed by its own intermediate, so a leaf's issuer names the cluster that signed it.
  helm upgrade cilium "$cilium_chart" -f .tmp/cilium-image-values.json -n kube-system --kube-context "kind-$cluster" --reuse-values \
    -f .tmp/mesh-values.json --set "clustermesh.apiserver.tls.auto.certManagerIssuerRef.name=$cluster-clustermesh-intermediate" \
    --wait --timeout 10m
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
