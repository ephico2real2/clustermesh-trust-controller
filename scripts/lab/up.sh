#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Registry first: the clusters pull the CMTC image by digest, never a side-loaded copy. The repository holds no CMTC
# image lock (.github/workflows/images.yaml keeps images.lock.json as a workflow artifact), so the caller names it:
# a published image, or a local build pushed with scripts/lab/local-registry.sh (make lab-up does that).
: "${CMTC_IMAGE:?set CMTC_IMAGE to ghcr.io/ephico2real2/cmtc@sha256:<digest> or localhost:5001/cmtc@sha256:<digest>}"
image=$CMTC_IMAGE
node_image=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
mkdir -p .tmp artifacts
for tool in docker kind kubectl helm openssl python3 cilium; do
  command -v "$tool" >/dev/null || { echo "up.sh needs $tool on PATH" >&2; exit 1; }
done
# The lab helpers that read YAML need PyYAML: the repository venv has it (docs/development/LAB_SCRIPTS.md); without a
# venv, python3 must have it (macOS's python3 does not).
py=python3; [ -x venv/bin/python ] && py=venv/bin/python
"$py" -c 'import yaml' 2>/dev/null || { echo "up.sh needs PyYAML for $py (create the repository venv)" >&2; exit 1; }
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
  # An image built on this machine comes from the local registry (scripts/lab/local-registry.sh push).
  case $image in
    localhost:5001/*) bash scripts/lab/local-registry.sh nodes "$cluster" ;;
  esac
done
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update
for cluster in cmtc-a cmtc-b; do
  id=1; [ "$cluster" = cmtc-b ] && id=2
  # Hubble waits for the second upgrade below: its certificates come from cert-manager, which does not exist yet.
  helm install cilium "$cilium_chart" -f .tmp/cilium-image-values.json -n kube-system --kube-context "kind-$cluster" \
    --set "cluster.name=$cluster" --set "cluster.id=$id" --set ipam.mode=kubernetes \
    --set kubeProxyReplacement=true --set "k8sServiceHost=$cluster-control-plane" --set k8sServicePort=6443 \
    --set operator.replicas=1 --set hubble.enabled=false --set encryption.enabled=false \
    --wait --timeout 10m
  kubectl --context "kind-$cluster" wait nodes --all --for=condition=Ready --timeout=5m
  # cert-manager's built-in approver approves every request (MESH_PKI.md, Approval).
  helm upgrade --install cert-manager jetstack/cert-manager --version v1.21.1 --namespace cert-manager --create-namespace \
    --kube-context "kind-$cluster" --set crds.enabled=true --wait --timeout 5m
done
# Mesh PKI (ADR-011, MESH_PKI.md): cert-manager in cmtc-a, the control cluster, mints the 10-year mesh root; its Secret
# is copied to cmtc-b; each cluster signs its own <cluster>-clustermesh-intermediate. The CMTC chart adds
# <cluster>-spire-intermediate below.
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
  # The shared values (config/lab/cilium/base.yaml: Hubble on, with cert-manager TLS) and the cluster's constants
  # (scripts/lab/cilium_cluster_values.py: each cluster's leaves, ClusterMesh and Hubble, are signed by its own
  # intermediate; the Relay and the UI run in the control cluster only). The instance values stay in mesh-values.json.
  # The ztunnel constants wait for the strict layer: the chart refuses them while encryption is off.
  "$py" scripts/lab/cilium_cluster_values.py config/lab/environments/cmtc.yaml "$cluster" ".tmp/cilium-constants-$cluster.json" \
    --constants-only --without-ztunnel
  helm upgrade cilium "$cilium_chart" -f config/lab/cilium/base.yaml -f .tmp/cilium-image-values.json -n kube-system \
    --kube-context "kind-$cluster" --reuse-values -f .tmp/mesh-values.json -f ".tmp/cilium-constants-$cluster.json" \
    --wait --timeout 10m
  kubectl --context "kind-$cluster" -n kube-system wait certificates --all --for=condition=Ready --timeout=3m
done
# trust-manager first: the CMTC chart's Bundle needs its CRD. Installed without app.targetNamespaces, so a namespace that
# opts in later (label trust=enabled) gets the mesh root ConfigMap without a reinstall (MESH_PKI.md, Trust bundle).
for cluster in cmtc-a cmtc-b; do
  helm upgrade --install trust-manager oci://quay.io/jetstack/charts/trust-manager --version v0.25.0 -n cert-manager \
    --kube-context "kind-$cluster" -f config/lab/trust-manager/values.yaml --wait --timeout 5m
done
# The CMTC chart owns the cluster's SPIFFE trust (trust.*): <cluster>-spire-intermediate, signed by the mesh root, and the
# Bundle cmtc-mesh-root. cmtc-system and cilium-spire opt in through their own manifests; kube-system (Cilium, ztunnel)
# has no manifest of ours, so it is labelled here.
case $image in
  *@sha256:*) image_values=(--set "image.repository=${image%@*}" --set "image.digest=${image#*@}") ;;
  *) image_values=(--set "image.repository=${image%:*}" --set "image.tag=${image##*:}") ;;
esac
for cluster in cmtc-a cmtc-b; do
  cilium clustermesh status --context "kind-$cluster" --wait --wait-duration 10m
  kubectl --context "kind-$cluster" label namespace kube-system trust=enabled --overwrite
  # Helm stores the release in cmtc-system, so the namespace exists, with the chart's labels, before the install.
  kubectl --context "kind-$cluster" create namespace cmtc-system --dry-run=client -o yaml | kubectl --context "kind-$cluster" apply -f -
  kubectl --context "kind-$cluster" label namespace cmtc-system security.cmtc.io/platform-protected=true trust=enabled --overwrite
  helm upgrade --install cmtc charts/cmtc -n cmtc-system --kube-context "kind-$cluster" --set "clusterName=$cluster" \
    "${image_values[@]}" --set namespace.create=false --set trust.enabled=true --wait --timeout 5m
  kubectl --context "kind-$cluster" wait crd/namespacemtlspolicies.security.cmtc.io --for=condition=Established --timeout=60s
  kubectl --context "kind-$cluster" -n cert-manager wait "certificate/$cluster-spire-intermediate" --for=condition=Ready --timeout=3m
  kubectl --context "kind-$cluster" wait bundle/cmtc-mesh-root --for=condition=Synced --timeout=2m
  kubectl --context "kind-$cluster" apply -f config/samples/namespace-mtls-policy.yaml
done
python3 scripts/cilium/verify.py
bash scripts/lab/monitoring.sh "$ip_a"
