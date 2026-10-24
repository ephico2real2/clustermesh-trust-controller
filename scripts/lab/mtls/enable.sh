#!/usr/bin/env bash
# Enable the locally built SPIRE credential path only in the owned test cluster.
set -euo pipefail
cd "$(dirname "$0")/../../.."
[ "$(cat .tmp/mtls-spike/created-cluster)" = cmtc-mtls ]
export KUBECONFIG=$(cat .tmp/mtls-spike/kubeconfig-path)
agent_image=${CILIUM_MTLS_AGENT_IMAGE:-docker.io/ephico2real2/cilium:spire-spike}
chart=${CILIUM_SOURCE_DIR:?local SPIRE source checkout required}/install/kubernetes/cilium
if [ -n "${CILIUM_MTLS_AGENT_ARCHIVE:-}" ]; then
  kind load image-archive "$CILIUM_MTLS_AGENT_ARCHIVE" --name cmtc-mtls
else
  # Reuse the existing lab-runtime image; new image builds use host Podman.
  kind load docker-image "$agent_image" --name cmtc-mtls
fi
kubectl -n kube-system wait certificaterequest/ztunnel-ads-server --for=condition=Ready --timeout=30s
helm upgrade cilium "$chart" -n kube-system --reuse-values \
  --set image.override="$agent_image" --set image.pullPolicy=IfNotPresent \
  --set encryption.enabled=true --set encryption.type=ztunnel --set encryption.ztunnel.ca.type=spire \
  --set authentication.mutual.spire.enabled=true --set authentication.mutual.spire.trustDomain=cmtc-mtls.test \
  --post-renderer scripts/lab/mtls/spire-upstream.py --wait --timeout 12m
kubectl -n kube-system rollout status ds/cilium --timeout=5m
kubectl -n cilium-spire rollout status statefulset/spire-server --timeout=5m
kubectl -n cilium-spire rollout status ds/spire-agent --timeout=5m
kubectl -n kube-system rollout status ds/ztunnel-cilium --timeout=5m
kubectl get nodes -o wide > artifacts/mtls-spike/nodes.txt
kubectl get pods -A -o wide > artifacts/mtls-spike/pods.txt
kubectl -n kube-system exec ds/cilium -- cilium-dbg version > artifacts/mtls-spike/cilium-version.txt
kubectl -n cilium-spire get certificaterequests -o json > artifacts/mtls-spike/spire-certificate-requests.json
printf 'SPIRE/ztunnel deployed; workload mTLS and negative tests must still pass.\n'
