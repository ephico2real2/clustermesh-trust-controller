#!/usr/bin/env bash
set -euo pipefail
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
cd /private/tmp/cmtc-spire-workload-qualification
mkdir -p artifacts/mtls-spike/authenticated-only-deploy
kind load image-archive /private/tmp/cmtc-authentication-agent-podman.tar --name cmtc-mtls
helm history cilium -n kube-system -o json > artifacts/mtls-spike/authenticated-only-deploy/helm-before.json
helm upgrade cilium /private/tmp/cilium-ztunnel-authorization-runtime/install/kubernetes/cilium -n kube-system --reuse-values \
 --set image.override=localhost/cilium:require-mtls --set image.pullPolicy=IfNotPresent \
 --set encryption.ztunnel.requireMtls=true \
 --post-renderer scripts/lab/mtls/spire-upstream.py --wait --timeout 5m
kubectl -n kube-system rollout status ds/cilium --timeout=2m
kubectl -n kube-system get cm cilium-config -o json > artifacts/mtls-spike/authenticated-only-deploy/cilium-config.json
for pod in $(kubectl -n kube-system get pods -l k8s-app=cilium -o jsonpath='{.items[*].metadata.name}'); do
 kubectl -n kube-system exec "$pod" -- /usr/bin/cilium-agent --version | tee "artifacts/mtls-spike/authenticated-only-deploy/$pod-version.txt"
 kubectl -n kube-system logs "$pod" > "artifacts/mtls-spike/authenticated-only-deploy/$pod.log"
 grep -F 'mtls-policy-published' "artifacts/mtls-spike/authenticated-only-deploy/$pod.log"
done
