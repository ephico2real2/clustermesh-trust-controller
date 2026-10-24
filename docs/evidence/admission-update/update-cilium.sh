#!/bin/bash
set -euo pipefail
export DOCKER_HOST=unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
out=/private/tmp/cmtc-admission-20261024
chart=/private/tmp/cilium-ztunnel-authorization-runtime/install/kubernetes/cilium
for cluster in cmtc-a cmtc-b; do
 context=kind-$cluster
 kind load image-archive "$out/cilium-arm64.tar" --name "$cluster"
 helm --kube-context "$context" -n kube-system get values cilium -o json > "$out/$cluster-cilium-values-before.json"
 helm upgrade cilium "$chart" --kube-context "$context" -n kube-system --reuse-values --atomic --wait --timeout 7m \
 --set image.override=localhost/cilium:admission-8b01a7c954 --set image.pullPolicy=IfNotPresent \
 --set preflight.image.override=localhost/cilium:admission-8b01a7c954 \
 --set encryption.ztunnel.image.override=localhost/cmtc-ztunnel:strict-8106c02662 --set encryption.ztunnel.image.pullPolicy=IfNotPresent
 kubectl --context "$context" -n kube-system rollout status ds/cilium --timeout=5m
 kubectl --context "$context" wait nodes --all --for=condition=Ready --timeout=3m
 cilium status --context "$context" --wait --wait-duration 3m > "$out/$cluster-cilium-status.txt" 2>&1
 cilium clustermesh status --context "$context" --wait --wait-duration 3m > "$out/$cluster-mesh-after.txt" 2>&1
 kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium -o json > "$out/$cluster-cilium-after.json"
 for pod in $(kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium -o name); do
  kubectl --context "$context" -n kube-system exec "$pod" -- cilium-agent --version | tee -a "$out/$cluster-cilium-node-versions.txt"
 done
 helm --kube-context "$context" -n kube-system get values cilium -o json > "$out/$cluster-cilium-values-after.json"
done
printf '0\n' > "$out/cilium-rollout.exit"
