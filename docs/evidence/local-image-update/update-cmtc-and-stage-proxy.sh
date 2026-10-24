#!/bin/bash
set -euo pipefail
export DOCKER_HOST=unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
out=/private/tmp/cmtc-rebuild-20261024
for cluster in cmtc-a cmtc-b; do
 context=kind-$cluster
 kind load image-archive "$out/cmtc-arm64.tar" --name "$cluster"
 kubectl --context "$context" -n cmtc-system get deploy/cmtc-controller ds/cmtc-node-agent -o json > "$out/$cluster-cmtc-before.json"
 kubectl --context "$context" -n cmtc-system set image deploy/cmtc-controller controller=localhost/cmtc:observe-85d0cd8acc
 kubectl --context "$context" -n cmtc-system rollout status deploy/cmtc-controller --timeout=3m
 kubectl --context "$context" -n cmtc-system set image ds/cmtc-node-agent agent=localhost/cmtc:observe-85d0cd8acc
 kubectl --context "$context" -n cmtc-system rollout status ds/cmtc-node-agent --timeout=3m
 kubectl --context "$context" -n cmtc-system get pods -o json > "$out/$cluster-cmtc-after.json"
done
