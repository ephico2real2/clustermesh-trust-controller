#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p artifacts
for cluster in cmtc-a cmtc-b; do
  context="kind-$cluster"
  kubectl --context "$context" get nodes -o wide > "artifacts/$cluster-nodes.txt" 2>&1 || true
  kubectl --context "$context" get pods -A -o wide > "artifacts/$cluster-pods.txt" 2>&1 || true
  kubectl --context "$context" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{range .status.containerStatuses[*]}{.image}{" "}{.imageID}{" "}{end}{"\n"}{end}' > "artifacts/$cluster-images.txt" 2>&1 || true
  kubectl --context "$context" get nmp -o yaml > "artifacts/$cluster-policies.yaml" 2>&1 || true
  kubectl --context "$context" get events -A --sort-by=.metadata.creationTimestamp > "artifacts/$cluster-events.txt" 2>&1 || true
  kubectl --context "$context" -n cmtc-system logs deployment/cmtc-controller --all-containers > "artifacts/$cluster-controller.log" 2>&1 || true
  kubectl --context "$context" -n cmtc-system logs -l app.kubernetes.io/name=cmtc-node-agent --all-containers --prefix > "artifacts/$cluster-agents.log" 2>&1 || true
  kubectl --context "$context" -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --verbose > "artifacts/$cluster-cilium-status.txt" 2>&1 || true
  cilium clustermesh status --context "$context" > "artifacts/$cluster-mesh.txt" 2>&1 || true
done
git rev-parse HEAD > artifacts/source-commit.txt
# Deliberate allowlist: no Secret resources, kubeconfigs, signing keys or full sysdump.
printf 'CMTC Observe lab: see results.json and screenshots/. Workload mTLS and transport composition remain blocked.\n' > artifacts/README.txt
