#!/usr/bin/env bash
set -euo pipefail
out=/private/tmp/cmtc-issuer-20261024
export DOCKER_HOST=unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
python3 - <<'PY'
import json,subprocess
from pathlib import Path
assert json.loads(Path('/private/tmp/cmtc-issuer-20261024/startup-contract/results.json').read_text())['status']=='passed'
for cluster in ['cmtc-a','cmtc-b']:
 values=json.loads(subprocess.check_output(['helm','--kube-context','kind-'+cluster,'-n','kube-system','get','values','cilium','-o','json']))
 assert values['encryption']['enabled'] is False
PY
for cluster in cmtc-a cmtc-b;do
 kind load image-archive "$out/ztunnel-arm64.tar" --name "$cluster"
done
python3 "$out/check-proxy-on-nodes.py"
for cluster in cmtc-a cmtc-b;do
 helm upgrade cilium /private/tmp/cilium-ztunnel-authorization-runtime/install/kubernetes/cilium --kube-context "kind-$cluster" -n kube-system --reuse-values --atomic --wait --timeout 7m --set encryption.ztunnel.image.override=localhost/cmtc-ztunnel:strict-1db4fb296b --set encryption.ztunnel.image.pullPolicy=IfNotPresent
 kubectl --context "kind-$cluster" -n kube-system rollout status ds/cilium --timeout=5m
 cilium clustermesh status --context "kind-$cluster" --wait --wait-duration 3m > "$out/$cluster-mesh.txt" 2>&1
done
printf '0\n' > "$out/stage.exit"
