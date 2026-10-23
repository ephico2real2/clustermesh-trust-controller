#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
hub_ip=${1:?hub node IP required}
for cluster in cmtc-a cmtc-b; do
  python3 scripts/lab/monitoring.py "$cluster" "$hub_ip" > ".tmp/monitoring-$cluster.json"
  kubectl --context "kind-$cluster" apply -f ".tmp/monitoring-$cluster.json"
  kubectl --context "kind-$cluster" -n monitoring rollout status deployment/prometheus --timeout=3m
done
kubectl --context kind-cmtc-a -n monitoring rollout status deployment/grafana --timeout=5m
