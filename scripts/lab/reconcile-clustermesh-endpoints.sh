#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

for tool in docker kind kubectl helm cilium python3; do command -v "$tool" >/dev/null; done
docker info >/dev/null

for cluster in cmtc-a cmtc-b; do
  if ! kind get clusters | grep -qx "$cluster"; then
    echo "Required retained kind cluster $cluster is missing; refusing to create or replace clusters." >&2
    exit 1
  fi
done

chart=${CMTC_CILIUM_CHART_PATH:-}
if [[ -z "$chart" ]]; then
  test -s .tmp/cilium-chart-path || { echo 'Missing .tmp/cilium-chart-path; run the local Cilium preparation first.' >&2; exit 1; }
  chart=$(cat .tmp/cilium-chart-path)
fi
mesh_values=${CMTC_MESH_VALUES_PATH:-.tmp/mesh-values.json}
test -f "$chart/Chart.yaml" || { echo "Cilium chart not found: $chart" >&2; exit 1; }
test -s "$mesh_values" || { echo "Mesh values not found: $mesh_values" >&2; exit 1; }

ips_a=$(python3 scripts/lab/kind-node-ips.py cmtc-a)
ips_b=$(python3 scripts/lab/kind-node-ips.py cmtc-b)
tmp_values=$(mktemp "${mesh_values}.XXXXXX")
trap 'rm -f "$tmp_values"' EXIT

python3 - "$mesh_values" "$tmp_values" "$ips_a" "$ips_b" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
endpoints = {"cmtc-a": json.loads(sys.argv[3]), "cmtc-b": json.loads(sys.argv[4])}
values = json.loads(source.read_text())
mesh = values.get("clustermesh", {})
if mesh.get("apiserver", {}).get("service", {}).get("type") != "NodePort":
    raise SystemExit("expected the retained lab's NodePort ClusterMesh API profile")
config = mesh.get("config", {})
clusters = config.get("clusters")
if config.get("enabled") is not True or not isinstance(clusters, list):
    raise SystemExit("mesh values do not contain enabled explicit ClusterMesh peer configuration")
by_name = {entry.get("name"): entry for entry in clusters}
if set(by_name) != set(endpoints):
    raise SystemExit(f"expected exactly cmtc-a and cmtc-b peers, found {sorted(by_name)}")
for name, addresses in endpoints.items():
    by_name[name]["ips"] = addresses
target.write_text(json.dumps(values, indent=2) + "\n")
for name, addresses in endpoints.items():
    print(f"{name}: {', '.join(addresses)}:32379")
PY

if python3 - "$mesh_values" "$tmp_values" <<'PY'
import json
import pathlib
import sys

def peers(path):
    values = json.loads(pathlib.Path(path).read_text())
    return {peer["name"]: peer["ips"] for peer in values["clustermesh"]["config"]["clusters"]}

raise SystemExit(0 if peers(sys.argv[1]) == peers(sys.argv[2]) else 1)
PY
then
  echo 'ClusterMesh peer endpoints already match the live kind node addresses.'
else
  for cluster in cmtc-a cmtc-b; do
    kubectl --context "kind-$cluster" wait nodes --all --for=condition=Ready --timeout=5m
    kubectl --context "kind-$cluster" wait clusterissuer/cmtc-lab-intermediate --for=condition=Ready --timeout=3m
    kubectl --context "kind-$cluster" -n kube-system wait certificates --all --for=condition=Ready --timeout=3m
  done

  for cluster in cmtc-a cmtc-b; do
    helm upgrade cilium "$chart" --namespace kube-system --kube-context "kind-$cluster" \
      --reuse-values --values "$tmp_values" --wait --timeout 10m
  done
  mv "$tmp_values" "$mesh_values"
  trap - EXIT
fi

for cluster in cmtc-a cmtc-b; do
  cilium clustermesh status --context "kind-$cluster" --wait --wait-duration 10m
done
