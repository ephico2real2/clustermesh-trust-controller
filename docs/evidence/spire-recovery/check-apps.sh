#!/bin/bash
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
assert_backend() {
  local case_name=$1 context=$2 target=$3 expected=$4 expected_pod=${5:-} response
  response=$(kubectl --context "$context" -n mesh-example exec mesh-client -- \
    curl -fsS --max-time 5 --dump-header /dev/stderr "http://$target/" \
    2> "/private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-$case_name.headers")
  printf '%s\n' "$response" > "/private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-$case_name.json"
  printf '%s' "$response" | grep -Fq "\"cluster\": \"$expected\"" || {
    echo "FAIL: $case_name served an unexpected backend: $response" >&2; exit 1;
  }
  if [ -n "$expected_pod" ] && ! grep -iFq "X-CMTC-Pod: $expected_pod" "/private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-$case_name.headers"; then
    echo "FAIL: $case_name did not identify the intended Pod $expected_pod" >&2; exit 1
  fi
  echo "PASS $case_name: $target returned the $expected backend${expected_pod:+ / $expected_pod}"
}

# Require one ready backend per node, rather than silently testing two
# replicas placed on the same worker. Keep the exact Pod/Node/IP inventory.
: > /private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-backends.tsv
for cluster in cmtc-a cmtc-b; do
  kubectl --context "kind-$cluster" -n mesh-example get pods -l "name=rebel-base,mesh.cmtc.io/cluster=$cluster" -o json > "/private/tmp/cmtc-spire-recovery-20261024/apps/$cluster-backends.json"
  python3 - "$cluster" "/private/tmp/cmtc-spire-recovery-20261024/apps/$cluster-backends.json" >> /private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-backends.tsv <<'PY_TOPOLOGY'
import json,sys
cluster=sys.argv[1]
pods=[p for p in json.load(open(sys.argv[2]))['items'] if not p['metadata'].get('deletionTimestamp')]
assert len(pods)==2, (cluster,'expected two backends',len(pods))
assert len({p['spec']['nodeName'] for p in pods})==2, (cluster,'backend replicas must occupy both nodes')
for index,p in enumerate(sorted(pods,key=lambda p:p['spec']['nodeName'])):
    assert p['status']['phase']=='Running' and all(c['ready'] for c in p['status']['containerStatuses']), p['metadata']['name']
    ip=p['status']['podIP'];assert ip
    print(cluster,p['spec']['nodeName'],p['metadata']['name'],ip,int(index==0),sep='\t')
PY_TOPOLOGY
 done

for port in 80 8080 31337; do
  for direction in a-to-a a-to-b b-to-b b-to-a; do
    case "$direction" in
      a-to-a) context=kind-cmtc-a; service=rebel-base-cmtc-a; expected=cmtc-a ;;
      a-to-b) context=kind-cmtc-a; service=rebel-base-cmtc-b; expected=cmtc-b ;;
      b-to-b) context=kind-cmtc-b; service=rebel-base-cmtc-b; expected=cmtc-b ;;
      b-to-a) context=kind-cmtc-b; service=rebel-base-cmtc-a; expected=cmtc-a ;;
    esac
    assert_backend "$direction-service-$port" "$context" "$service:$port" "$expected"
  done
done
# Both clients contact every local and remote backend on every app port.
# This covers local same/different-node paths and both remote destination nodes.
while IFS=$'\t' read -r target_cluster node pod ip first; do
  for source_cluster in cmtc-a cmtc-b; do
    direction="${source_cluster#cmtc-}-to-${target_cluster#cmtc-}"
    for port in 80 8080 31337; do
      case_name="$direction-podip-$node-$port"
      assert_backend "$case_name" "kind-$source_cluster" "$ip:$port" "$target_cluster" "$pod"
      if [ "$source_cluster" != "$target_cluster" ] && [ "$first" = 1 ]; then
        # Preserve the previous artifact names as aliases of this run's first
        # remote Pod checks; no stale earlier-run response is reused.
        cp "/private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-$case_name.json" "/private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-$direction-podip-$port.json"
      fi
    done
  done
done < /private/tmp/cmtc-spire-recovery-20261024/apps/clustermesh-backends.tsv
