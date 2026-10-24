#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p artifacts
wait_status() {
  local context=$1 expression=$2 expected=$3 actual=''
  for _ in $(seq 1 60); do
    actual=$(kubectl --context "$context" get nmp cluster-default -o "jsonpath=$expression")
    [ "$actual" = "$expected" ] && return 0
    sleep 2
  done
  echo "FAIL $context $expression expected=$expected got=$actual" >&2
  return 1
}
for cluster in cmtc-a cmtc-b; do
  context="kind-$cluster"
  for ns in payments-alpha orders-delta legacy-payments cmtc-platform-fixture; do
    kubectl --context "$context" create namespace "$ns" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  done
  # These are test-owned namespaces. Remove only selector labels left by an
  # earlier run so the initial selected-count assertion is repeatable.
  for ns in cf2cnp-lab mesh-example; do
    if kubectl --context "$context" get namespace "$ns" >/dev/null 2>&1; then
      for selector in company.net/lob company.net/mnemonic; do
        value=$(kubectl --context "$context" get namespace "$ns" -o json | python3 -c \
          'import json,sys; print(json.load(sys.stdin).get("metadata",{}).get("labels",{}).get(sys.argv[1],""))' "$selector")
        [ -z "$value" ] || kubectl --context "$context" label namespace "$ns" "$selector-"
      done
    fi
  done
  kubectl --context "$context" label --overwrite ns payments-alpha legacy-payments cmtc-platform-fixture company.net/lob=alpha
  kubectl --context "$context" label --overwrite ns orders-delta company.net/mnemonic=delta
  wait_status "$context" '{.status.selected}' 2
  wait_status "$context" '{.status.excluded}' 1
  wait_status "$context" '{.status.conditions[?(@.type=="EnforcementVerified")].status}' Unknown
  [ "$(kubectl --context "$context" get ns -l io.cilium/mtls-enabled=true -o name | wc -l | tr -d ' ')" = 0 ]
  # Strict is an unimplemented API contract and must fail server-side validation.
  echo "NEGATIVE TEST $cluster: the API must reject unsupported Strict mode; this rejection is expected"
  strict_error="artifacts/$cluster-strict-rejection.txt"
  if sed 's/mode: Observe/mode: Strict/' config/samples/namespace-mtls-policy.yaml | kubectl --context "$context" apply --dry-run=server -f - 2> "$strict_error"; then
    echo 'FAIL: API accepted unimplemented Strict mode' >&2; exit 1
  fi
  if ! grep -Fq 'spec.enforcement.mode: Unsupported value: "Strict"' "$strict_error" || ! grep -Fq 'supported values: "Observe"' "$strict_error"; then
    cat "$strict_error" >&2
    echo 'FAIL: Strict request failed for an unexpected reason' >&2;exit 1
  fi
  echo "PASS $cluster: API rejected unsupported Strict mode as expected (full response: $strict_error)"
  kubectl --context "$context" label ns payments-alpha company.net/lob=beta --overwrite
  wait_status "$context" '{.status.selected}' 1
  kubectl --context "$context" delete ns payments-alpha --wait=true
  kubectl --context "$context" create ns payments-alpha
  wait_status "$context" '{.status.selected}' 1
  kubectl --context "$context" label ns payments-alpha company.net/lob=alpha
  wait_status "$context" '{.status.selected}' 2
  sed 's/name: cluster-default/name: conflicting-policy/' config/samples/namespace-mtls-policy.yaml | kubectl --context "$context" apply -f -
  wait_status "$context" '{.status.conditions[?(@.type=="EvaluationReady")].reason}' PolicyConflict
  wait_status "$context" '{.status.selected}' 0
  kubectl --context "$context" delete nmp conflicting-policy
  wait_status "$context" '{.status.conditions[?(@.type=="EvaluationReady")].status}' True
  wait_status "$context" '{.status.selected}' 2
  if kubectl --context "$context" auth can-i patch namespaces --as=system:serviceaccount:cmtc-system:cmtc-controller; then echo 'FAIL: controller can mutate namespaces' >&2;exit 1;fi
  if kubectl --context "$context" auth can-i get secrets -n cert-manager --as=system:serviceaccount:cmtc-system:cmtc-controller; then echo 'FAIL: controller can read issuer keys' >&2;exit 1;fi
done
# Reused demo 26: actual allowed/denied application traffic on each cluster.
for cluster in cmtc-a cmtc-b; do
  context="kind-$cluster"
  kubectl --context "$context" apply -f examples/apps/shop
  kubectl --context "$context" -n cf2cnp-lab rollout status deployment/shop --timeout=3m
  kubectl --context "$context" -n cf2cnp-lab wait pod/pos pod/stranger --for=condition=Ready --timeout=3m
  shop_ip=$(kubectl --context "$context" -n cf2cnp-lab get svc shop -o jsonpath='{.spec.clusterIP}')
  allowed=0
  for _ in $(seq 1 30); do
    if kubectl --context "$context" -n cf2cnp-lab exec pos -- wget -qO- -T 3 "http://$shop_ip/" > "artifacts/$cluster-shop-allowed.html"; then allowed=1;break;fi
    sleep 2
  done
  [ "$allowed" = 1 ] || { echo 'FAIL: intended POS caller denied' >&2;exit 1; }
  denied=0
  for _ in $(seq 1 30); do
    if ! kubectl --context "$context" -n cf2cnp-lab exec stranger -- wget -qO- -T 3 "http://$shop_ip/" > "artifacts/$cluster-shop-stranger.txt" 2>&1; then denied=1;break;fi
    sleep 2
  done
  [ "$denied" = 1 ] || { echo 'FAIL: stranger reached shop' >&2;exit 1; }
  kubectl --context "$context" create namespace mesh-example --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml
  kubectl --context "$context" label ns cf2cnp-lab mesh-example company.net/lob=alpha
  wait_status "$context" '{.status.selected}' 4
 done
# Reused demo 07: both clusters publish an app, and the two directional global
# services target only the backend in the opposite cluster.
kubectl --context kind-cmtc-a -n mesh-example apply -f examples/apps/clustermesh/backend-poc1.yaml
kubectl --context kind-cmtc-b -n mesh-example apply -f examples/apps/clustermesh/backend-poc2.yaml
kubectl --context kind-cmtc-a -n mesh-example rollout status deployment/rebel-base --timeout=3m
kubectl --context kind-cmtc-b -n mesh-example rollout status deployment/rebel-base --timeout=3m
for cluster in cmtc-a cmtc-b; do
  kubectl --context "kind-$cluster" -n mesh-example delete pod mesh-client --ignore-not-found --wait=true
  kubectl --context "kind-$cluster" -n mesh-example apply -f examples/apps/clustermesh/client.yaml
  kubectl --context "kind-$cluster" -n mesh-example wait pod/mesh-client --for=condition=Ready --timeout=3m
done
assert_backend() {
  local case_name=$1 context=$2 target=$3 expected=$4 expected_pod=${5:-} response
  response=$(kubectl --context "$context" -n mesh-example exec mesh-client -- \
    curl -fsS --max-time 5 --dump-header /dev/stderr "http://$target/" \
    2> "artifacts/clustermesh-$case_name.headers")
  printf '%s\n' "$response" > "artifacts/clustermesh-$case_name.json"
  printf '%s' "$response" | grep -Fq "\"cluster\": \"$expected\"" || {
    echo "FAIL: $case_name served an unexpected backend: $response" >&2; exit 1;
  }
  if [ -n "$expected_pod" ] && ! grep -iFq "X-CMTC-Pod: $expected_pod" "artifacts/clustermesh-$case_name.headers"; then
    echo "FAIL: $case_name did not identify the intended Pod $expected_pod" >&2; exit 1
  fi
  echo "PASS $case_name: $target returned the $expected backend${expected_pod:+ / $expected_pod}"
}

# Require one ready backend per node, rather than silently testing two
# replicas placed on the same worker. Keep the exact Pod/Node/IP inventory.
: > artifacts/clustermesh-backends.tsv
for cluster in cmtc-a cmtc-b; do
  kubectl --context "kind-$cluster" -n mesh-example get pods -l "name=rebel-base,mesh.cmtc.io/cluster=$cluster" -o json > "artifacts/$cluster-backends.json"
  python3 - "$cluster" "artifacts/$cluster-backends.json" >> artifacts/clustermesh-backends.tsv <<'PY_TOPOLOGY'
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
        cp "artifacts/clustermesh-$case_name.json" "artifacts/clustermesh-$direction-podip-$port.json"
      fi
    done
  done
done < artifacts/clustermesh-backends.tsv
python3 - <<'PY'
import json,pathlib
result={'policyReconciliation':'passed','exclusionAndPlatformPrecedence':'passed','uidRecreation':'passed','policyConflicts':'passed','strictModeRejected':'passed','readOnlyNamespaceRBAC':'passed','reusedShopAllowedAndDenied':'passed','applicationPorts':[80,8080,31337],'pathChecks':36,'backendTopology':'one replica on each node in each cluster','bidirectionalGlobalService':['cmtc-a-to-cmtc-a','cmtc-a-to-cmtc-b','cmtc-b-to-cmtc-b','cmtc-b-to-cmtc-a'],'bidirectionalPodIP':['cmtc-a-to-cmtc-b','cmtc-b-to-cmtc-a'],'workloadMTLS':'blocked: the Observe profile does not enable ztunnel/SPIRE','layeredEncryption':'blocked: composition pending'}
pathlib.Path('artifacts/results.json').write_text(json.dumps(result,indent=2)+'\n')
PY
echo 'PASS: deployed CMTC observation API, controller, node agents and baseline ClusterMesh assertions'
