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
  for ns in payments-alpha orders-delta legacy-payments cmtc-platform-fixture; do kubectl --context "$context" create namespace "$ns"; done
  kubectl --context "$context" label ns payments-alpha legacy-payments cmtc-platform-fixture company.net/lob=alpha
  kubectl --context "$context" label ns orders-delta company.net/mnemonic=delta
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
  kubectl --context "$context" create namespace mesh-example
  kubectl --context "$context" -n mesh-example apply -f examples/apps/clustermesh/global-service.yaml
  kubectl --context "$context" label ns cf2cnp-lab mesh-example company.net/lob=alpha
  wait_status "$context" '{.status.selected}' 4
 done
# Reused demo 07: a remote-only backend makes the service result unambiguous.
kubectl --context kind-cmtc-b -n mesh-example apply -f examples/apps/clustermesh/backend-poc2.yaml
kubectl --context kind-cmtc-b -n mesh-example rollout status deployment/rebel-base --timeout=3m
kubectl --context kind-cmtc-a -n mesh-example run mesh-client --restart=Never --image=curlimages/curl:8.14.1 --command -- sleep 3600
kubectl --context kind-cmtc-a -n mesh-example wait pod/mesh-client --for=condition=Ready --timeout=3m
success=0
for _ in $(seq 1 60); do
  response=$(kubectl --context kind-cmtc-a -n mesh-example exec mesh-client -- curl -fsS --max-time 5 http://rebel-base/ || true)
  if printf '%s' "$response" | grep -q '"cluster": "poc2"'; then success=1;break;fi
  sleep 2
 done
[ "$success" = 1 ] || { echo 'FAIL: remote imported Global Service unavailable' >&2;exit 1; }
printf '%s\n' "$response" > artifacts/global-service-response.json
python3 - <<'PY'
import json,pathlib
result={'policyReconciliation':'passed','exclusionAndPlatformPrecedence':'passed','uidRecreation':'passed','policyConflicts':'passed','strictModeRejected':'passed','readOnlyNamespaceRBAC':'passed','remoteGlobalService':'passed','reusedShopAllowedAndDenied':'passed','workloadMTLS':'blocked: Cilium integration pending','layeredEncryption':'blocked: composition pending'}
pathlib.Path('artifacts/results.json').write_text(json.dumps(result,indent=2)+'\n')
PY
echo 'PASS: deployed CMTC observation API, controller, node agents and baseline ClusterMesh assertions'
