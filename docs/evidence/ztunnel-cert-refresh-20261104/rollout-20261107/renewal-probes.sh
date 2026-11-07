#!/bin/bash
# Same-cluster probes of one cluster, repeated past two certificate lives, with the worker's certificate cache read each round.
# Usage: renewal-probes.sh CLUSTER OUT ROUNDS INTERVAL   (run from the repository root)
set -u
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
C=$1; R=$2; ROUNDS=$3; GAP=$4
STATE=docs/evidence/local-activation-20261025/live-tests
RUNNER=scripts/evidence/live_mtls_fixture.py
POD=$(kubectl --context kind-$C -n kube-system get pods -l app.kubernetes.io/name=ztunnel-cilium --field-selector spec.nodeName=$C-worker -o jsonpath='{.items[0].metadata.name}')
echo "worker ztunnel: $POD" | tee -a "$R/rounds.txt"
PORT=$((15100 + RANDOM % 400))
kubectl --context kind-$C -n kube-system port-forward "pod/$POD" "$PORT:15000" > "$R/port-forward.txt" 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT; sleep 3
for i in $(seq 1 "$ROUNDS"); do
  echo "=== round $i $(date -u +%FT%TZ)" | tee -a "$R/rounds.txt"
  for scope in same crossnode name; do
    python3 "$RUNNER" --cluster "$C" --out "$STATE" --scope $scope probe --execute > "$R/round-$i-$scope.txt" 2>&1; echo "$scope exit=$?" | tee -a "$R/rounds.txt"
  done
  for scope in negative negative-name; do
    python3 "$RUNNER" --cluster "$C" --out "$STATE" --scope $scope --expect deny probe --execute > "$R/round-$i-$scope.txt" 2>&1; echo "$scope(deny) exit=$?" | tee -a "$R/rounds.txt"
  done
  curl -s --max-time 5 "http://127.0.0.1:$PORT/config_dump" > "$R/round-$i-config-dump.json" || echo "config_dump read failed" | tee -a "$R/rounds.txt"
  python3 - "$R/round-$i-config-dump.json" <<'PY' | tee -a "$R/rounds.txt"
import json, sys
d = json.load(open(sys.argv[1]))
for c in d.get('certificates', []):
    certs = c.get('certChain') or []
    print(' ', c.get('identity', '').split('/')[-1], c.get('state'), (certs[0].get('validFrom'), certs[0].get('expirationTime')) if certs else '')
PY
  [ "$i" -lt "$ROUNDS" ] && sleep "$GAP"
done
echo "DONE $(date -u +%FT%TZ)" | tee -a "$R/rounds.txt"
