#!/usr/bin/env bash
# Meshed mTLS matrix after the gen-2 re-bootstrap, per docs/evidence/g1-destination-sources/PROVE_MTLS_FROM_ZTUNNEL_LOGS.md.
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
R=$1
RUNNER=/private/tmp/cmtc-opus-final-20261025/review/live_mtls_fixture_runner.py
NODES=(cmtc-a-control-plane cmtc-a-worker cmtc-b-control-plane cmtc-b-worker)
scripts/evidence/capture_cilium_drops.sh "$R/cilium-drops" 240 \
  kind-cmtc-a/cmtc-a-control-plane kind-cmtc-a/cmtc-a-worker \
  kind-cmtc-b/cmtc-b-control-plane kind-cmtc-b/cmtc-b-worker > "$R/capture.txt" 2>&1 &
CAP=$!
# A background job of a script ignores SIGINT; forward an interrupt so the capture writes what it has.
trap 'kill -TERM $CAP 2> /dev/null; wait $CAP; exit 130' INT TERM
until grep -q 'capturing drops on 4 node' "$R/capture.txt"; do kill -0 $CAP; sleep 1; done
# Probe times are on the host clock, log lines on the node clock: bound node minus host before and after the probes.
scripts/evidence/node_clock_offset.py --out "$R/node-clock-before.json" "${NODES[@]}" 2>> "$R/node-clock.txt"
START_S=$(date -u +%s); START=$(date -u -r "$START_S" +%FT%TZ)
echo "probes start $START" | tee "$R/window.txt"
# The runner's --out is the fixture state (namespace UID pins, registration ledger); it writes each probe file there.
STATE=docs/evidence/local-activation-20261025/live-tests
touch "$R/.probes-start"
for c in cmtc-a cmtc-b; do
  for scope in same crossnode crosscluster global; do
    python3 "$RUNNER" --cluster $c --out "$STATE" --scope $scope probe --execute >> "$R/probe-$c.txt" 2>&1 || echo "probe $c $scope exit $?" | tee -a "$R/window.txt"
  done
  python3 "$RUNNER" --cluster $c --out "$STATE" --scope negative --expect deny probe --execute >> "$R/probe-$c.txt" 2>&1 || echo "probe $c negative exit $?" | tee -a "$R/window.txt"
done
mkdir -p "$R/probes"
find "$STATE" -maxdepth 1 -name '*-probe-*.json' -newer "$R/.probes-start" -exec cp -p {} "$R/probes/" \;
END_S=$(date -u +%s); END=$(date -u -r "$END_S" +%FT%TZ)
scripts/evidence/node_clock_offset.py --out "$R/node-clock-after.json" "${NODES[@]}" 2>> "$R/node-clock.txt"
echo "probes end $END" | tee -a "$R/window.txt"
for c in cmtc-a cmtc-b; do for ns in cmtc-live-mtls cmtc-live-mtls-unauth; do
  kubectl --context kind-$c get pods -n $ns --no-headers \
    -o custom-columns=NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,SA:.spec.serviceAccountName,UID:.metadata.uid \
    | sed "s/^/$c $ns /"
done; done > "$R/fixture-pods.txt"
# The capture writes its files when its monitors stop, so wait for it; never kill it.
wait $CAP || echo "drop capture exit $?" | tee -a "$R/window.txt"
# A node's coverage reaches END only once it has logged a later line; retry until every node has.
for _ in $(seq 20); do
  # The join reads each probe from 3 s before its time (--window); whole seconds truncate, so keep a 10 s margin.
  scripts/evidence/extract_ztunnel_logs.sh "$R/ztunnel-access" "$(date -u -r $((START_S - 10)) +%FT%TZ)" \
    "$(date -u -r $((END_S + 10)) +%FT%TZ)" \
    'cmtc-live-mtls|src\.addr=10\.(10|20)\.[01]\.' "${NODES[@]}" && break
  sleep 15
done
OFFSET=$(scripts/evidence/node_clock_offset.py --union "$R/node-clock-before.json" "$R/node-clock-after.json")
echo "node minus host $OFFSET s" | tee -a "$R/window.txt"
scripts/evidence/join_probes_to_ztunnel.py "$R/probes" --pods "$R/fixture-pods.txt" \
  --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \
  --logs "$R"/ztunnel-access/*.log --drops "$R"/cilium-drops/*.log \
  --node-clock-offset "$OFFSET" --out "$R/join.json" --rows --color never > "$R/join.txt" || echo "join exit $?" | tee -a "$R/window.txt"
echo "matrix finished"
