#!/usr/bin/env bash
# Capture the Cilium datapath's drop events on each node for a fixed time, one file per node, while a probe run goes
# on. Read-only on the cluster: it runs `cilium-dbg monitor` in each node's Cilium agent, which only reads the agent's
# monitor socket, and `timeout` in the agent container stops it, also when this script is interrupted.
#
# `cilium-dbg monitor` prints no time for an event in any output form (pkg/monitor/datapath_drop.go, DumpInfo and
# DumpJSON), so the agent container puts its clock time in front of each line as the line arrives. The monitor
# flushes after each event (pkg/monitor/format/format.go, FormatSample). The text form is captured because it names
# the BPF source file of the drop; the JSON form (-j) gives only the file's numeric ID.
#
# Each output starts with "# coverage <start> <end>", the header convention of extract_ztunnel_logs.sh. The start is
# 1 s after the monitor printed "Press Ctrl-C to quit", which it prints just before it dials the monitor socket
# (cilium-dbg/cmd/monitor.go, runMonitor). The end is when `timeout` stopped the monitor. If the monitor stops early,
# or reports "connection closed" (it then reconnects after 12 s), the coverage ends there and the script exits 1.
#
# Usage: capture_cilium_drops.sh OUT_DIR SECONDS CONTEXT/NODE...
#   capture_cilium_drops.sh <run-dir>/cilium-drops 240 kind-cmtc-a/cmtc-a-control-plane kind-cmtc-a/cmtc-a-worker \
#     kind-cmtc-b/cmtc-b-control-plane kind-cmtc-b/cmtc-b-worker &
#   Start the probes after it prints "capturing", then `wait` for it.
# Environment: KUBECONFIG, the kubeconfig that holds the contexts.
set -euo pipefail
[ $# -ge 3 ] || { sed -n '2,20p' "$0" >&2; exit 2; }
out=$1 seconds=$2; shift 2
# The coverage starts 1 s after the monitor starts, so a shorter capture would cover nothing.
[[ $seconds =~ ^[0-9]+$ ]] && [ "$seconds" -ge 2 ] || { echo "SECONDS must be a whole number, at least 2" >&2; exit 2; }
mkdir -p "$out"

# Runs in the agent container (bash 5: EPOCHREALTIME and printf %(...)T are builtins, so stamping forks nothing).
# shellcheck disable=SC2016  # expanded by the agent container's bash, not here
remote='export TZ=UTC LC_ALL=C
{ timeout "$1" cilium-dbg monitor -n -t drop 2>&1; echo "CMTC_MONITOR_EXIT=$?"; } | while IFS= read -r line; do
  t=$EPOCHREALTIME
  printf -v s "%(%Y-%m-%dT%H:%M:%S)T" "${t%.*}"
  printf "%s.%sZ %s\n" "$s" "${t#*.}" "$line"
  if [ "$line" = "Press Ctrl-C to quit" ]; then
    printf -v s "%(%Y-%m-%dT%H:%M:%S)T" "$(( ${t%.*} + 1 ))"
    printf "CMTC_COVERAGE_START %s.%sZ\n" "$s" "${t#*.}"
  fi
done'

raw=$(mktemp -d)
pids=() nodes=() pods=() contexts=()
trap 'kill ${pids[@]+"${pids[@]}"} 2>/dev/null || true; rm -rf "$raw"' EXIT
for target in "$@"; do
  context=${target%/*} node=${target##*/}
  if [ -z "$context" ] || [ -z "$node" ] || [ "$context" = "$target" ]; then
    echo "$target: expected CONTEXT/NODE" >&2; exit 2
  fi
  pod=$(kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium --field-selector "spec.nodeName=$node" \
    -o jsonpath='{.items[0].metadata.name}')
  [ -n "$pod" ] || { echo "$node: no Cilium agent Pod in $context" >&2; exit 1; }
  kubectl --context "$context" -n kube-system exec "$pod" -c cilium-agent -- bash -c "$remote" bash "$seconds" \
    > "$raw/$node" 2> "$raw/$node.err" &
  pids+=($!) nodes+=("$node") pods+=("$pod") contexts+=("$context")
done

# Report "capturing" only when every coverage has started: 1 s after each monitor is about to dial its socket.
for node in "${nodes[@]}"; do
  for _ in $(seq 100); do grep -q '^CMTC_COVERAGE_START ' "$raw/$node" && break; sleep 0.2; done
  if ! grep -q '^CMTC_COVERAGE_START ' "$raw/$node"; then
    echo "$node: the monitor did not start: $(cat "$raw/$node.err")" >&2; exit 1
  fi
done
sleep 1
echo "capturing drops on ${#nodes[@]} node(s) for ${seconds}s" >&2

failed=0
for i in "${!nodes[@]}"; do
  node=${nodes[$i]}
  wait "${pids[$i]}" || true
  start=$(sed -n 's/^CMTC_COVERAGE_START //p' "$raw/$node" | head -1)
  exit_line=$(grep -E '^[^ ]+ CMTC_MONITOR_EXIT=' "$raw/$node" | tail -1 || true)
  closed=$(grep -E '^[^ ]+ .*connection closed' "$raw/$node" | head -1 | cut -d' ' -f1 || true)
  problem=""
  if [ -z "$exit_line" ]; then
    end=$(grep -v '^CMTC_COVERAGE_START ' "$raw/$node" | tail -1 | cut -d' ' -f1)
    problem="the stream ended before the monitor stopped: $(cat "$raw/$node.err")"
  else
    end=${exit_line%% *}
    [ "${exit_line##*=}" = 124 ] || problem="the monitor exited with ${exit_line##*=} before the timeout"
  fi
  if [ -n "$closed" ] && [[ "$closed" < "$end" ]]; then
    end=$closed problem="the monitor connection closed at $closed"
  fi
  # A monitor that stopped before its coverage started covers nothing: an empty interval, never an inverted one.
  if [[ "$end" < "$start" ]]; then end=$start; fi
  {
    printf '# cilium drop capture: node %s, agent Pod kube-system/%s in %s, cilium-dbg monitor -n -t drop for %ss\n' \
      "$node" "${pods[$i]}" "${contexts[$i]}" "$seconds"
    printf '# each line: the agent container clock (UTC) when the line arrived, then the line of the monitor\n'
    printf '# coverage %s %s\n' "$start" "$end"
    grep -v '^CMTC_COVERAGE_START ' "$raw/$node" || true
  } > "$out/$node.log"
  drops=$(grep -c ' xx drop ' "$out/$node.log" || true)
  lost=$(grep -c ' Lost [0-9]* events' "$out/$node.log" || true)
  echo "$node: $drops drop line(s), $lost lost-event report(s), coverage $start .. $end -> $out/$node.log"
  if [ -n "$problem" ]; then echo "$node: $problem" >&2; failed=1; fi
done
exit "$failed"
