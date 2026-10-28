#!/usr/bin/env bash
# Capture the Cilium datapath's drop events on each node for a fixed time, one file per node, while a probe run goes
# on. Read-only on the cluster: it runs `cilium-dbg monitor` in each node's Cilium agent, which only reads the agent's
# monitor socket, and `timeout` in the agent container bounds it, also when this script is interrupted.
#
# `cilium-dbg monitor` prints no time for an event in any output form (pkg/monitor/datapath_drop.go, DumpInfo and
# DumpJSON), so the agent container puts its clock time in front of each line as the line arrives. The monitor
# flushes after each event (pkg/monitor/format/format.go, FormatSample). The text form is captured because it names
# the BPF source file of the drop; the JSON form (-j) gives only the file's numeric ID.
#
# Each output starts with "# coverage <start> <end>", the header convention of extract_ztunnel_logs.sh. The start is
# 1 s after the monitor printed "Press Ctrl-C to quit", which it prints just before it dials the monitor socket
# (cilium-dbg/cmd/monitor.go, runMonitor). The end is when `timeout` stopped the monitor. If the monitor stops early,
# reports "connection closed" (it then reconnects after 12 s), or the capture is interrupted, the coverage ends there,
# the log says why, and the script exits non-zero (1, or 128+signal).
#
# Failure tolerance. Every line is written to OUT_DIR/.raw/ as it arrives, so no ending loses what was received. The
# agent container also sends a heartbeat with its clock time each second without a line; the newest heartbeat is the
# last time the stream is proven alive, on the same clock as the drops. An interrupted or cut stream therefore covers
# up to its last heartbeat, never past it. After SIGKILL, when no trap can run, `--finalize OUT_DIR` writes the logs
# from the raw lines.
#
# Agent-side cleanup. The container runtime keeps accepting the agent side's writes after the client is gone, so no
# SIGPIPE stops it (measured on the labs, 2026-10-26). The exec therefore holds stdin open (`-i`, a FIFO opened
# read-write, so only the stream's end can close it). When the client goes, stdin reaches EOF and the agent side stops
# the monitor at once; `timeout` remains the bound if even that fails.
#
# Usage: capture_cilium_drops.sh OUT_DIR SECONDS CONTEXT/NODE...
#        capture_cilium_drops.sh --finalize OUT_DIR
#   capture_cilium_drops.sh <run-dir>/cilium-drops 240 kind-cmtc-a/cmtc-a-control-plane kind-cmtc-a/cmtc-a-worker \
#     kind-cmtc-b/cmtc-b-control-plane kind-cmtc-b/cmtc-b-worker &
#   Start the probes after it prints "capturing", then `wait` for it. A background job of a script ignores SIGINT, so
#   stop it early with SIGTERM. OUT_DIR must not hold an earlier capture.
# Environment: KUBECONFIG, the kubeconfig that holds the contexts.
set -euo pipefail
usage() { sed -n '2,34p' "$0" >&2; exit 2; }

# Write NODE's log from its raw lines. REASON, when given, says why the capture ended early. The log is written to a
# temporary name and renamed, so a log is complete or absent. Returns 1 when the coverage ended early.
finalize() {
  local node=$1 reason=${2:-} r=$raw/$1 pod context seconds start end exit_line closed alive problem=""
  IFS=$'\t' read -r pod context seconds < "$r.meta"
  [ -e "$r" ] || : > "$r"
  start=$(sed -n 's/^CMTC_COVERAGE_START //p' "$r" | head -1)
  exit_line=$(grep -E '^[^ ]+ CMTC_MONITOR_EXIT=' "$r" | tail -1 || true)
  closed=$(grep -E '^[^ ]+ .*connection closed' "$r" | head -1 | cut -d' ' -f1 || true)
  # The newest stamp of a line or a heartbeat. Stamps are fixed-width ISO times, so they sort as text.
  alive=$(sed -n -E 's/^CMTC_ALIVE //p; s/^([0-9]{4}-[0-9T:.-]+Z) .*/\1/p' "$r" | sort | tail -1)
  if [ -z "$start" ]; then
    # Nothing was covered. Keep what arrived for diagnosis, but write no log that would claim a coverage.
    mv "$r" "$out/$node.not-started.raw"
    [ ! -s "$r.err" ] || mv "$r.err" "$out/$node.not-started.err"
    rm -f "$r.meta" "$r.err" "$r.stdin"
    echo "$node: the monitor did not start${reason:+ ($reason)}; nothing covered" >&2
    return 1
  fi
  if [ -n "$exit_line" ]; then
    end=${exit_line%% *}
    [ "${exit_line##*=}" = 124 ] || problem="the monitor exited with ${exit_line##*=} before the timeout"
  else
    end=$alive
    problem=${reason:-"the stream ended before the monitor stopped: $(tr '\n' ' ' < "$r.err")"}
    problem="$problem; the coverage ends at the last line or heartbeat"
  fi
  if [ -n "$closed" ] && [[ "$closed" < "$end" ]]; then
    end=$closed problem="the monitor connection closed at $closed"
  fi
  # A monitor that stopped before its coverage started covers nothing: an empty interval, never an inverted one.
  if [[ "$end" < "$start" ]]; then end=$start; fi
  {
    printf '# cilium drop capture: node %s, agent Pod kube-system/%s in %s, cilium-dbg monitor -n -t drop for %ss\n' \
      "$node" "$pod" "$context" "$seconds"
    printf '# each line: the agent container clock (UTC) when the line arrived, then the line of the monitor\n'
    printf '# coverage %s %s\n' "$start" "$end"
    [ -z "$problem" ] || printf '# ended early: %s\n' "$problem"
    grep -v -E '^CMTC_(COVERAGE_START|ALIVE) ' "$r" || true
  } > "$out/.$node.log.tmp"
  mv "$out/.$node.log.tmp" "$out/$node.log"
  # The meta file goes first: from now on the node counts as written, and the rest only repeats its log.
  rm -f "$r.meta" "$r" "$r.err" "$r.stdin"
  local drops lost
  drops=$(grep -c ' xx drop ' "$out/$node.log" || true)
  lost=$(grep -c ' Lost [0-9]* events' "$out/$node.log" || true)
  echo "$node: $drops drop line(s), $lost lost-event report(s), coverage $start .. $end -> $out/$node.log"
  if [ -n "$problem" ]; then echo "$node: $problem" >&2; return 1; fi
}

if [ "${1:-}" = --finalize ]; then
  [ $# -eq 2 ] || usage
  out=$2 raw=$2/.raw failed=0
  [ -d "$raw" ] || { echo "$out: no unfinished capture" >&2; exit 2; }
  # A SIGKILL of the script alone leaves its streams running, and finalizing would cut a file that is still written.
  # A live stream appends a heartbeat at least once a second, so a raw file that grows is still written.
  declare -A size
  for f in "$raw"/*.meta; do [ -e "$f" ] && size[$f]=$(wc -c < "${f%.meta}" 2> /dev/null || echo 0); done
  sleep 2.5
  for f in "${!size[@]}"; do
    if [ "$(wc -c < "${f%.meta}" 2> /dev/null || echo 0)" != "${size[$f]}" ]; then
      echo "$out: the stream of $(basename "$f" .meta) is still written; stop it, then --finalize again" >&2; exit 2
    fi
  done
  for meta in "$raw"/*.meta; do
    [ -e "$meta" ] || continue
    node=$(basename "$meta" .meta)
    finalize "$node" "the capture was killed before it finished" || failed=1
  done
  rmdir "$raw" 2>/dev/null || true
  exit "$failed"
fi

[ $# -ge 3 ] || usage
out=$1 seconds=$2; shift 2
# The coverage starts 1 s after the monitor starts, so a shorter capture would cover nothing.
[[ $seconds =~ ^[0-9]+$ ]] && [ "$seconds" -ge 2 ] || { echo "SECONDS must be a whole number, at least 2" >&2; exit 2; }
raw=$out/.raw
mkdir -p "$out"
if [ -e "$raw" ] || compgen -G "$out/*.log" > /dev/null; then
  echo "$out already holds a capture; give a new directory (or --finalize an unfinished one)" >&2; exit 2
fi
mkdir "$raw"

# Runs in the agent container (bash 5: EPOCHREALTIME and printf %(...)T are builtins, so stamping forks nothing).
# `read -t 1` returns >128 on a timeout and keeps the partial line it read, which the next read completes. The
# watchdog reads stdin through fd 3, because a background job's own stdin is /dev/null.
# shellcheck disable=SC2016  # expanded by the agent container's bash, not here
remote='export TZ=UTC LC_ALL=C
stamp() { t=$EPOCHREALTIME; printf -v s "%(%Y-%m-%dT%H:%M:%S)T" "${t%.*}"; }
{ timeout "$1" cilium-dbg monitor -n -t drop 2>&1 & m=$!
  { while IFS= read -r _; do :; done; kill -TERM "$m" 2> /dev/null; } <&3 &
  w=$!
  wait "$m"; rc=$?
  kill "$w" 2> /dev/null
  echo "CMTC_MONITOR_EXIT=$rc"; } 3<&0 | {
  buf=""
  while :; do
    if IFS= read -r -t 1 part; then
      line=$buf$part buf=""
      stamp
      printf "%s.%sZ %s\n" "$s" "${t#*.}" "$line"
      if [ "$line" = "Press Ctrl-C to quit" ]; then
        printf -v s "%(%Y-%m-%dT%H:%M:%S)T" "$(( ${t%.*} + 1 ))"
        printf "CMTC_COVERAGE_START %s.%sZ\n" "$s" "${t#*.}"
      fi
    elif [ $? -gt 128 ]; then
      buf+=$part
      stamp
      printf "CMTC_ALIVE %s.%sZ\n" "$s" "${t#*.}"
    else
      if [ -n "$buf$part" ]; then stamp; printf "%s.%sZ %s\n" "$s" "${t#*.}" "$buf$part"; fi
      break
    fi
  done
}'

pids=() nodes=() done_nodes=() reason=""
# On any ending, stop the local streams and write every node's log from what arrived.
finish() {
  local rc=$1 node
  trap - EXIT INT TERM HUP
  set +e
  [ ${#pids[@]} -eq 0 ] || { kill "${pids[@]}" 2> /dev/null; wait "${pids[@]}" 2> /dev/null; }
  for node in ${nodes[@]+"${nodes[@]}"}; do
    [[ " ${done_nodes[*]-} " == *" $node "* ]] && continue
    # finalize removes the meta file once the log is in place: no meta means this node is already written.
    [ -e "$raw/$node.meta" ] || continue
    finalize "$node" "${reason:-the capture script stopped (exit $rc)}" || [ "$rc" -ne 0 ] || rc=1
  done
  rmdir "$raw" 2> /dev/null
  exit "$rc"
}
trap 'finish $?' EXIT
trap 'reason="interrupted by SIGINT"; exit 130' INT
trap 'reason="interrupted by SIGTERM"; exit 143' TERM
trap 'reason="interrupted by SIGHUP"; exit 129' HUP

for target in "$@"; do
  context=${target%/*} node=${target##*/}
  if [ -z "$context" ] || [ -z "$node" ] || [ "$context" = "$target" ]; then
    echo "$target: expected CONTEXT/NODE" >&2; exit 2
  fi
  pod=$(kubectl --context "$context" -n kube-system get pods -l k8s-app=cilium --field-selector "spec.nodeName=$node" \
    -o jsonpath='{.items[0].metadata.name}')
  [ -n "$pod" ] || { echo "$node: no Cilium agent Pod in $context" >&2; exit 1; }
  printf '%s\t%s\t%s\n' "$pod" "$context" "$seconds" > "$raw/$node.meta"
  mkfifo "$raw/$node.stdin"
  kubectl --context "$context" -n kube-system exec -i "$pod" -c cilium-agent -- bash -c "$remote" bash "$seconds" \
    <> "$raw/$node.stdin" > "$raw/$node" 2> "$raw/$node.err" &
  pids+=($!) nodes+=("$node")
done

# Report "capturing" only when every coverage has started: 1 s after each monitor is about to dial its socket.
for node in "${nodes[@]}"; do
  for _ in $(seq 100); do grep -q '^CMTC_COVERAGE_START ' "$raw/$node" && break; sleep 0.2; done
  if ! grep -q '^CMTC_COVERAGE_START ' "$raw/$node"; then
    reason="the monitor did not start: $(tr '\n' ' ' < "$raw/$node.err")"; exit 1
  fi
done
sleep 1
echo "capturing drops on ${#nodes[@]} node(s) for ${seconds}s" >&2

failed=0
for i in "${!nodes[@]}"; do
  wait "${pids[$i]}" || true
  finalize "${nodes[$i]}" || failed=1
  done_nodes+=("${nodes[$i]}")
done
pids=()
exit "$failed"
