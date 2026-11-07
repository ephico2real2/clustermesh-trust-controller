#!/usr/bin/env bash
# Copy each kind node's ztunnel log for a time window into one file per node, keeping only the lines that name the
# given namespace or Pod addresses. Read-only on the cluster.
#
# `kubectl logs` returns only the current log file. After kubelet rotates a busy ztunnel log (10 MiB by default)
# the earlier lines are only in the node's /var/log/pods files, so this reads those, oldest first.
#
# Each output starts with "# coverage <start> <end>". The filter drops lines, so the first and last kept lines do not
# show which times the file covers; join_probes_to_ztunnel.py relies on this header before it counts a missing line
# as evidence.
#
# Usage: extract_ztunnel_logs.sh OUT_DIR START END MATCH_REGEX NODE...
#   extract_ztunnel_logs.sh docs/evidence/run/ztunnel-access 2026-10-25T23:00:00Z 2026-10-25T23:13:00Z \
#     'cmtc-live-mtls|src\.addr=10\.(10|20)\.[01]\.' cmtc-a-control-plane cmtc-a-worker cmtc-b-control-plane cmtc-b-worker
# Environment: DOCKER_CONTEXT (default colima-cmtc-cilium), the Docker context that runs the kind nodes.
set -euo pipefail
# Byte semantics for sed, awk, grep and sort on both GNU (Linux) and BSD (macOS): a log line need not be UTF-8.
export LC_ALL=C
[ $# -ge 5 ] || { sed -n '2,15p' "$0" >&2; exit 2; }
out=$1 start=$2 end=$3 match=$4; shift 4
context=${DOCKER_CONTEXT:-colima-cmtc-cilium}
mkdir -p "$out"
for node in "$@"; do
  dir=$(docker --context "$context" exec "$node" sh -c 'ls -d /var/log/pods/kube-system_ztunnel-cilium-*/*' | tail -1)
  [ -n "$dir" ] || { echo "$node: no ztunnel-cilium Pod log directory" >&2; exit 1; }
  # The kubelet names each rotated file 0.log.<rotation time> and gzips all but the newest, so the oldest-first order
  # is the name order with the live 0.log last (mtimes are compression times and can tie), and .gz files are inflated.
  files=$(docker --context "$context" exec "$node" sh -c "ls $dir/0.log.* 2>/dev/null | sort; echo $dir/0.log" | tr '\n' ' ')
  raw=$(mktemp)
  docker --context "$context" exec "$node" sh -c \
    "for f in $files; do case \$f in *.gz) zcat \$f;; *) cat \$f;; esac; done" \
    | sed -E 's/^[^ ]+ (stdout|stderr) [FP] //' > "$raw"
  first=$(head -1 "$raw" | cut -f1)
  last=$(tail -1 "$raw" | cut -f1)
  # The log must reach back to START and forward to END, or the coverage header would claim times it lacks.
  if [[ "$first" > "$start" || "$last" < "$end" ]]; then
    echo "$node: log spans $first .. $last and does not cover $start .. $end" >&2; rm -f "$raw"; exit 1
  fi
  {
    printf '# ztunnel log extract: node %s, source %s (%s)\n' "$node" "$dir" "$(echo "$files" | xargs -n1 basename | tr '\n' ' ')"
    printf '# filter: lines between %s and %s matching /%s/\n' "$start" "$end" "$match"
    printf '# source spans %s .. %s\n' "$first" "$last"
    printf '# coverage %s %s\n' "$start" "$end"
    awk -v s="${start%Z}" -v e="${end%Z}" '$1 >= s && $1 < e' "$raw" | grep -E "$match" || true
  } > "$out/$node.log"
  rm -f "$raw"
  if grep -qi 'private key' "$out/$node.log"; then echo "$node: private key material in the extract" >&2; exit 1; fi
  echo "$node: $(grep -vc '^#' "$out/$node.log") lines -> $out/$node.log"
done
