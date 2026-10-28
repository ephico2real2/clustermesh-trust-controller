#!/usr/bin/env bash
# Resolve one name with nslookup from each named Pod, and record the answer or the error, one line per Pod.
# It sends DNS queries from the Pods, so run it only when you hold the lab. It changes no resource.
#
# Each line records what the Pod's resolver did, not why. Read it with the Cilium drop capture of the same time
# (capture_cilium_drops.sh): a drop from the Pod to its nameserver on port 53 names the component that dropped it.
#
# Output, one line per Pod, after a header:
#   START END CONTEXT NAMESPACE/POD nameserver=IP rc=N OUTPUT
#   START and END are this host's UTC clock around the kubectl exec; rc is nslookup's exit status; OUTPUT is what
#   nslookup printed, its lines joined with " | ". rc=exec means the exec failed and nslookup did not run; OUTPUT is
#   then kubectl's error.
#
# Usage: dns_check.sh OUT_FILE NAME CONTEXT/NAMESPACE/POD...
#   dns_check.sh <run-dir>/dns-check.txt kubernetes.default.svc.cluster.local \
#     kind-cmtc-a/cmtc-live-mtls/client-worker kind-cmtc-a/cmtc-live-mtls-unauth/unregistered-control-plane
# Environment: KUBECONFIG, the kubeconfig that holds the contexts.
# Exit status: 0 when every exec ran (whatever nslookup answered), 1 when an exec failed, 2 for bad input.
set -euo pipefail
[ $# -ge 3 ] || { sed -n '2,18p' "$0" >&2; exit 2; }
out=$1 name=$2; shift 2
[[ $name =~ ^[A-Za-z0-9.-]+$ ]] || { echo "NAME must be a DNS name" >&2; exit 2; }
mkdir -p "$(dirname "$out")"

# Runs in the Pod's own shell; $1 is the name.
# shellcheck disable=SC2016  # expanded by the Pod's shell, not here
probe='ns=$(sed -n "s/^nameserver[[:space:]]*//p" /etc/resolv.conf | head -1)
echo "CMTC_NAMESERVER=$ns"
nslookup "$1" 2>&1
echo "CMTC_RC=$?"'

for target in "$@"; do
  rest=${target#*/}
  if [ "${target%%/*}" = "$target" ] || [ "${rest%%/*}" = "$rest" ] || [ -z "${rest#*/}" ]; then
    echo "$target: expected CONTEXT/NAMESPACE/POD" >&2; exit 2
  fi
done

failed=0
{
  printf '# dns check: nslookup %s from %s Pod(s), started %s\n' "$name" "$#" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# START END CONTEXT NAMESPACE/POD nameserver=IP rc=N OUTPUT\n'
  for target in "$@"; do
    context=${target%%/*} rest=${target#*/}
    namespace=${rest%%/*} pod=${rest#*/}
    start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    result=$(kubectl --context "$context" -n "$namespace" exec "$pod" -- sh -c "$probe" sh "$name" 2>&1 || true)
    end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    nameserver=$(printf '%s\n' "$result" | sed -n 's/^CMTC_NAMESERVER=//p')
    rc=$(printf '%s\n' "$result" | sed -n 's/^CMTC_RC=//p')
    [ -n "$rc" ] || { rc="exec"; failed=1; }
    said=$(printf '%s\n' "$result" | grep -v '^CMTC_' | grep -v '^[[:space:]]*$' | sed 's/[[:space:]]\{1,\}/ /g' \
      | paste -sd '|' - | sed 's/|/ | /g' || true)
    printf '%s %s %s %s/%s nameserver=%s rc=%s %s\n' "$start" "$end" "$context" "$namespace" "$pod" \
      "${nameserver:-?}" "$rc" "$said"
  done
} > "$out"
cat "$out"
exit "$failed"
