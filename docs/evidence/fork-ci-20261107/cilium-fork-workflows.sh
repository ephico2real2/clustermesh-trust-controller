#!/bin/sh
# Disable (or, with "enable", restore) the upstream scheduled workflows that cannot pass on ephico2real2/cilium.
# Usage: cilium-fork-workflows.sh disable|enable <list.tsv>   (list: workflow id <tab> path)
set -u
action=${1:?disable or enable}; list=${2:?list file}
case "$action" in disable|enable) ;; *) echo "disable or enable" >&2; exit 2 ;; esac
failed=0
while IFS="$(printf '\t')" read -r id path; do
  if gh api -X PUT "repos/ephico2real2/cilium/actions/workflows/$id/$action" >/dev/null; then echo "$action $id $path"; else echo "FAILED $id $path" >&2; failed=1; fi
done < "$list"
gh api 'repos/ephico2real2/cilium/actions/workflows?per_page=100' --jq '.workflows|group_by(.state)|map({(.[0].state):length})|add'
exit $failed
