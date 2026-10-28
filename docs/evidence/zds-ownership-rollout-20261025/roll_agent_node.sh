#!/usr/bin/env bash
# Restart one node's Cilium agent onto the DaemonSet template while following
# the outgoing agent's log to its last line (shutdown evidence), then keep the
# new agent's first 90 s of log. Usage: roll_agent_node.sh CLUSTER NODE OLD_IMAGE OUT
set -euo pipefail
cluster=$1 node=$2 old=$3 out=$4
K=(kubectl --kubeconfig /private/tmp/cmtc-a-b-20261024.kubeconfig --context "kind-$cluster" -n kube-system)
mkdir -p "$out"
pod=$("${K[@]}" get pods -l k8s-app=cilium --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}')
"${K[@]}" logs -f "$pod" -c cilium-agent --since=1s > "$out/$cluster-$node-old-agent-shutdown.log" 2>&1 &
follower=$!
sleep 2
python3 /private/tmp/cmtc-opus-final-20261025/review/restart_node_pod.py "$cluster" kube-system k8s-app=cilium cilium "$node" "$old" "$out"
wait "$follower" || true
new=$("${K[@]}" get pods -l k8s-app=cilium --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}')
sleep 90
"${K[@]}" logs "$new" -c cilium-agent > "$out/$cluster-$node-new-agent.log"
echo "$cluster $node: old $pod shutdown log $(wc -l < "$out/$cluster-$node-old-agent-shutdown.log") lines; new $new log $(wc -l < "$out/$cluster-$node-new-agent.log") lines"
