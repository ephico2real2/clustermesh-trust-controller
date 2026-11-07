#!/usr/bin/env bash
# Wait until no ztunnel logged a failed certificate fetch for 60 s, past one full 150 s back-off after registration.
set -u
KC=/private/tmp/cmtc-a-b-20261024.kubeconfig
until [ "$(date -u +%H%M%S)" \> 030920 ]; do sleep 5; done
for i in $(seq 1 40); do
  bad=0
  for c in cmtc-a cmtc-b; do
    for p in $(kubectl --kubeconfig $KC --context kind-$c -n kube-system get pods -l app=ztunnel-cilium -o name); do
      n=$(kubectl --kubeconfig $KC --context kind-$c -n kube-system logs $p --since=60s | grep -c 'certificate fetch failed')
      [ "$n" -gt 0 ] && { bad=1; echo "$(date -u +%T) $c $p failed fetches in 60s: $n"; }
    done
  done
  [ $bad -eq 0 ] && { echo "$(date -u +%T) no failed certificate fetch in 60 s on any ztunnel"; exit 0; }
  sleep 15
done
echo "$(date -u +%T) still failing after 10 min"; exit 1
