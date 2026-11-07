#!/usr/bin/env bash
# Restart one cluster's clustermesh-apiserver Deployment and wait for the rollout and its etcd users.
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
c=$1; K=(kubectl --context "kind-$c" -n kube-system)
"${K[@]}" rollout restart deployment/clustermesh-apiserver
"${K[@]}" rollout status deployment/clustermesh-apiserver --timeout=5m
"${K[@]}" get pods -l k8s-app=clustermesh-apiserver -o wide
