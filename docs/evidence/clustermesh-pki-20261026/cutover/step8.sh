#!/usr/bin/env bash
# Step 8 for one cluster: move the 6 remaining kube-system Certificates to <cluster>-clustermesh-intermediate one at a
# time (each issuerRef change reissues it), the server Certificate last; its key must not change (peers pin it).
set -euo pipefail
c=$1 root=/Users/olasumbo/gitRepos/clustermest-trust-controller/docs/evidence/clustermesh-pki-20261026/cutover/cmtc-mesh-root-ca.crt
for name in clustermesh-apiserver-admin-cert clustermesh-apiserver-local-cert clustermesh-apiserver-remote-cert ztunnel-membership-writer ztunnel-origin-reader clustermesh-apiserver-server-cert; do
  /private/tmp/claude-501/-Users-olasumbo-gitRepos-clustermest-trust-controller/b744973a-790d-4002-b391-59c175420e0c/scratchpad/migrate.sh "$c" "$name" "$root"
  sleep 10
done
