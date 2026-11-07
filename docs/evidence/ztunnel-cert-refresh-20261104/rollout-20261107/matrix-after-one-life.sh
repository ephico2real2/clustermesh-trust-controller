#!/bin/bash
# First certificate fetch on both clusters, one certificate life (130 s) and a margin, then the full matrix.
set -u
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
cd "/private/tmp/claude-501/-Users-olasumbo-gitRepos-clustermest-trust-controller/b744973a-790d-4002-b391-59c175420e0c/scratchpad/cmtc-1104" || exit 2
for c in cmtc-a cmtc-b; do python3 scripts/evidence/live_mtls_fixture.py --cluster $c --out docs/evidence/local-activation-20261025/live-tests --scope same probe --execute > "docs/evidence/ztunnel-cert-refresh-20261104/matrix-20261107/first-fetch-$c.txt" 2>&1; echo "first fetch $c exit=$? $(date -u +%FT%TZ)"; done
sleep 150
echo "matrix start $(date -u +%FT%TZ)"
scripts/evidence/run_mtls_matrix.sh "docs/evidence/ztunnel-cert-refresh-20261104/matrix-20261107"
echo "matrix exit=$? $(date -u +%FT%TZ)"
