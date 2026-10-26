#!/usr/bin/env bash
# cmtc-b step 7 as one event: restart the clustermesh-apiserver (fresh etcd, both roots in its client-CA pool), let the
# source writers re-acquire their locks, then roll each agent so its local source reader lists the fresh etcd.
set -euo pipefail
/private/tmp/claude-501/-Users-olasumbo-gitRepos-clustermest-trust-controller/b744973a-790d-4002-b391-59c175420e0c/scratchpad/restart-apiserver.sh cmtc-b
sleep 30
/private/tmp/cmtc-opus-final-20261025/review/issuer-rotation/runners/roll_agent_node.sh cmtc-b cmtc-b-worker localhost/cilium:dev-overlay-72b5bc3a65 /private/tmp/cmtc-opus-final-20261025/review/issuer-rotation/live/lifecycle/meshpki-step7-cmtc-b/roll-worker
/private/tmp/cmtc-opus-final-20261025/review/issuer-rotation/runners/roll_agent_node.sh cmtc-b cmtc-b-control-plane localhost/cilium:dev-overlay-72b5bc3a65 /private/tmp/cmtc-opus-final-20261025/review/issuer-rotation/live/lifecycle/meshpki-step7-cmtc-b/roll-control-plane
