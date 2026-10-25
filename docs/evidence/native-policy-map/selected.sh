#!/bin/bash
set -euo pipefail
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 4g --privileged --security-opt label=disable -e PRIVILEGED_TESTS=1 -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src cee8c5638bdedad0944780cd5dd7e3ff4f7b5c7e558d328d5412deacd364b905 sh -ec 'go test -race -count=1 -json ./pkg/policy -run "^TestNativeZtunnel"; go test -race -count=1 -json ./pkg/endpoint -run "^TestNativePolicyMap"' > /private/tmp/cmtc-native-policy-map-20261025/selected-fourth.jsonl 2>&1
python3 - <<'PY'
import json
from pathlib import Path
p=Path('/private/tmp/cmtc-native-policy-map-20261025/selected-fourth.jsonl');events=[]
for line in p.read_text().splitlines():
 try:events.append(json.loads(line))
 except ValueError:pass
assert not [e for e in events if e.get('Action')=='fail' or (e.get('Action')=='skip' and e.get('Test'))]
tops=[e for e in events if e.get('Action')=='pass' and e.get('Test') and '/' not in e['Test']]
assert len(tops)==11,[(e['Package'],e['Test']) for e in tops]
print('PASS 11 actual new native policy/map top-level tests; no skipped cases')
PY
