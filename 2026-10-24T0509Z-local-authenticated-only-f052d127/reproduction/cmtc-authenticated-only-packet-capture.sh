#!/usr/bin/env bash
set -euo pipefail
cd /private/tmp/cmtc-spire-workload-qualification
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
out=artifacts/mtls-spike/authenticated-only-f052d127
backend=$(kubectl -n mtls-spike get pods -l app=mtls-server -o jsonpath='{.items[0].status.podIP}')
sudo timeout --signal=INT 20 tcpdump -U -nn -i any -s 0 -w "$out/authenticated-capture.pcap" 'udp port 8472 and host 172.18.0.6 and host 172.18.0.7' > "$out/authenticated-capture-tcpdump.log" 2>&1 &
capture=$!
sleep 2
set +e
kubectl -n mtls-spike exec client -- sh -c 'for i in $(seq 1 10); do wget -q -O /dev/null -T 5 --header "X-CMTC-Canary: CMTC_AUTHENTICATED_ONLY_F052_20261024" "http://'"$backend"'/" || exit 1; echo request=$i,result=success; done' > "$out/authenticated-capture-requests.log" 2>&1
requests=$?
wait "$capture"
capture_result=$?
set -e
sudo chown "$(id -u):$(id -g)" "$out/authenticated-capture.pcap"
printf 'requests_exit=%s capture_exit=%s\n' "$requests" "$capture_result"
python3 - <<'PY'
from pathlib import Path
from scapy.all import rdpcap, TCP
from scapy.layers.vxlan import VXLAN
import json
p=Path('artifacts/mtls-spike/authenticated-only-f052d127')
packets=rdpcap(str(p/'authenticated-capture.pcap'))
canary=b'CMTC_AUTHENTICATED_ONLY_F052_20261024'
result={'capturedPackets':len(packets),'canaryPackets':sum(canary in bytes(x) for x in packets),'hbonePackets':sum(TCP in x and (x[TCP].dport==15008 or x[TCP].sport==15008) for x in packets)}
(p/'authenticated-capture-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
PY
exit "$requests"
