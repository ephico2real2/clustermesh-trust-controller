from pathlib import Path
import json
from scapy.all import rdpcap,TCP
from scapy.layers.vxlan import VXLAN
p=Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike/authenticated-only-f052d127')
records={};packets=rdpcap(str(p/'authenticated-capture.pcap'))
for packet in packets:
 if TCP not in packet:continue
 tcp=packet[TCP]
 if tcp.dport!=15008 and tcp.sport!=15008:continue
 payload=bytes(tcp.payload)
 if len(payload)<5 or payload[0] not in (20,21,22,23) or payload[1]!=3:continue
 name={20:'changeCipherSpec',21:'alert',22:'handshake',23:'applicationData'}[payload[0]]
 records[name]=records.get(name,0)+1
assert records.get('applicationData',0)>0
canary=b'CMTC_AUTHENTICATED_ONLY_F052_20261024'
assert not any(canary in bytes(packet) for packet in packets)
summary={'sourceSHA':'f052d1276b0fb1619809db0059fbbb7898c9cfae','tlsRecordPackets':records,'canaryPackets':0,'note':'Captured TLS record packets can include duplicate observations; not TLS handshake counts'}
(p/'tls-record-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
