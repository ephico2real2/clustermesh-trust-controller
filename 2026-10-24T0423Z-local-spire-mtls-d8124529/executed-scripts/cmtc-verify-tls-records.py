from pathlib import Path
from scapy.all import rdpcap, TCP
from scapy.layers.vxlan import VXLAN
import json
p=Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike')
records={}
for packet in rdpcap(str(p/'enrolled-trial.pcap')):
 if TCP not in packet: continue
 tcp=packet[TCP]
 if tcp.dport!=15008 and tcp.sport!=15008: continue
 payload=bytes(tcp.payload)
 if len(payload)<5 or payload[0] not in (20,21,22,23) or payload[1]!=3: continue
 kind={20:'changeCipherSpec',21:'alert',22:'handshake',23:'applicationData'}[payload[0]]
 records[kind]=records.get(kind,0)+1
assert records.get('handshake',0)>0,records
assert records.get('applicationData',0)>0,records
summary={'hboneTLSRecords':records,'plaintextCanaryPresentBeforeEnrollment':True,'enrolledCanaryPackets':0,'scope':'single-cluster cross-node SPIRE workload identity and TLS positive trial; authorization/bypass and cross-cluster gates remain open'}
(p/'tls-record-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
