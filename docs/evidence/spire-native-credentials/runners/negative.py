from pathlib import Path
import sys,json,uuid
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
assert ledger['positivePassed']
for cluster,state in ledger['clusters'].items():
 api=API(cluster)
 for node,positive in state['positive'].items():
  wanted=positive['registration'];peer=next(v['registration'] for n,v in state['positive'].items() if n!=node)
  identity=wanted['spiffeID'];prefix=identity.rsplit('/sa/',1)[0]
  cases=[('wrong-service-account',prefix+'/sa/not-authorized',wanted['podUID'],'Mismatched identity'),
         ('wrong-namespace',identity.replace('/ns/mesh-example/','/ns/not-authorized/'),wanted['podUID'],'Mismatched identity'),
         ('wrong-trust-domain',identity.replace(w.r.CLUSTERS[cluster],'untrusted.mesh.example'),wanted['podUID'],'explicit SPIRE mode and exact local domain required'),
         ('nonexistent-UID',identity,str(uuid.uuid4()),'No sandbox found for workload UID'),
         ('cross-node-UID',peer['spiffeID'],peer['podUID'],'No sandbox found for workload UID')]
  for label,sid,uid,expected in cases:
   result=q.expect_native_denied(api,probe_pod=state['probes'][node],identity=sid,pod_uid=uid,pod_name=wanted['podName'],diagnostic_substring=expected)
   state['negative'][node+'/'+label]=result;save();print('PASS',cluster,node,label,expected,flush=True)
ledger['basicNegativesPassed']=True;save()
