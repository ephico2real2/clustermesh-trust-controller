from pathlib import Path
import sys,json,copy
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
assert ledger['positivePassed'] and ledger['basicNegativesPassed']
for cluster,state in ledger['clusters'].items():
 api=API(cluster);node=next(n for n in sorted(state['positive']) if 'control-plane' in n)
 wanted=state['positive'][node]['registration'];record={'name':node,'uid':PINS[cluster]['nodes'][node]}
 obj=w.probe_pod(cluster,record,IMAGE['canonicalImage'],namespace=state['namespace'],service_account='node-probe')
 obj['metadata']['name']='unregistered-delegate';obj['spec']['containers'][0]['resources']={'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'128Mi'}}
 unregistered=wait_pod(api,api.create(obj));state['unregisteredDelegate']=unregistered;save()
 state['negative']['unregistered-delegate']=q.expect_native_denied(api,probe_pod=unregistered,identity=wanted['spiffeID'],pod_uid=wanted['podUID'],pod_name=wanted['podName'],diagnostic_substring='no identity issued');save();print('PASS',cluster,'unregistered delegate same SA different exact PodUID denied',flush=True)
 # An ordinary target process has no node sockets, host PID, token or proxy.
 obj=copy.deepcopy(obj);obj['metadata']['name']='unregistered-workload'
 spec=obj['spec'];spec.pop('hostPID');spec.pop('hostUsers');spec.pop('volumes');spec['securityContext']['runAsUser']=65532;spec['securityContext']['runAsGroup']=65532
 container=spec['containers'][0];container.pop('volumeMounts');container.pop('env')
 target=wait_pod(api,api.create(obj));state['unregisteredWorkload']=target;save()
 identity='spiffe://'+w.r.CLUSTERS[cluster]+'/ns/'+state['namespace']+'/sa/node-probe'
 state['negative']['unregistered-workload']=q.expect_native_denied(api,probe_pod=state['probes'][node],identity=identity,pod_uid=target['metadata']['uid'],pod_name=target['metadata']['name'],diagnostic_substring='SPIRE credential deadline exceeded across CRI, process binding, SVID and bundle');save();print('PASS',cluster,'unregistered workload with real running PID returned no credential before bounded deadline',flush=True)
ledger['unregisteredNegativesPassed']=True;save()
