from pathlib import Path
import sys,json,time,copy
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
sys.path.insert(0,str(ROOT/'scripts/lab/pki'));import pki
assert ledger['unregisteredNegativesPassed']

def checked_delete(api,state,pod):
 m=pod['metadata'];path=f'/api/v1/namespaces/{m["namespace"]}/pods/{m["name"]}';key='Pod/'+m['namespace']+'/'+m['name']
 with pki.Proxy('/private/tmp/cmtc-a-b-20261024.kubeconfig','kind-'+api.c) as proxy:
  current=proxy.get(path);assert current['metadata']['uid']==m['uid'] and current['metadata']['labels']['security.cmtc.io/credential-owner']==ledger['owner'] and current['spec']==pod['spec']
  retired={'cluster':api.c,'key':key,'original':state['objects'][key],'observed':current,'phase':'delete-intended'};ledger.setdefault('retiredTargets',[]).append(retired);save()
  proxy.request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':m['uid'],'resourceVersion':current['metadata']['resourceVersion']}})
  end=time.monotonic()+55
  while True:
   try:present=proxy.get(path)
   except pki.APIError as e:assert e.status==404;break
   assert present['metadata']['uid']==m['uid'] and time.monotonic()<end;time.sleep(.3)
  retired['phase']='old-UID-absent';del state['objects'][key];save()

for cluster,state in ledger['clusters'].items():
 api=API(cluster);node=next(n for n in state['positive'] if 'control-plane' in n);record={'name':node,'uid':PINS[cluster]['nodes'][node]};probe=state['probes'][node]
 target=state['unregisteredWorkload'];path=f'/api/v1/namespaces/{state["namespace"]}/pods/unregistered-workload'
 assert api.get(path)['metadata']['uid']==target['metadata']['uid']
 wanted=w.registration(cluster,w.r.CLUSTERS[cluster],PINS[cluster]['clusterUID'],{'pod':target,'namespaceUID':state['namespaceUID']},record,'workload');register(api,wanted)
 issuer=proof(api,'owned-target-before-replacement')
 result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=probe,wanted=wanted,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage'])
 state.setdefault('recovery',{})['initialExactRegistration']={'wanted':wanted,'result':result};save();print('PASS',cluster,'previously unregistered PID gets exact registered SVID',flush=True)
 intent=copy.deepcopy(state['objects']['Pod/'+state['namespace']+'/unregistered-workload']['intent']);checked_delete(api,state,target)
 replaced=wait_pod(api,api.create(intent));assert replaced['metadata']['uid']!=target['metadata']['uid'];state['replacementWorkload']=replaced;save()
 state['negative']['deleted-target-UID']=q.expect_native_denied(api,probe_pod=probe,identity=wanted['spiffeID'],pod_uid=wanted['podUID'],pod_name=wanted['podName'],diagnostic_substring='No sandbox found for workload UID');save()
 state['negative']['replacement-without-new-registration']=q.expect_native_denied(api,probe_pod=probe,identity=wanted['spiffeID'],pod_uid=replaced['metadata']['uid'],pod_name=wanted['podName'],diagnostic_substring='SPIRE credential deadline exceeded across CRI, process binding, SVID and bundle');save();print('PASS',cluster,'deleted UID and replacement same name/SA have no old entitlement',flush=True)
 fresh=w.registration(cluster,w.r.CLUSTERS[cluster],PINS[cluster]['clusterUID'],{'pod':replaced,'namespaceUID':state['namespaceUID']},record,'workload');register(api,fresh)
 result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=probe,wanted=fresh,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);state['recovery']['replacementExactRegistration']={'wanted':fresh,'result':result};save();print('PASS',cluster,'new exact replacement UID registration recovers credential delivery',flush=True)
 # Delete only the exact entry that this run created, then require actual
 # failure to issue before re-creating the same entitlement. This is a fresh
 # credential test, not revocation of an already-issued leaf or TLS flow.
 q.show_exact(api,fresh);state['recovery']['entryRemoval']={'wanted':fresh,'phase':'delete-intended'};save()
 deletion=q.server_cli(api,['entry','delete','-socketPath',w.r.SERVER_SOCKET,'-entryID',fresh['entryID'],'-output','json']);results=deletion['results'];assert len(results)==1 and results[0]['id']==fresh['entryID'] and results[0].get('status',{}).get('code',0)==0
 assert all(e['id']!=fresh['entryID'] for e in entry_list(api));state['recovery']['entryRemoval'].update(phase='server-absence-verified',response=deletion);save()
 started=time.monotonic()
 while True:
  p=q.bounded(api.argv+['exec','-n',state['namespace'],probe['metadata']['name'],'-c','probe','--',q.BINARY,'fetch',fresh['spiffeID'],fresh['podUID'],fresh['podName']],success=False)
  elapsed=time.monotonic()-started
  if p.returncode:
   assert not p.stdout.strip() and 'SPIRE credential deadline exceeded across CRI, process binding, SVID and bundle' in p.stderr
   state['negative']['removed-exact-registration']={'credentialDenied':True,'elapsedSeconds':elapsed,'publicDiagnostic':p.stderr,'packetProtectionTested':False};save();break
  assert elapsed<30,'agent did not observe owned entry deletion promptly';time.sleep(1)
 register(api,fresh)
 result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=probe,wanted=fresh,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);state['recovery']['registrationReadded']={'wanted':fresh,'result':result};save();print('PASS',cluster,'entry removal stops fresh credentials; re-registration recovers',flush=True)
ledger['registrationRecoveryPassed']=True;save()
