from pathlib import Path
import sys,json,time
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
sys.path.insert(0,str(ROOT/'scripts/lab/pki'));import pki
BOOT=json.loads(Path('/private/tmp/cmtc-spire-workload-runtime-20261024/workload-ledger.json').read_text());AGENT=json.loads(Path('/private/tmp/cmtc-spire-workload-runtime-20261024/image-pin.json').read_text())
assert ledger['delegateRecoveryPassed']
for cluster,state in ledger['clusters'].items():
 api=API(cluster);baseline=BOOT['clusters'][cluster];ds=api.get('/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent');assert ds['spec']['template']==baseline['expectedTemplate'];dsUID=ds['metadata']['uid']
 state['agentRestart']={};save()
 for node,positive in sorted(state['positive'].items()):
  candidates=[p for p in api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'] if p['spec']['nodeName']==node and not p['metadata'].get('deletionTimestamp')];assert len(candidates)==1;old=candidates[0];m=old['metadata']
  assert old['spec']['containers'][0]['image']==AGENT['canonicalImage'] and any(o['uid']==dsUID and o.get('controller') for o in m['ownerReferences']) and all(s['ready'] for s in old['status']['containerStatuses'])
  proof_before=proof(api,'before-agent-restart-'+node);entry={'oldPod':old,'phase':'delete-intended','signerBefore':proof_before['directIssuerSHA256']};state['agentRestart'][node]=entry;save()
  with pki.Proxy('/private/tmp/cmtc-a-b-20261024.kubeconfig','kind-'+cluster) as proxy:
   proxy.request('DELETE','/api/v1/namespaces/cilium-spire/pods/'+m['name'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}})
  entry['phase']='waiting-replacement';save();end=time.monotonic()+150
  while True:
   pods=[p for p in api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'] if p['spec']['nodeName']==node and not p['metadata'].get('deletionTimestamp') and p['metadata']['uid']!=m['uid']]
   if len(pods)==1 and pods[0].get('status',{}).get('phase')=='Running' and pods[0]['status'].get('containerStatuses') and all(s['ready'] for s in pods[0]['status']['containerStatuses']):break
   assert time.monotonic()<end,'node agent replacement not ready';time.sleep(1)
  new=pods[0];assert new['spec']['containers'][0]['image']==AGENT['canonicalImage'] and any(o['uid']==dsUID and o.get('controller') for o in new['metadata']['ownerReferences'])
  current=api.get('/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent');assert current['metadata']['uid']==dsUID and current['spec']['template']==ds['spec']['template']
  issuer=proof(api,'after-agent-restart-'+node);assert issuer['directIssuerSHA256']==proof_before['directIssuerSHA256']
  result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=state['probes'][node],wanted=positive['registration'],issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage'])
  entry.update(phase='fresh-native-credential-verified',newPod=new,result=result,signerAfter=issuer['directIssuerSHA256']);save();print('PASS',cluster,node,'SPIRE restart retains exact signer and real native credential path',flush=True)
ledger['allNodeAgentRestartPassed']=True;save()
