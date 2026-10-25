from pathlib import Path
import sys,json,time
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
sys.path.insert(0,str(ROOT/'scripts/lab/pki'));import pki
assert ledger['finalRuntimeChecksPassed'] and ledger['wrongKubeletCARecoveryPassed']
assert len([x for x in (OUT/'apps/regression-second.log').read_text().splitlines() if x.startswith('PASS ')])==36
assert (OUT/'publication-final.log').read_text().count('PASS ')==2
ledger['appRegressionPassed']=True;ledger['freshPublicationMetricsPassed']=True;save()
for cluster,state in ledger['clusters'].items():
 api=API(cluster);assert not state.get('cleanup'),'existing cleanup ledger; inspect before resume'
 clean={'phase':'removing-owned-registrations','entries':{},'objects':{}};state['cleanup']=clean;save()
 for eid,item in state['entries'].items():
  assert item['phase']=='verified';wanted=item['wanted'];q.show_exact(api,wanted)
  clean['entries'][eid]={'phase':'delete-intended','wanted':wanted};save()
  response=q.server_cli(api,['entry','delete','-socketPath',w.r.SERVER_SOCKET,'-entryID',eid,'-output','json']);assert len(response['results'])==1 and response['results'][0]['id']==eid and response['results'][0].get('status',{}).get('code',0)==0
  assert all(e['id']!=eid for e in entry_list(api));clean['entries'][eid].update(phase='verified-absent',response=response);save()
 assert not ({e['id'] for e in entry_list(api)} & set(state['entries']))
 with pki.Proxy('/private/tmp/cmtc-a-b-20261024.kubeconfig','kind-'+cluster) as proxy:
  paths={}
  for key,prior in state['objects'].items():
   if not key.startswith('Pod/'):continue
   _,ns,name=key.split('/');path=f'/api/v1/namespaces/{ns}/pods/{name}';current=proxy.get(path);m=current['metadata']
   known=prior.get('acknowledged') or state['probes'][current['spec']['nodeName']]
   assert m['uid']==prior['uid']==known['metadata']['uid'] and m['labels']['security.cmtc.io/credential-owner']==ledger['owner'] and current['spec']==known['spec']
   clean['objects'][key]={'phase':'delete-intended','uid':m['uid'],'resourceVersion':m['resourceVersion']};save()
   proxy.request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}});paths[path]=(key,m['uid'])
  end=time.monotonic()+70
  while paths:
   for path,(key,expectedUID) in list(paths.items()):
    try:current=proxy.get(path)
    except pki.APIError as e:
     assert e.status==404;clean['objects'][key]['phase']='verified-absent';del paths[path];save();continue
    assert current['metadata']['uid']==expectedUID
   assert not paths or time.monotonic()<end,'owned Pods did not terminate';time.sleep(.3)
  for kind,resource in [('ServiceAccount','serviceaccounts'),('Namespace','namespaces')]:
   for key,prior in state['objects'].items():
    if not key.startswith(kind+'/'):continue
    if kind=='Namespace':name=key.split('/')[1];path='/api/v1/namespaces/'+name
    else:_,ns,name=key.split('/');path=f'/api/v1/namespaces/{ns}/{resource}/{name}'
    current=proxy.get(path);m=current['metadata'];assert m['uid']==prior['uid'] and m['labels']['security.cmtc.io/credential-owner']==ledger['owner']
    clean['objects'][key]={'phase':'delete-intended','uid':m['uid'],'resourceVersion':m['resourceVersion']};save()
    proxy.request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}})
    end=time.monotonic()+65
    while True:
     try:current=proxy.get(path)
     except pki.APIError as e:assert e.status==404;break
     assert current['metadata']['uid']==m['uid'] and time.monotonic()<end;time.sleep(.3)
    clean['objects'][key]['phase']='verified-absent';save()
 original=api.get('/api/v1/namespaces/mesh-example/pods/mesh-client');assert original['metadata']['uid']==state['regressionClient']['originalCompletedClientUID']
 clean['phase']='all-owned-credentials-and-runtime-probes-absent';state['phase']='native-credentials-qualified-fixture-cleaned-no-proxy';save();print('PASS',cluster,len(clean['entries']),'exact registrations and',len(clean['objects']),'UID-bound objects absent; original apps retained',flush=True)
ledger['cleanupPassed']=True;ledger['success']=True;save()
