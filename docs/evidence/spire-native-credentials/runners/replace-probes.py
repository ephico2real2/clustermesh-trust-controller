from pathlib import Path
import sys,json,time
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py')
exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
sys.path.insert(0,str(ROOT/'scripts/lab/pki'));import pki
ledger.setdefault('retiredProbes',[])
for cluster,state in ledger['clusters'].items():
 api=API(cluster)
 with pki.Proxy('/private/tmp/cmtc-a-b-20261024.kubeconfig','kind-'+cluster) as proxy:
  for key,prior in list(state['objects'].items()):
   if not key.startswith('Pod/'):continue
   _,ns,name=key.split('/');path=f'/api/v1/namespaces/{ns}/pods/{name}'
   current=api.get(path);m=current['metadata'];known=prior.get('acknowledged') or state['probes'][current['spec']['nodeName']]
   assert m['uid']==prior['uid'] and m['labels']['security.cmtc.io/credential-owner']==ledger['owner'] and current['spec']==known['spec']
   assert current['spec']['containers'][0].get('workingDir','')!='/'
   item={'cluster':cluster,'key':key,'original':prior,'observed':current,'phase':'delete-intended'};ledger['retiredProbes'].append(item);save()
   proxy.request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}})
   deadline=time.monotonic()+55
   while True:
    try:observed=proxy.request('GET',path)
    except pki.APIError as e:
     assert e.status==404;break
    assert observed['metadata']['uid']==m['uid']
    assert time.monotonic()<deadline;time.sleep(.3)
   item['phase']='old-UID-absent';del state['objects'][key];state['probes'].pop(current['spec']['nodeName'],None);save()
   print('PASS',cluster,name,'exact UID/RV retired; replacement will use explicit workingDir /',flush=True)
