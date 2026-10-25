from pathlib import Path
import importlib.util,json,subprocess,time
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');OUT=Path('/private/tmp/cmtc-spire-recovery-20261024');KUBE='/private/tmp/cmtc-a-b-20261024.kubeconfig'
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
pki=module('pki',ROOT/'scripts/lab/pki/pki.py');q=module('q',ROOT/'scripts/lab/spire/public_proof.py');pin=json.loads((OUT/'image-pin.json').read_text());pins=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text())
def k(c,*args):return subprocess.check_output(['kubectl','--kubeconfig',KUBE,'--context','kind-'+c,*args],text=True,timeout=40)
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def wait(fn,seconds=150):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.5)
 raise RuntimeError('bounded SPIRE qualification wait expired')
def ready_new(api,path,old_uid,count):
 try:p=api.get(path)
 except pki.APIError as e:
  if e.status==404:return False
  raise
 cs=p.get('status',{}).get('containerStatuses',[])
 return p if p['metadata']['uid']!=old_uid and not p['metadata'].get('deletionTimestamp') and len(cs)==count and all(s['ready'] for s in cs) else False
def delete(api,path,pod):
 m=pod['metadata'];api.request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','gracePeriodSeconds':20,'preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}})
def proof(api,c,pod):
 pub=json.loads((Path('/private/tmp/cmtc-spire-ca-opaque-20261024')/(c+'-pki.stdout')).read_text())['publication']
 return q.execute_proof(api,cluster=c,cluster_uid=pins[c]['clusterUID'],pod_uid=pod['metadata']['uid'],approval_uid=pub['approvalUID'],root_pin=pub['rootSHA256'],server_image=pin['canonicalImage'])
summary={}
for roundid in [1,2]:
 target=OUT/('retention-round-'+str(roundid));target.mkdir(exist_ok=False)
 for c in ['cmtc-a','cmtc-b']:
  with pki.Proxy(KUBE,'kind-'+c) as api:
   baseline=pki.snapshot(api,api.argv);assert baseline['clusterUID']==pins[c]['clusterUID'];podpath='/api/v1/namespaces/cilium-spire/pods/spire-server-0';pod=api.get(podpath);before=proof(api,c,pod);save(target/(c+'-proof-before.json'),before)
   pvcpath='/api/v1/namespaces/cilium-spire/persistentvolumeclaims/spire-data-spire-server-0';pvc=api.get(pvcpath);sts_uid=pod['metadata']['ownerReferences'][0]['uid'];save(target/(c+'-before.json'),{'pod':pod,'pvc':pvc})
   delete(api,podpath,pod);new=wait(lambda:ready_new(api,podpath,pod['metadata']['uid'],2));assert new['metadata']['ownerReferences'][0]['uid']==sts_uid
   current=api.get(pvcpath);assert current['metadata']['uid']==pvc['metadata']['uid'] and current['spec']['volumeName']==pvc['spec']['volumeName'];save(target/(c+'-after.json'),{'pod':new,'pvc':current})
   after=proof(api,c,new);save(target/(c+'-proof-after.json'),after);assert before['directIssuerSHA256']==after['directIssuerSHA256'] and before['activeAuthority']==after['activeAuthority']
   version=subprocess.check_output(['kubectl','--kubeconfig',KUBE,'--context','kind-'+c,'-n','cilium-spire','exec','spire-server-0','-c','spire-server','--','/opt/spire/bin/spire-server','--version'],stderr=subprocess.STDOUT,text=True,timeout=40);assert pin['sourceSHA'] in version;(target/(c+'-version.txt')).write_text(version)
   assert pki.snapshot(api,api.argv)==baseline
   summary[c]={'signerSHA256':after['directIssuerSHA256'],'activeAuthority':after['activeAuthority'],'pvcUID':current['metadata']['uid'],'serverSourceSHA':pin['sourceSHA'],'retentionRoundsPassed':roundid}
   print(c,'PASS retained exact signer/PVC after server restart round',roundid,flush=True)
 save(OUT/'retention-summary.json',summary)
# Force new PSAT attestations against the new server for every owned node.
target=OUT/'fresh-psat';target.mkdir(exist_ok=False)
for c in ['cmtc-a','cmtc-b']:
 with pki.Proxy(KUBE,'kind-'+c) as api:
  ds=api.get('/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent');ds_uid=ds['metadata']['uid'];pods=api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'];assert len(pods)==2
  for old in sorted(pods,key=lambda p:p['spec']['nodeName']):
   node=old['spec']['nodeName'];assert node in pins[c]['nodes'] and old['metadata']['ownerReferences'][0]['uid']==ds_uid
   path='/api/v1/namespaces/cilium-spire/pods/'+old['metadata']['name'];delete(api,path,old)
   def fresh():
    values=api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'];matches=[p for p in values if p['spec']['nodeName']==node and p['metadata']['uid']!=old['metadata']['uid'] and not p['metadata'].get('deletionTimestamp') and p['metadata']['ownerReferences'][0]['uid']==ds_uid and len(p.get('status',{}).get('containerStatuses',[]))==1 and all(x['ready'] for x in p['status']['containerStatuses'])]
    return matches[0] if len(matches)==1 else False
   new=wait(fresh);save(target/(node+'-new-pod.json'),new)
   def attested():
    obj=json.loads(k(c,'-n','cilium-spire','exec','spire-server-0','-c','spire-server','--','/opt/spire/bin/spire-server','agent','list','-output','json'))
    matches=[a for a in obj['agents'] if not a['banned'] and a['attestation_type']=='k8s_psat' and a['id']['trust_domain']==c+'.mesh.example' and a['id']['path']=='/spire/agent/k8s_psat/'+c+'/'+pins[c]['nodes'][node] and 'agent_pod_uid:'+new['metadata']['uid'] in {s['value'] for s in a['selectors'] if s['type']=='k8s_psat'}]
    return obj if len(matches)==1 else False
   actual=wait(attested,40);save(target/(node+'-attestation.json'),actual);summary[c].setdefault('freshPSATNodes',[]).append({'node':node,'nodeUID':pins[c]['nodes'][node],'newPodUID':new['metadata']['uid']})
   print(c,node,'PASS fresh PSAT attestation against recovery image',flush=True)
  save(OUT/'retention-summary.json',summary)
print('PASS both repeated server retention and all four fresh node attestations; no workload protection claim',flush=True)
