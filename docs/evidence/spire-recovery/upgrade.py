from pathlib import Path
import copy,importlib.util,json,os,subprocess,time
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');OUT=Path('/private/tmp/cmtc-spire-recovery-20261024');KUBE='/private/tmp/cmtc-a-b-20261024.kubeconfig'
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
pki=module('pki',ROOT/'scripts/lab/pki/pki.py');proof=module('proof',ROOT/'scripts/lab/spire/public_proof.py')
pins=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text());created=json.loads(Path('/private/tmp/cmtc-spire-deploy-20261024/created.json').read_text());image=json.loads((OUT/'image-pin.json').read_text());imports=json.loads((OUT/'loaded-images.json').read_text())
assert len(imports)==4 and all(v['configurationID']==image['configurationID'] and v['architecture']=='arm64' and image['sourceSHA'] in v['versionJob']['version'] for v in imports.values())
BUSY='docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e'
STSPATH='/apis/apps/v1/namespaces/cilium-spire/statefulsets/spire-server';PVCPATH='/api/v1/namespaces/cilium-spire/persistentvolumeclaims/spire-data-spire-server-0';PODPATH='/api/v1/namespaces/cilium-spire/pods/spire-server-0'
def k(c,*args,data=None,raw=False,timeout=40):
 r=subprocess.run(['kubectl','--kubeconfig',KUBE,'--context','kind-'+c,*args],input=json.dumps(data) if data is not None else None,text=True,capture_output=True,timeout=timeout)
 if r.returncode:raise RuntimeError(r.stderr)
 return r.stdout if raw else json.loads(r.stdout) if r.stdout.strip() else None
def save(name,value): (OUT/name).write_text(json.dumps(value,indent=2)+'\n')
def patch(c,current,changes):
 m=current['metadata'];ops=[{'op':'test','path':'/metadata/uid','value':m['uid']},{'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']}]+changes
 return k(c,'-n','cilium-spire','patch','statefulset','spire-server','--type=json','-p',json.dumps(ops),'-o','json')
def poll(fn,timeout=150):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  value=fn()
  if value:return value
  time.sleep(.5)
 raise RuntimeError('bounded SPIRE upgrade wait expired')
def do_proof(api,c,pod,server_image):
 pub=json.loads((Path('/private/tmp/cmtc-spire-ca-opaque-20261024')/(c+'-pki.stdout')).read_text())['publication']
 return proof.execute_proof(api,cluster=c,cluster_uid=pins[c]['clusterUID'],pod_uid=pod['metadata']['uid'],approval_uid=pub['approvalUID'],root_pin=pub['rootSHA256'],server_image=server_image)
for c in ['cmtc-a','cmtc-b']:
 with pki.Proxy(KUBE,'kind-'+c) as api:
  before=pki.snapshot(api,api.argv);save(c+'-upgrade-baseline.json',before)
  assert before['clusterUID']==pins[c]['clusterUID'] and dict(before['nodes'])==pins[c]['nodes']
  original=api.get(STSPATH);sts_uid=next(x['metadata']['uid'] for x in created[c] if x['kind']=='StatefulSet');assert original['metadata']['uid']==sts_uid and original['spec']['replicas']==1
  pod=api.get(PODPATH);assert pod['metadata']['ownerReferences'][0]['uid']==sts_uid and all(s['ready'] for s in pod['status']['containerStatuses'])
  node=pod['spec']['nodeName'];assert node in pins[c]['nodes']
  pvc=api.get(PVCPATH);assert pvc['status']['phase']=='Bound';save(c+'-upgrade-original.json',{'statefulset':original,'pod':pod,'pvc':pvc})
  save(c+'-upgrade-proof-before.json',do_proof(api,c,pod,proof.SERVER_IMAGE))
  pin=proof.approved_server_image(imports[node]['canonicalImage'])
  spec=copy.deepcopy(original['spec']['template']);server=next(x for x in spec['spec']['containers'] if x['name']=='spire-server');assert server['image']==proof.SERVER_IMAGE;server['image']=pin
  cli=next(x for x in spec['spec']['volumes'] if x['name']=='spire-server-cli');assert cli['image']['reference']==proof.SERVER_IMAGE;cli['image']['reference']=pin
  # Validate the exact future template against the live API before stopping the server.
  trial=copy.deepcopy(original);trial['spec']['template']=spec
  k(c,'replace','--dry-run=server','-f','-','-o','json',data=trial)
  name='spire-snapshot-28f6b8d84a'
  job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':'cilium-spire','labels':{'app.kubernetes.io/managed-by':'cmtc-local-validation','security.cmtc.io/trial':'spire-journal-28f6b8d84a'}},'spec':{'activeDeadlineSeconds':90,'backoffLimit':0,'template':{'spec':{'nodeName':node,'restartPolicy':'Never','automountServiceAccountToken':False,'tolerations':[{'operator':'Exists'}],'securityContext':{'runAsNonRoot':True,'runAsUser':1000,'runAsGroup':1000,'fsGroup':1000,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'snapshot','image':BUSY,'imagePullPolicy':'IfNotPresent','command':['/bin/sh','-ec',(OUT/'snapshot.sh').read_text()],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'cpu':'200m','memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'data','mountPath':'/data'}]}],'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':pvc['metadata']['name']}}]}}}}
  k(c,'create','--dry-run=server','-f','-','-o','json',data=job)
  if os.environ.get('CMTC_UPGRADE_PREFLIGHT_ONLY')=='1':
   print(c,'PASS exact upgrade and snapshot live API preflight; no rollout performed',flush=True)
   continue
  patch(c,original,[{'op':'replace','path':'/spec/replicas','value':0}])
  poll(lambda:not api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-server')['items'],90)
  assert api.get(PVCPATH)['metadata']['uid']==pvc['metadata']['uid']
  ack=k(c,'create','-f','-','-o','json',data=job);save(c+'-snapshot-job.json',ack);job_uid=ack['metadata']['uid']
  k(c,'-n','cilium-spire','wait','--for=condition=Complete','job/'+name,'--timeout=90s',raw=True,timeout=100)
  log=k(c,'-n','cilium-spire','logs','job/'+name,raw=True);assert json.loads(log)['snapshotComplete'] is True;save(c+'-snapshot-ack.json',json.loads(log))
  current=k(c,'-n','cilium-spire','get','job',name,'-o','json');assert current['metadata']['uid']==job_uid
  options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':job_uid,'resourceVersion':current['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
  k(c,'delete','--raw','/apis/batch/v1/namespaces/cilium-spire/jobs/'+name,'-f','-',data=options)
  k(c,'-n','cilium-spire','wait','--for=delete','job/'+name,'--timeout=90s',raw=True,timeout=100)
  save(c+'-snapshot-cleanup.json',{'jobUID':job_uid,'deleted':True,'backupRemainsOnExistingPVC':True,'privateKeysExported':False})
  current=api.get(STSPATH);assert current['metadata']['uid']==sts_uid and current['spec']['replicas']==0 and current['spec']['template']==original['spec']['template']
  patch(c,current,[{'op':'test','path':'/spec/template','value':original['spec']['template']},{'op':'replace','path':'/spec/template','value':spec},{'op':'replace','path':'/spec/replicas','value':1}])
  def ready():
   try:p=api.get(PODPATH)
   except pki.APIError as e:
    if e.status==404:return False
    raise
   if p['metadata']['uid']==pod['metadata']['uid'] or p['metadata'].get('deletionTimestamp'):return False
   cs=p.get('status',{}).get('containerStatuses',[])
   return p if len(cs)==2 and all(x['ready'] for x in cs) else False
  new=poll(ready);assert new['metadata']['ownerReferences'][0]['uid']==sts_uid
  currentpvc=api.get(PVCPATH);assert currentpvc['metadata']['uid']==pvc['metadata']['uid'] and currentpvc['spec']['volumeName']==pvc['spec']['volumeName']
  save(c+'-upgrade-after.json',{'pod':new,'pvc':currentpvc,'approvedServerImage':pin})
  fresh=do_proof(api,c,new,pin);save(c+'-upgrade-proof-after.json',fresh)
  old=json.loads((OUT/(c+'-upgrade-proof-before.json')).read_text());assert old['directIssuerSHA256']==fresh['directIssuerSHA256'] and old['activeAuthority']==fresh['activeAuthority'],'upgrade must recover exact current signer'
  after=pki.snapshot(api,api.argv);save(c+'-upgrade-preserved.json',after);assert before==after
  print(c,'PASS exact-source image, private PVC snapshot, retained signer and lineage, unchanged Cilium/cert-manager',flush=True)
