from pathlib import Path
import json,os,subprocess
out=Path('/private/tmp/cmtc-spire-recovery-20261024')
sha='28f6b8d84ade21c6accb32ba9689a3bdf64877ec'
image='localhost/cmtc-spire-server:journal-28f6b8d84a'
config='sha256:70f8fbde787b46479d8bd22aed9005d36caa7c597fcff7108cee9bf122a6edd0'
env={**os.environ,'KUBECONFIG':'/private/tmp/cmtc-a-b-20261024.kubeconfig','DOCKER_HOST':'unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock','KIND_EXPERIMENTAL_PROVIDER':'docker'}
def run(cmd,**kwargs):return subprocess.run(cmd,env=env,check=True,text=True,**kwargs)
def get(cmd):return run(cmd,stdout=subprocess.PIPE).stdout
verified={}
pins=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text())
for c in ('cmtc-a','cmtc-b'):
 base=['kubectl','--context','kind-'+c]
 ns=json.loads(get(base+['get','namespace','kube-system','-o','json']))
 assert ns['metadata']['uid']==pins[c]['clusterUID']
 nodes=json.loads(get(base+['get','nodes','-o','json']))['items']
 assert {n['metadata']['name']:n['metadata']['uid'] for n in nodes}==pins[c]['nodes']
for cluster in ('cmtc-a','cmtc-b'):
 with (out/f'load-{cluster}.log').open('w') as log:
  run(['kind','load','image-archive',str(out/'server-arm64.tar'),'--name',cluster],stdout=log,stderr=subprocess.STDOUT)
 for node in (cluster+'-control-plane',cluster+'-worker'):
  raw=get(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,'crictl','inspecti',image])
  actual=json.loads(raw)
  (out/f'import-{node}.json').write_text(raw)
  assert actual['status']['id']==config,(node,actual['status']['id'])
  assert actual['info']['imageSpec']['architecture']=='arm64'
  verified[node]={'image':image,'configurationID':config,'architecture':'arm64','repoDigests':actual['status']['repoDigests']}
(out/'loaded-images.json').write_text(json.dumps(verified,indent=2)+'\n')
cleanup=[]
for cluster in ('cmtc-a','cmtc-b'):
 base=['kubectl','--context','kind-'+cluster,'-n','cmtc-system']
 for node in (cluster+'-control-plane',cluster+'-worker'):
  name='spire-pins-'+sha[:10]+'-'+node
  job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':'cmtc-system','labels':{'app.kubernetes.io/managed-by':'cmtc-local-validation','security.cmtc.io/trial':'spire-journal-28f6b8d84a'}},'spec':{'activeDeadlineSeconds':120,'backoffLimit':0,'template':{'metadata':{'labels':{'app.kubernetes.io/name':'ztunnel-image-validation'}},'spec':{'nodeName':node,'restartPolicy':'Never','automountServiceAccountToken':False,'tolerations':[{'operator':'Exists'}],'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'version','image':image,'imagePullPolicy':'Never','command':['/opt/spire/bin/spire-server'],'args':['--version'],'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'128Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}}}
  created=json.loads(run(base+['create','-f','-','-o','json'],input=json.dumps(job),stdout=subprocess.PIPE).stdout)
  uid=created['metadata']['uid']
  try:
   run(base+['wait','--for=condition=Complete','job/'+name,'--timeout=120s'],stdout=subprocess.PIPE)
   log=get(base+['logs','job/'+name])
   assert sha in log,log
   (out/(name+'.log')).write_text(log)
   pods=json.loads(get(base+['get','pods','-l','job-name='+name,'-o','json']))['items']
   assert len(pods)==1 and pods[0]['status']['phase']=='Succeeded'
   pod=pods[0]; status=pod['status']['containerStatuses'][0]
   observed=status['imageID'].split('://')[-1].split('@')[-1]
   accepted={config}|{ref.split('@')[-1] for ref in verified[node]['repoDigests']}
   assert observed in accepted,(node,observed,accepted)
   assert pod['spec']['nodeName']==node and status['state']['terminated']['exitCode']==0
   (out/(name+'-pod.json')).write_text(json.dumps(pod,indent=2)+'\n')
   verified[node]['versionJob']={'uid':uid,'podUID':pod['metadata']['uid'],'podImageID':status['imageID'],'version':log.strip(),'exitCode':0}
   print('PASS',node,config,flush=True)
  finally:
   current=json.loads(get(base+['get','job',name,'-o','json']))
   assert current['metadata']['uid']==uid
   rv=current['metadata']['resourceVersion']
   options={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':uid,'resourceVersion':rv}}
   uri=f'/apis/batch/v1/namespaces/cmtc-system/jobs/{name}'
   run(base+['delete','--raw',uri,'-f','-'],input=json.dumps(options),stdout=subprocess.PIPE)
   run(base+['wait','--for=delete','job/'+name,'--timeout=90s'],stdout=subprocess.PIPE)
   cleanup.append({'name':name,'uid':uid,'deleted':True})
   (out/'version-job-cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
   (out/'loaded-images.json').write_text(json.dumps(verified,indent=2)+'\n')
assert len(cleanup)==4
print('All four exact-image version Jobs passed and were UID-safely removed. SPIRE server rollout is a separate next step.',flush=True)
