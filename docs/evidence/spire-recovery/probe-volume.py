from pathlib import Path
import json,subprocess
out=Path('/private/tmp/cmtc-spire-recovery-20261024');pin=json.loads((out/'image-pin.json').read_text());image=pin['canonicalImage'];busy='docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e'
def run(c,*args,data=None):
 p=subprocess.run(['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c,*args],input=json.dumps(data) if data is not None else None,text=True,capture_output=True,timeout=40)
 if p.returncode:raise RuntimeError(p.stderr)
 return p.stdout
for c in ['cmtc-a','cmtc-b']:
 name='spire-cli-digest-28f6b8d84a';job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':'cilium-spire','labels':{'app.kubernetes.io/managed-by':'cmtc-local-validation'}},'spec':{'backoffLimit':0,'activeDeadlineSeconds':90,'template':{'spec':{'nodeName':c+'-worker','automountServiceAccountToken':False,'restartPolicy':'Never','securityContext':{'runAsNonRoot':True,'runAsUser':1000,'runAsGroup':1000,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'cli','image':busy,'imagePullPolicy':'IfNotPresent','command':['/bin/sh','-ec','exec /spire/opt/spire/bin/spire-server --version'],'resources':{'limits':{'cpu':'200m','memory':'64Mi'}},'volumeMounts':[{'name':'cli','mountPath':'/spire','readOnly':True}],'securityContext':{'readOnlyRootFilesystem':True,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}}}],'volumes':[{'name':'cli','image':{'reference':image,'pullPolicy':'IfNotPresent'}}]}}}}
 ack=json.loads(run(c,'create','-f','-','-o','json',data=job));uid=ack['metadata']['uid'];(out/(c+'-cli-probe-created.json')).write_text(json.dumps(ack,indent=2)+'\n')
 try:
  run(c,'-n','cilium-spire','wait','--for=condition=Complete','job/'+name,'--timeout=35s');log=run(c,'-n','cilium-spire','logs','job/'+name);assert pin['sourceSHA'] in log;(out/(c+'-cli-probe.log')).write_text(log)
 finally:
  current=json.loads(run(c,'-n','cilium-spire','get','job',name,'-o','json'));assert current['metadata']['uid']==uid
  run(c,'delete','--raw','/apis/batch/v1/namespaces/cilium-spire/jobs/'+name,'-f','-',data={'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':uid,'resourceVersion':current['metadata']['resourceVersion']}})
  run(c,'-n','cilium-spire','wait','--for=delete','job/'+name,'--timeout=35s');(out/(c+'-cli-probe-cleanup.json')).write_text(json.dumps({'uid':uid,'deleted':True})+'\n')
 print(c,'PASS immutable digest CLI image-volume executes exact ARM64 source',flush=True)
