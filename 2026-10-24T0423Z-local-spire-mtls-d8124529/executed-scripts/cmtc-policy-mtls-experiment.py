import datetime,json,pathlib,re,subprocess,time
k=['/private/tmp/cmtc-mac-qualification/.tmp/bin/kubectl','--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike']
out=pathlib.Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike/policy-experiment');out.mkdir(exist_ok=True)
def run(args,input=None,check=True):
 r=subprocess.run(k+args,input=input,text=True,capture_output=True,timeout=35)
 if check and r.returncode:raise RuntimeError((args,r.stdout,r.stderr))
 return r

def apply(obj):return run(['apply','-f','-'],json.dumps(obj))
def delete(kind,name,ns=None):return run((['-n',ns] if ns else [])+['delete',kind,name,'--ignore-not-found','--wait=false'],check=False)
server=json.loads(run(['-n','mtls-spike','get','pods','-l','app=mtls-server','-o','json']).stdout)['items'][0]
server_ip=server['status']['podIP']
results={'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'serverPodIP':server_ip,'sourceAgent':'0d787e82f2a54b0f51eec97a39c24556dd3596d5','stages':[]}
# Refuse to reuse/delete resources that were not created by this experiment.
for kind,name,ns in [('cnp','spike-hbone-only','mtls-spike'),('networkpolicy','spike-broad-allow','mtls-spike'),('ccnp','spike-hbone-only',None),('pod','policy-control-worker','mtls-plaintext-control'),('pod','policy-control-server-node','mtls-plaintext-control')]:
 r=run((['-n',ns] if ns else [])+['get',kind,name],check=False)
 if r.returncode==0:raise RuntimeError(f'Owned experiment name already exists: {kind}/{name}')
owned=[]
try:
 for suffix,node in [('worker','cmtc-mtls-worker'),('server-node','cmtc-mtls-control-plane')]:
  name='policy-control-'+suffix
  pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'mtls-plaintext-control','labels':{'app':'cmtc-policy-experiment'}},'spec':{'nodeSelector':{'kubernetes.io/hostname':node},'automountServiceAccountToken':False,'restartPolicy':'Never','tolerations':[{'key':'node-role.kubernetes.io/control-plane','operator':'Exists','effect':'NoSchedule'}],'containers':[{'name':'probe','image':'alpine:3.20','command':['sleep','600'],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'memory':'32Mi'}}}]}}
  apply(pod);owned.append(('pod',name,'mtls-plaintext-control'))
  run(['-n','mtls-plaintext-control','wait','pod/'+name,'--for=condition=Ready','--timeout=30s'])
 def stage(name):
  samples=[]
  cases=[('enrolled-pod-ip','mtls-spike','client','http://'+server_ip+'/'),('enrolled-service','mtls-spike','client','http://server.mtls-spike/'),('unenrolled-cross-node','mtls-plaintext-control','policy-control-worker','http://'+server_ip+'/'),('unenrolled-same-node','mtls-plaintext-control','policy-control-server-node','http://'+server_ip+'/')]
  for case,ns,pod,url in cases:
   r=run(['-n',ns,'exec',pod,'--','wget','-T','3','-S','-O','/dev/null',url],check=False)
   text=r.stdout+r.stderr;(out/(name+'-'+case+'.log')).write_text(text)
   samples.append({'case':case,'commandExit':r.returncode,'http200':'200 OK' in text,'httpStatusLines':re.findall(r'HTTP/\S+\s+\d+[^\n]*',text)})
  for node in ['cmtc-mtls-control-plane','cmtc-mtls-worker']:
   r=subprocess.run(['docker','exec',node,'curl','--silent','--show-error','--max-time','3','-o','/dev/null','-w','%{http_code}','http://'+server_ip+'/'],capture_output=True,text=True,timeout=8)
   (out/(name+'-host-'+node+'.log')).write_text(r.stdout+'\n'+r.stderr)
   samples.append({'case':'host-'+node,'commandExit':r.returncode,'http200':r.stdout.strip()=='200','httpStatus':r.stdout.strip()})
  results['stages'].append({'stage':name,'samples':samples});(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results['stages'][-1]),flush=True)
 stage('baseline')
 spec={'endpointSelector':{'matchLabels':{'app':'mtls-server'}},'ingress':[{'fromEndpoints':[{'matchLabels':{'k8s:io.kubernetes.pod.namespace':'mtls-spike'}}],'toPorts':[{'ports':[{'port':'15008','protocol':'TCP'}]}]}]}
 cnp={'apiVersion':'cilium.io/v2','kind':'CiliumNetworkPolicy','metadata':{'name':'spike-hbone-only','namespace':'mtls-spike'},'spec':spec}
 (out/'cnp-hbone-only.json').write_text(json.dumps(cnp,indent=2)+'\n');apply(cnp);owned.append(('cnp','spike-hbone-only','mtls-spike'));time.sleep(5);stage('cnp-hbone-only')
 knp={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'spike-broad-allow','namespace':'mtls-spike'},'spec':{'podSelector':{'matchLabels':{'app':'mtls-server'}},'policyTypes':['Ingress'],'ingress':[{}]}}
 apply(knp);owned.append(('networkpolicy','spike-broad-allow','mtls-spike'));time.sleep(5);stage('cnp-with-broad-allow')
 spec['ingressDeny']=[{'toPorts':[{'ports':[{'port':'80','protocol':'TCP'}]}]}]
 apply(cnp);time.sleep(5);stage('cnp-explicit-port-deny')
 delete('cnp','spike-hbone-only','mtls-spike');owned.remove(('cnp','spike-hbone-only','mtls-spike'))
 cc_spec=json.loads(json.dumps(spec));cc_spec['endpointSelector']['matchLabels']['k8s:io.kubernetes.pod.namespace']='mtls-spike'
 ccnp={'apiVersion':'cilium.io/v2','kind':'CiliumClusterwideNetworkPolicy','metadata':{'name':'spike-hbone-only'},'spec':cc_spec}
 (out/'ccnp-hbone-only-explicit-deny.json').write_text(json.dumps(ccnp,indent=2)+'\n');apply(ccnp);owned.append(('ccnp','spike-hbone-only',None));time.sleep(5);stage('ccnp-explicit-port-deny')
finally:
 for kind,name,ns in reversed(owned):delete(kind,name,ns)
 results['temporaryPoliciesRemoved']=True
 (out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
 print('Removed only the experiment-owned policies and probe pods',flush=True)
