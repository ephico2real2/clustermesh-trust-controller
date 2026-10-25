from pathlib import Path
import subprocess,json,sys,datetime
BASE=Path('/private/tmp/cmtc-primary-operations-20261025')
CLUSTER=sys.argv[1]; assert CLUSTER in ['cmtc-a','cmtc-b']
CTX='kind-'+CLUSTER; OTHER='cmtc-b' if CLUSTER=='cmtc-a' else 'cmtc-a'
K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context',CTX]
OUT=BASE/('activation-'+CLUSTER);OUT.mkdir(exist_ok=True)
UIDS={'cmtc-a':'bb7182c7-de95-4e70-816a-a1400d755794','cmtc-b':'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
APP={'cmtc-a':'902e1117-142f-4c91-ada7-65e57b0863e6','cmtc-b':'ba07d872-3ccb-4396-bd60-828f615a9cde'}
PUB={'cmtc-a':'fbc7b3c2-00f1-4787-a149-fca76e274c4e','cmtc-b':'cb6e0317-d887-49be-b265-d24d896c35ef'}
PEER={'cmtc-a':(1,['172.18.0.3','172.18.0.2'],'57eec8f36902aceb097c956c54736cb1e9f8569798a0b8f7649f0eca9dba99ad'),'cmtc-b':(2,['172.18.0.4','172.18.0.5'],'034f5e79a9e5d58ca1c1f624f1415f1dca787966b6740637aa55ebda6726210a')}
ROOT='0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c'
LABEL={'app.kubernetes.io/managed-by':'cmtc-local-qualification'}
def get(*args):return json.loads(subprocess.check_output(K+['get',*args,'-o','json']))
def save(name,value):p=OUT/name;p.write_text(json.dumps(value,indent=2)+'\n');return p
def meta(name,ns='kube-system'):return {'name':name,'namespace':ns,'labels':LABEL}
assert get('ns','kube-system')['metadata']['uid']==UIDS[CLUSTER]
ds=get('ds','cilium','-n','kube-system');cfg=get('cm','cilium-config','-n','kube-system');op=get('deployment','cilium-operator','-n','kube-system')
for name,obj in [('cilium-ds-before.json',ds),('cilium-config-before.json',cfg),('operator-before.json',op)]:
 assert not (OUT/name).exists(),'Existing activation snapshot; preserve and inspect before rerun'
 save(name,obj)
assert cfg['data'].get('cluster-name')==CLUSTER
for name in ['ztunnel-membership-writer','ztunnel-origin-reader','cmtc-ztunnel-ads-server']:
 c=get('certificate',name,'-n','kube-system');assert any(x['type']=='Ready' and x['status']=='True' for x in c['status']['conditions']),name
approval=get('cm','cmtc-issuer-approval-g1','-n','cmtc-system');pub=get('cm','cmtc-issuer-publication','-n','cmtc-system')
assert approval['metadata']['uid']==APP[CLUSTER] and pub['metadata']['uid']==PUB[CLUSTER]
a=json.loads(approval['data']['approval.json']);p=json.loads(pub['data']['profile.json'])
assert p['state']=='published' and p['approvalDigest']=='3ee827dd1f39ff42dd113b2a87f7538ec6ca73af7c5cc0fe0abf136f81b20baf'
assert ROOT in [x['sha256'] for x in a['roots']]
assert datetime.datetime.fromisoformat(p['validUntil'].replace('Z','+00:00'))>datetime.datetime.now(datetime.timezone.utc)
nodeNames=[n['metadata']['name'] for n in get('nodes')['items']];assert len(nodeNames)==2
bootstrap=[]
for node in nodeNames:
 pins={'cluster':CLUSTER,'node':node,'sourceNamespace':'cmtc-system','sourceName':'cmtc-issuer-approval-g1','sourceUID':APP[CLUSTER],'outputNamespace':'cmtc-system','outputName':'cmtc-issuer-publication','outputUID':PUB[CLUSTER],'rootPins':[ROOT],'minimumGeneration':str(p['acceptedGeneration']),'minimumSequence':str(p['sequence']),'approvalDigestAtMinimum':p['approvalDigest'],'publicationDigestAtMinimum':p['digest']}
 save('pins-'+node+'.json',pins)
 code='''set -eu
P=/etc/cmtc/ztunnel-issuer-pins
C=/var/lib/cmtc/ztunnel-issuer-checkpoint
if [ ! -d "$P" ]; then install -d -m 0755 "$P"; fi
[ "$(stat -c %u "$P")" = 0 ]
if [ -e "$P/pins.json" ] || [ -L "$P/pins.json" ]; then echo "Existing pins; preserve and inspect" >&2; exit 73; fi
(umask 022; set -C; cat > "$P/pins.json")
chmod 0644 "$P/pins.json"
chown 0:0 "$P/pins.json"
if [ ! -d "$C" ]; then install -d -m 0700 "$C"; fi
[ "$(stat -c %u "$C")" = 0 ]
[ "$(stat -c %a "$C")" = 700 ]
if [ -z "$(ls -A "$C")" ]; then echo virgin; else echo existing; fi
'''
 r=subprocess.run(['docker','--context','colima-cmtc-cilium','exec','-i',node,'sh','-ec',code],input=json.dumps(pins),text=True,capture_output=True)
 assert r.returncode==0,(node,r.stderr);bootstrap.append(r.stdout.strip())
assert all(x=='virgin' for x in bootstrap),'Existing checkpoint found; preserve and use explicit recovery'
peerid,ips,spki=PEER[OTHER]
membership='endpoints:\n- https://clustermesh-apiserver.kube-system.svc:2379\ntrusted-ca-file: /var/lib/cilium/ztunnel-membership/ca.crt\ncert-file: /var/lib/cilium/ztunnel-membership/tls.crt\nkey-file: /var/lib/cilium/ztunnel-membership/tls.key\n'
origin='endpoints:\n- https://'+OTHER+'.mesh.cilium.io:32379\ntrusted-ca-file: /var/lib/cilium/clustermesh-origin/ca.crt\ncert-file: /var/lib/cilium/clustermesh-origin/tls.crt\nkey-file: /var/lib/cilium/clustermesh-origin/tls.key\ncilium-host-aliases:\n- hostname: '+OTHER+'.mesh.cilium.io\n  ips: '+json.dumps(ips)+'\ncilium-remote-peer:\n  cluster-id: '+str(peerid)+'\n  spki-sha256: ["'+spki+'"]\n'
resources=[{'apiVersion':'v1','kind':'ConfigMap','metadata':meta('ztunnel-membership-etcd'),'data':{'etcd.yaml':membership}},{'apiVersion':'v1','kind':'ConfigMap','metadata':meta('ztunnel-origin-config'),'data':{OTHER:origin}},{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':meta('cilium-ztunnel-issuer-profile','cmtc-system'),'rules':[{'apiGroups':[''],'resources':['configmaps'],'resourceNames':['cmtc-issuer-approval-g1','cmtc-issuer-publication'],'verbs':['get']}]},{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':meta('cilium-ztunnel-issuer-profile','cmtc-system'),'subjects':[{'kind':'ServiceAccount','name':'cilium','namespace':'kube-system'}],'roleRef':{'kind':'Role','name':'cilium-ztunnel-issuer-profile','apiGroup':'rbac.authorization.k8s.io'}}]
save('public-resources.json',{'apiVersion':'v1','kind':'List','items':resources})
rootproj={'configMap':{'name':'cmtc-public-root','items':[{'key':'ca.crt','path':'ca.crt'}]}}
volumes=[];mounts=[]
for role,name,cm,key,path,secret in [('membership','ztunnel-membership','ztunnel-membership-etcd','etcd.yaml','/var/lib/cilium/ztunnel-membership','ztunnel-membership-writer'),('origin','ztunnel-origin','ztunnel-origin-config',OTHER,'/var/lib/cilium/clustermesh-origin','ztunnel-origin-reader')]:
 volumes.append({'name':name,'projected':{'defaultMode':384,'sources':[{'configMap':{'name':cm,'items':[{'key':key,'path':key}]}},rootproj,{'secret':{'name':secret,'items':[{'key':'tls.crt','path':'tls.crt'},{'key':'tls.key','path':'tls.key'}]}}]}})
 mounts.append({'name':name,'mountPath':path,'readOnly':True})
volumes.extend([{'name':'ztunnel-issuer-pins','hostPath':{'path':'/etc/cmtc/ztunnel-issuer-pins','type':'Directory'}},{'name':'cmtc-ztunnel-bootstrap','secret':{'secretName':'cmtc-ztunnel-ads-tls','defaultMode':384,'items':[{'key':'tls.key','path':'bootstrap-private.key'},{'key':'tls.crt','path':'bootstrap-root.crt'}]}}])
mounts.extend([{'name':'ztunnel-issuer-pins','mountPath':'/etc/cmtc/ztunnel-issuer-pins','readOnly':True},{'name':'cmtc-ztunnel-bootstrap','mountPath':'/etc/ztunnel','readOnly':True}])
container=next(c for c in ds['spec']['template']['spec']['containers'] if c['name']=='cilium-agent')
assert not any(m['mountPath']=='/etc/ztunnel' for m in container.get('volumeMounts',[]))
save('agent-mount-patch.json',{'metadata':{'uid':ds['metadata']['uid'],'resourceVersion':ds['metadata']['resourceVersion']},'spec':{'updateStrategy':{'type':'OnDelete','rollingUpdate':None},'template':{'spec':{'volumes':volumes,'containers':[{'name':'cilium-agent','volumeMounts':mounts}]}}}})
data={'enable-ztunnel':'true','ztunnel-ca-type':'spire','ztunnel-require-mtls':'true','ztunnel-effective-policy-quarantine':'true','ztunnel-enable-remote-workload-membership':'true','ztunnel-remote-origin-config-dir':'/var/lib/cilium/clustermesh-origin','ztunnel-remote-origin-client-common-name':'ztunnel-origin-reader','ztunnel-source-membership-etcd-config':'/var/lib/cilium/ztunnel-membership/etcd.yaml','ztunnel-issuer-profile-probe-pins':'/etc/cmtc/ztunnel-issuer-pins/pins.json','mesh-auth-spiffe-trust-domain':CLUSTER+'.mesh.example','ztunnel-spire-external-exact-registrar':'true','prometheus-serve-addr':':9962'}
save('agent-config-patch.json',{'metadata':{'uid':cfg['metadata']['uid'],'resourceVersion':cfg['metadata']['resourceVersion']},'data':data})
mesh={'clusters':[{'clusterId':c,'trustDomain':c+'.mesh.example','podCidrs':['10.10.0.0/16' if c=='cmtc-a' else '10.20.0.0/16'],'serviceCidrs':['10.11.0.0/16' if c=='cmtc-a' else '10.21.0.0/16']} for c in ['cmtc-a','cmtc-b']],'exceptions':[]}
extra=[{'name':n,'value':v} for n,v in [('CLUSTER_ID',CLUSTER),('REQUIRE_INBOUND_MTLS','true'),('REQUIRE_MESH_HBONE','true'),('MESH_EGRESS_CONFIG',json.dumps(mesh,separators=(',',':'))),('ISSUER_PROFILE_PROBE_PINS','/etc/cmtc/ztunnel-issuer-pins/pins.json'),('ISSUER_PROFILE_CHECKPOINT_DIR','/var/lib/cmtc/ztunnel-issuer-checkpoint'),('ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP','true')]]
values={'serviceAccounts':{'ztunnel':{'create':True,'name':'ztunnel-cilium','automount':False}},'authentication':{'mutual':{'spire':{'enabled':True,'trustDomain':CLUSTER+'.mesh.example','adminSocketPath':'/run/cmtc-spire/'+CLUSTER+'/delegated/delegated.sock'}}},'encryption':{'enabled':True,'type':'ztunnel','ztunnel':{'ca':{'type':'spire','externalExactRegistrar':True},'requireMtls':True,'image':{'override':'localhost/cmtc-ztunnel:native-35a6c9403e','useDigest':False,'pullPolicy':'Never'},'spire':{'containerRuntimeSocketPath':'/run/containerd/containerd.sock'},'updateStrategy':{'type':'OnDelete','rollingUpdate':None},'extraEnv':extra,'extraVolumes':[{'name':'issuer-pins','hostPath':{'path':'/etc/cmtc/ztunnel-issuer-pins','type':'Directory'}},{'name':'issuer-checkpoint','hostPath':{'path':'/var/lib/cmtc/ztunnel-issuer-checkpoint','type':'Directory'}}],'extraVolumeMounts':[{'name':'issuer-pins','mountPath':'/etc/cmtc/ztunnel-issuer-pins','readOnly':True},{'name':'issuer-checkpoint','mountPath':'/var/lib/cmtc/ztunnel-issuer-checkpoint','readOnly':False}]}}}
v=save('ztunnel-values.json',values)
raw=OUT/'ztunnel-rendered.yaml'
with raw.open('w') as f:subprocess.run(['helm','template','cilium','/private/tmp/cmtc-opus-final-20261025/cilium/install/kubernetes/cilium','-n','kube-system','-f',str(v),'--show-only','templates/ztunnel/serviceaccount.yaml','--show-only','templates/ztunnel/daemonset.yaml'],stdout=f,check=True)
stream=subprocess.check_output(K+['create','--dry-run=client','-f',str(raw),'-o','json'],text=True)
decoder=json.JSONDecoder(); decoded=[]
while stream.strip():
 stream=stream.lstrip(); obj,end=decoder.raw_decode(stream);decoded.append(obj);stream=stream[end:]
objects={'apiVersion':'v1','kind':'List','items':decoded}
for o in objects['items']:
 o['metadata'].setdefault('labels',{}).update(LABEL)
 if o['kind']=='DaemonSet':
  t=o['spec']['template']['spec'];c=t['containers'][0]
  for e in c['env']:
   if e['name'] in ['XDS_ROOT_CA','CA_ROOT_CA']:e['value']='/etc/ztunnel/bootstrap-ca.crt'
  for v in t['volumes']:
   if v['name']=='cilium-ztunnel-secrets':
    v.pop('secret',None);v['projected']={'defaultMode':420,'sources':[{'secret':{'name':'cmtc-ztunnel-ads-tls','items':[{'key':'tls.crt','path':'bootstrap-root.crt'}]}},{'configMap':{'name':'cmtc-public-root','items':[{'key':'ca.crt','path':'bootstrap-ca.crt'}]}}]}
  assert c['args']==['proxy-mtls','ztunnel'] and t['hostPID'] and t['hostNetwork']
  assert not any('private' in str(x) or 'tls.key' in str(x) for x in t['volumes'])
save('ztunnel-ready.json',objects)
print('Prepared',CLUSTER,'nodes',nodeNames,'virgin checkpoint directories, pinned public profile and rendered strict proxy. No app namespace enrolled yet.')
