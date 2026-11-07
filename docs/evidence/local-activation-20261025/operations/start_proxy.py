from pathlib import Path
import json,subprocess,sys,time,uuid
c=sys.argv[1];assert c in ['cmtc-a','cmtc-b'];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c];O=Path('/private/tmp/cmtc-primary-operations-20261025')/('activation-'+c)
def kj(*a):return json.loads(subprocess.check_output(K+list(a)+['-o','json']))
ps=kj('-n','kube-system','get','pods','-l','k8s-app=cilium')['items'];assert len(ps)==2
assert all(any(z['type']=='Ready' and z['status']=='True' for z in p['status'].get('conditions',[])) for p in ps)
assert all(any(v['name']=='ztunnel-issuer-pins' for v in p['spec']['volumes']) for p in ps),'All agents must have activated mounts'
digest=None;images=[]
for n in kj('get','nodes')['items']:
 node=n['metadata']['name'];base=['docker','--context','colima-cmtc-cilium','exec',node]
 tag='localhost/cmtc-ztunnel:native-35a6c9403e'
 image=json.loads(subprocess.check_output(base+['crictl','inspecti','-o','json',tag]))['status']
 assert image['id'].removeprefix('sha256:')=='ae3844096b580049c05d8be6520491eb339a1b583a6d1143b3b50ca992c17df9'
 d=json.loads((O.parent/'canonical-proxy-manifest.json').read_text())['digest']
 if digest is None:digest=d
 assert d==digest
 listing=subprocess.check_output(base+['ctr','-n','k8s.io','images','ls'],text=True)
 assert any(line.split()[0]==tag and line.split()[2]==d for line in listing.splitlines()[1:] if line.strip()), 'Tag is not the canonical OCI descriptor'
 alias='localhost/cmtc-ztunnel@'+d
 r=subprocess.run(base+['crictl','inspecti','-o','json',alias],capture_output=True,text=True)
 if r.returncode:
  subprocess.run(base+['ctr','-n','k8s.io','images','tag',tag,alias],check=True,stdout=subprocess.DEVNULL)
 result=json.loads(subprocess.check_output(base+['crictl','inspecti','-o','json',alias]))['status']
 assert result['id']==image['id'];images.append({'node':node,'reference':alias,'configID':image['id']})
(O/'proxy-image-aliases.json').write_text(json.dumps(images,indent=2)+'\n')
objects=json.loads((O/'ztunnel-ready.json').read_text())
for obj in objects['items']:
 if obj['kind']=='DaemonSet':
  ctr=obj['spec']['template']['spec']['containers'][0];ctr['image']='localhost/cmtc-ztunnel@'+digest
  ctr['env'].append({'name':'AUTHZ_POLICY_INFO_LOGGING','value':'true'})
  assert obj['spec']['updateStrategy']['type']=='OnDelete'
p=O/'ztunnel-applied.json';p.write_text(json.dumps(objects,indent=2)+'\n')
subprocess.run(K+['apply','-f',str(p)],check=True)
entries=[];deadline=time.time()+60
while time.time()<deadline:
 pods=kj('-n','kube-system','get','pods','-l','app=ztunnel-cilium')['items']
 if len(pods)==2 and all(p['spec'].get('nodeName') for p in pods):break
 time.sleep(2)
else:raise SystemExit('Proxy Pods not assigned within60s')
def server(*a):return subprocess.run(K+['-n','cilium-spire','exec','spire-server-0','-c','register-agent-node','--','/bin/timeout','-s','KILL','12','/spire-cli/opt/spire/bin/spire-server',*a,'-socketPath','/tmp/spire-server/private/api.sock'],text=True,capture_output=True,timeout=30)
for pod in pods:
 m=pod['metadata'];s=pod['spec'];sels=['k8s:ns:kube-system','k8s:sa:'+s['serviceAccountName'],'k8s:pod-uid:'+m['uid'],'k8s:node-name:'+s['nodeName']]
 entry={'id':str(uuid.uuid5(uuid.NAMESPACE_URL,'cmtc-live-activation:'+c+':'+m['uid'])),'pod':m['name'],'uid':m['uid'],'node':s['nodeName'],'selectors':sels}
 entries.append(entry);(O/'delegate-entries.json').write_text(json.dumps(entries,indent=2)+'\n')
 args=['entry','create','-entryID',entry['id'],'-parentID','spiffe://'+c+'.mesh.example/ns/cilium-spire/sa/spire-agent','-spiffeID','spiffe://'+c+'.mesh.example/ztunnel-proxy','-x509SVIDTTL','120']
 for sel in sels:args+=['-selector',sel]
 r=server(*args);assert r.returncode==0,r.stderr[:1500]+r.stdout[:1500]
 read=server('entry','show','-entryID',entry['id'],'-output','json');assert read.returncode==0
 vals=json.loads(read.stdout)['entries'];assert len(vals)==1
 assert sorted(x['type']+':'+x['value'] for x in vals[0]['selectors'])==sorted(sels)
 entry['readback']=True;(O/'delegate-entries.json').write_text(json.dumps(entries,indent=2)+'\n')
 print(c,'exact proxy delegate registered',s['nodeName'],m['uid'],flush=True)
print(c,'proxies deployed; awaiting profile checkpoints and actual ready state',flush=True)
