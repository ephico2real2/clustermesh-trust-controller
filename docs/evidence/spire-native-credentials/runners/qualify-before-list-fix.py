from pathlib import Path
import datetime as dt,json,os,secrets,subprocess,sys,time,urllib.parse
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');OUT=Path('/private/tmp/cmtc-native-credentials-20261025');sys.path.insert(0,str(ROOT/'scripts/lab/spire'))
import workload_api as w
import qualify_workload as q
PINS=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text());IMAGE=json.loads(Path('/private/tmp/cmtc-native-credential-image-20261025/image-pin.json').read_text());SERVER=json.loads(Path('/private/tmp/cmtc-spire-recovery-20261024/image-pin.json').read_text());PUB=json.loads(Path('/Users/olasumbo/.local/share/cmtc-issuer-profile/live-a-b/ledger.json').read_text());STATE=OUT/'ledger.json'
if STATE.exists():
 assert sys.argv[1:]==['--resume'], 'existing ownership ledger; explicit resume required'
 ledger=json.loads(STATE.read_text())
 assert all(ledger['image'][k]==IMAGE[k] for k in ['sourceSHA','image','configurationID','architecture'])
 ledger.setdefault('imagePinHistory',[]).append(ledger['image']);ledger['image']=IMAGE
else:
 assert not sys.argv[1:]
 ledger={'owner':secrets.token_hex(12),'image':IMAGE,'clusters':{},'scope':'native workload credentials only; no traffic proxy or encryption claim'}
def save():
 temp=STATE.with_suffix('.tmp');temp.write_text(json.dumps(ledger,indent=2)+'\n');os.chmod(temp,0o600);os.replace(temp,STATE)
def run(args,input=None,timeout=40,check=True):
 p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
 assert 'PRIVATE KEY' not in p.stdout and 'PRIVATE KEY' not in p.stderr,'unsafe output suppressed'
 if check and p.returncode:raise RuntimeError(f'bounded command failed {args[:5]}: {p.stderr[:5000]}')
 return p
class API:
 def __init__(self,c):self.c=c;self.argv=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c,'--request-timeout=25s']
 def get(self,path):return json.loads(run(self.argv+['get','--raw',path]).stdout)
 def k(self,*args,input=None,timeout=40):return run(self.argv+list(args),input,timeout)
 def create(self,obj):
  name=obj['metadata']['name'];kind=obj['kind'];ns=obj['metadata'].get('namespace');state=ledger['clusters'][self.c];key=kind+'/'+(ns+'/' if ns else '')+name
  obj['metadata'].setdefault('labels',{})['security.cmtc.io/credential-owner']=ledger['owner']
  if key in state['objects']:
   prior=state['objects'][key];assert prior.get('uid') and prior['intent']==obj,'unknown create outcome or changed intent; no adoption'
   resource={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Pod':'pods'}[kind]
   path='/api/v1/'+('namespaces/'+ns+'/' if ns else '')+resource+'/'+name
   current=self.get(path);m=current['metadata'];assert m['uid']==prior['uid'] and not m.get('deletionTimestamp') and m.get('labels',{}).get('security.cmtc.io/credential-owner')==ledger['owner']
   for k,v in obj['metadata'].get('labels',{}).items():assert m['labels'].get(k)==v
   for k,v in obj.items():
    if k!='metadata':assert current.get(k)==v,'owned object spec drift'
   return current
  state['objects'][key]={'intent':obj};save()
  created=json.loads(self.k('create','-f','-','-o','json',input=json.dumps(obj)).stdout);state['objects'][key]['uid']=created['metadata']['uid'];save();return created

def proof(api,label):
 c=api.c;pod=api.get('/api/v1/namespaces/cilium-spire/pods/spire-server-0')
 cmd=[sys.executable,str(ROOT/'scripts/lab/spire/public_proof.py'),'--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--cluster',c,'--cluster-uid',PINS[c]['clusterUID'],'--pod-uid',pod['metadata']['uid'],'--approval-uid',PUB['identity']['approvalPins'][c],'--root-sha256',PUB['identity']['rootSHA256'],'--pki-module',str(ROOT/'scripts/lab/pki/pki.py'),'--server-image',SERVER['canonicalImage']]
 value=json.loads(run(cmd,timeout=90).stdout);(OUT/(c+'-'+label+'-issuer-proof.json')).write_text(json.dumps(value,indent=2)+'\n');return value

def entry_list(api):return q.server_cli(api,['entry','show','-socketPath',w.r.SERVER_SOCKET,'-output','json']).get('entries',[])
def register(api,wanted):
 c=ledger['clusters'][api.c];current=entry_list(api)
 assert not any(e['id']==wanted['entryID'] for e in current),'registration ID collision'
 # Reject an unknown broad entry for the same identity. Other entries created
 # by this exact run may select another exact Pod on the same trust domain.
 for e in current:
  sid='spiffe://'+e['spiffe_id']['trust_domain']+e['spiffe_id']['path']
  if sid==wanted['spiffeID']:
   assert e['id'] in c['entries'],'unknown entitlement for requested identity'
   w.compare_entry(e,c['entries'][e['id']]['wanted'])
 c['entries'][wanted['entryID']]={'wanted':wanted,'phase':'create-intended'};save()
 result=q.server_cli(api,wanted['createArguments']+['-output','json']);c['entries'][wanted['entryID']]['response']=result;save()
 exact=q.show_exact(api,wanted);c['entries'][wanted['entryID']].update(phase='verified',actual=exact);save()

def wait_pod(api,pod):
 name=pod['metadata']['name'];ns=pod['metadata']['namespace'];uid=pod['metadata']['uid']
 api.k('-n',ns,'wait','--for=condition=Ready','pod/'+name,'--timeout=100s',timeout=115)
 p=api.get(f'/api/v1/namespaces/{ns}/pods/{name}');assert p['metadata']['uid']==uid and p['spec']['containers'][0]['image']==IMAGE['canonicalImage']
 assert not p['metadata'].get('deletionTimestamp') and all(s['ready'] for s in p['status']['containerStatuses'])
 node=p['spec']['nodeName'];assert api.get('/api/v1/nodes/'+node)['metadata']['uid']==PINS[api.c]['nodes'][node]
 statuses=p['status']['containerStatuses'];accepted=json.loads(Path('/private/tmp/cmtc-native-credential-image-20261025/canonical-'+node+'.json').read_text())['status']['repoDigests']
 assert statuses[0]['imageID'].split('://')[-1].split('@')[-1] in {IMAGE['importedManifestDigest']}|{x.split('@')[-1] for x in accepted}
 v=api.k('-n',ns,'exec',name,'-c','probe','--',q.BINARY,'version');assert IMAGE['sourceSHA'] in v.stdout and 'BuildStatus:"Clean"' in v.stdout
 return p

save()
for cluster in ['cmtc-a','cmtc-b']:
 api=API(cluster);assert api.get('/api/v1/namespaces/kube-system')['metadata']['uid']==PINS[cluster]['clusterUID']
 nodes=api.get('/api/v1/nodes')['items'];assert {n['metadata']['name']:n['metadata']['uid'] for n in nodes}==PINS[cluster]['nodes']
 ns='cmtc-credential-'+ledger['owner'][:10]
 state=ledger['clusters'].setdefault(cluster,{'phase':'prepare','namespace':ns,'objects':{},'entries':{},'probes':{},'positive':{},'negative':{}});assert state['namespace']==ns;save()
 namespace=api.create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'pod-security.kubernetes.io/enforce':'privileged'}}});state['namespaceUID']=namespace['metadata']['uid'];save()
 api.create({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'node-probe','namespace':ns},'automountServiceAccountToken':False})
 for node in sorted(nodes,key=lambda n:n['metadata']['name']):
  record={'name':node['metadata']['name'],'uid':node['metadata']['uid']}
  wanted_pod=w.probe_pod(cluster,record,IMAGE['canonicalImage'],namespace=ns,service_account='node-probe')
  wanted_pod['spec']['containers'][0]['resources']={'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'128Mi'}}
  p=wait_pod(api,api.create(wanted_pod));state['probes'][record['name']]=p;save()
  wanted=w.registration(cluster,w.r.CLUSTERS[cluster],PINS[cluster]['clusterUID'],{'pod':p,'namespaceUID':state['namespaceUID']},record,'delegate');register(api,wanted)
 backends=api.get('/api/v1/namespaces/mesh-example/pods?labelSelector='+urllib.parse.quote('name=rebel-base,mesh.cmtc.io/cluster='+cluster,safe=''))['items']
 assert len(backends)==2 and {p['spec']['nodeName'] for p in backends}==set(PINS[cluster]['nodes'])
 namespaceUID=api.get('/api/v1/namespaces/mesh-example')['metadata']['uid'];state['targetNamespaceUID']=namespaceUID;save()
 for pod in sorted(backends,key=lambda p:p['spec']['nodeName']):
  node=pod['spec']['nodeName'];record={'name':node,'uid':PINS[cluster]['nodes'][node]}
  wanted=w.registration(cluster,w.r.CLUSTERS[cluster],PINS[cluster]['clusterUID'],{'pod':pod,'namespaceUID':namespaceUID},record,'workload');register(api,wanted)
  issuer=proof(api,'before-'+node)
  result=q.native_fetch(api,probe_pod=state['probes'][node],wanted=wanted,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);state['positive'][node]={'registration':wanted,'result':result};save();print('PASS',cluster,node,'actual native held-process credential, exact workload SVID/current signer, no private output',flush=True)
 state['phase']='four-node-native-positive-in-progress';save()
ledger['positivePassed']=True;save()
