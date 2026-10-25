from pathlib import Path
import datetime,hashlib,importlib.util,json,os,secrets,subprocess,time,sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');OUT=Path('/private/tmp/cmtc-spire-workload-runtime-20261024')
sys.path.insert(0,str(ROOT/'scripts/lab/spire'));import workload_api as w
PINS=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text());PIN=json.loads((OUT/'image-pin.json').read_text());SERVER=json.loads(Path('/private/tmp/cmtc-spire-recovery-20261024/image-pin.json').read_text());PUB=json.loads(Path('/Users/olasumbo/.local/share/cmtc-issuer-profile/live-a-b/ledger.json').read_text())
LEDGER=OUT/'workload-ledger.json';assert not LEDGER.exists(),'existing ownership ledger: review/resume, never reset'
ledger={'owner':secrets.token_hex(16),'agentImage':PIN,'clusters':{},'scope':'node Workload/Admin socket bootstrap, not workload mTLS'}
def save():
 temp=LEDGER.with_suffix('.tmp');temp.write_text(json.dumps(ledger,indent=2)+'\n');os.chmod(temp,0o600);os.replace(temp,LEDGER)
def run(args,input=None,timeout=40,check=True):
 p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
 assert 'PRIVATE KEY' not in p.stdout and 'PRIVATE KEY' not in p.stderr,'unsafe output suppressed'
 if check and p.returncode:raise RuntimeError(f'command failed {args[:6]}: {p.stderr[:3500]}')
 return p

def k(c,*args,input=None,timeout=40):return run(['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c,'--request-timeout=25s',*args],input,timeout)
def get(c,*args):return json.loads(k(c,*args,'-o','json').stdout)
def record(name,obj): (OUT/name).write_text(json.dumps(obj,indent=2)+'\n')
def proof(c,label):
 pod=get(c,'-n','cilium-spire','get','pod','spire-server-0')
 cmd=[sys.executable,str(ROOT/'scripts/lab/spire/public_proof.py'),'--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--cluster',c,'--cluster-uid',PINS[c]['clusterUID'],'--pod-uid',pod['metadata']['uid'],'--approval-uid',PUB['identity']['approvalPins'][c],'--root-sha256',PUB['identity']['rootSHA256'],'--pki-module',str(ROOT/'scripts/lab/pki/pki.py'),'--server-image',SERVER['canonicalImage']]
 value=json.loads(run(cmd,timeout=90).stdout);record(c+'-bootstrap-proof-'+label+'.json',value);return value
save()
for c in ['cmtc-a','cmtc-b']:
 assert get(c,'get','namespace','kube-system')['metadata']['uid']==PINS[c]['clusterUID']
 nodes=get(c,'get','nodes')['items'];assert {n['metadata']['name']:n['metadata']['uid'] for n in nodes}==PINS[c]['nodes']
 # Keep existing routing configuration, server authority and issuer producers.
 state={'phase':'preflight','baselineCiliumDS':get(c,'-n','kube-system','get','daemonset','cilium'),'baselineCiliumCM':get(c,'-n','kube-system','get','configmap','cilium-config'),'baselineServer':get(c,'-n','cilium-spire','get','statefulset','spire-server'),'baselinePVC':get(c,'-n','cilium-spire','get','pvc','spire-data-spire-server-0'),'baselineProducer':get(c,'-n','cmtc-system','get','deployment','cmtc-controller'),'baselinePublication':get(c,'-n','cmtc-system','get','configmap','cmtc-issuer-publication'),'configMaps':{}}
 ledger['clusters'][c]=state;save()
 assert '--issuer-profile-producer=true' in state['baselineProducer']['spec']['template']['spec']['containers'][0]['args']
 before=proof(c,'before');state['signerSHA256']=before['directIssuerSHA256'];save()
 ds=get(c,'-n','cilium-spire','get','daemonset','spire-agent');cm=get(c,'-n','cilium-spire','get','configmap','spire-agent')
 records=[]
 for n in nodes:
  name=n['metadata']['name'];ip=next(a['address'] for a in n['status']['addresses'] if a['type']=='InternalIP')
  raw=(OUT/(name+'-kubelet-public.pem')).read_bytes();certs=x509.load_pem_x509_certificates(raw);assert len(certs)==2
  # Re-read the pinned node's public chain immediately before approving it.
  current=run(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',name,'cat','/var/lib/kubelet/pki/kubelet.crt'],timeout=25).stdout.encode();assert current==raw
  probe=run(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',name,'sh','-ec',f'test ! -e /run/cmtc-spire/{c}; test ! -L /run/cmtc-spire; test ! -L /run/cmtc-spire/{c}'],timeout=25);assert probe.returncode==0
  cri=json.loads(run(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',name,'crictl','inspecti',PIN['canonicalImage']],timeout=25).stdout);assert cri['status']['id']==PIN['configurationID'] and cri['info']['imageSpec']['architecture']=='arm64'
  records.append({'name':name,'uid':n['metadata']['uid'],'ip':ip,'kubeletCertificatePEM':raw.decode(),'kubeletCertificateSHA256':certs[0].fingerprint(hashes.SHA256()).hex(),'kubeletCASHA256':certs[1].fingerprint(hashes.SHA256()).hex()})
 snap={'schema':'cmtc-workload-api-plan-input/v1','cluster':c,'clusterUID':PINS[c]['clusterUID'],'domain':w.r.CLUSTERS[c],'nodes':records,'expectedNodes':list(PINS[c]['nodes']),'approvedAgentImage':PIN['canonicalImage'],'approvedAgentSource':PIN['sourceSHA'],'agentDaemonSet':ds,'agentConfigMap':cm,'delegateNamespace':'cmtc-workload-api-lab','delegateServiceAccount':'node-probe','delegates':[],'workloads':[]}
 plan=w.make_plan(snap);record(c+'-bootstrap-input.json',snap);record(c+'-bootstrap-plan.json',plan);state.update(originalAgent=ds,plan=plan);save()
 for obj in plan['configMaps']:
  obj['metadata']['annotations']={'security.cmtc.io/workload-api-owner':ledger['owner']};name=obj['metadata']['name'];state['configMaps'][name]={'intent':obj};save()
  created=json.loads(k(c,'create','-f','-','-o','json',input=json.dumps(obj)).stdout);state['configMaps'][name]['uid']=created['metadata']['uid'];save()
  observed=get(c,'-n','cilium-spire','get','configmap',name);assert observed['metadata']['uid']==created['metadata']['uid'] and observed['data']==obj['data'] and observed['immutable'] is True and observed['metadata']['annotations']==obj['metadata']['annotations']
 # API defaulting must accept the exact patch before a real rollout.
 dry=k(c,'-n','cilium-spire','patch','daemonset','spire-agent','--type=json','--dry-run=server','-p',json.dumps(plan['daemonSetPatch']),'-o','json');record(c+'-bootstrap-dry-run.json',json.loads(dry.stdout));state['expectedTemplate']=json.loads(dry.stdout)['spec']['template'];save()
 state['phase']='patching-agent';save()
 result=k(c,'-n','cilium-spire','patch','daemonset','spire-agent','--type=json','-p',json.dumps(plan['daemonSetPatch']),'-o','json');record(c+'-agent-patch-response.json',json.loads(result.stdout));state['phase']='waiting-agent';save()
 ready=k(c,'-n','cilium-spire','rollout','status','daemonset/spire-agent','--timeout=180s',timeout=195);(OUT/(c+'-agent-rollout.log')).write_text(ready.stdout+ready.stderr)
 afterds=get(c,'-n','cilium-spire','get','daemonset','spire-agent');assert afterds['metadata']['uid']==ds['metadata']['uid'] and afterds['spec']['template']==state['expectedTemplate'];assert afterds['status']['numberReady']==2
 pods=get(c,'-n','cilium-spire','get','pods','-l','app=spire-agent')['items'];assert len(pods)==2 and {p['spec']['nodeName'] for p in pods}==set(PINS[c]['nodes'])
 for pod in pods:
  assert not pod['metadata'].get('deletionTimestamp') and pod['status']['phase']=='Running';cs=pod['status']['containerStatuses'];assert len(cs)==1 and cs[0]['ready'] and pod['spec']['containers'][0]['image']==PIN['canonicalImage']
  assert cs[0]['imageID'].split('://')[-1].split('@')[-1] in {PIN['importedManifestDigest']}|{x.split('@')[-1] for x in json.loads((OUT/('canonical-'+pod['spec']['nodeName']+'.json')).read_text())['status']['repoDigests']}
  version=k(c,'-n','cilium-spire','exec',pod['metadata']['name'],'-c','spire-agent','--','/opt/spire/bin/spire-agent','--version');assert PIN['sourceSHA'] in version.stdout+version.stderr
 record(c+'-running-agents.json',pods)
 assert get(c,'-n','kube-system','get','daemonset','cilium')['spec']==state['baselineCiliumDS']['spec']
 assert get(c,'-n','kube-system','get','configmap','cilium-config')['data']==state['baselineCiliumCM']['data']
 currentserver=get(c,'-n','cilium-spire','get','statefulset','spire-server');assert currentserver['metadata']['uid']==state['baselineServer']['metadata']['uid'] and currentserver['spec']==state['baselineServer']['spec']
 assert get(c,'-n','cilium-spire','get','pvc','spire-data-spire-server-0')['metadata']['uid']==state['baselinePVC']['metadata']['uid']
 currentprod=get(c,'-n','cmtc-system','get','deployment','cmtc-controller');assert currentprod['metadata']['uid']==state['baselineProducer']['metadata']['uid'] and currentprod['spec']==state['baselineProducer']['spec']
 currentpub=get(c,'-n','cmtc-system','get','configmap','cmtc-issuer-publication');assert currentpub['metadata']['uid']==state['baselinePublication']['metadata']['uid']
 state['publicationAfter']=currentpub
 assert {n['metadata']['name']:n['metadata']['uid'] for n in get(c,'get','nodes')['items']}==PINS[c]['nodes']
 after=proof(c,'after');assert after['directIssuerSHA256']==before['directIssuerSHA256']
 state['phase']='agent-bootstrap-ready-no-workload-proof';save();print('PASS',c,'exact agent image, secure kubelet config, node sockets, preserved server/signer/producer/Cilium',flush=True)
ledger['success']=True;save()
