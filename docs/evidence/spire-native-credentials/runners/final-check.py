from pathlib import Path
import sys,json
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
BOOT=json.loads(Path('/private/tmp/cmtc-spire-workload-runtime-20261024/workload-ledger.json').read_text());AGENT=json.loads(Path('/private/tmp/cmtc-spire-workload-runtime-20261024/image-pin.json').read_text())
assert all(ledger[k] for k in ['positivePassed','basicNegativesPassed','unregisteredNegativesPassed','registrationRecoveryPassed','delegateRecoveryPassed','allNodeAgentRestartPassed','wrongKubeletCARecoveryPassed'])
for cluster,state in ledger['clusters'].items():
 api=API(cluster);baseline=BOOT['clusters'][cluster];ds=api.get('/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent');assert ds['spec']['template']==baseline['expectedTemplate']
 issuer=proof(api,'final');assert issuer['directIssuerSHA256']==baseline['signerSHA256'];state['final']={'issuerProof':issuer,'positive':{}};save()
 for node,positive in state['positive'].items():
  result=q.native_fetch(api,probe_pod=state['probes'][node],wanted=positive['registration'],issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);state['final']['positive'][node]=result;save()
 agents=api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'];agents=[p for p in agents if not p['metadata'].get('deletionTimestamp')];assert len(agents)==2 and {p['spec']['nodeName'] for p in agents}==set(PINS[cluster]['nodes'])
 for agent in agents:
  assert agent['spec']['containers'][0]['image']==AGENT['canonicalImage'] and all(s['ready'] for s in agent['status']['containerStatuses'])
  version=api.k('-n','cilium-spire','exec',agent['metadata']['name'],'-c','spire-agent','--','/opt/spire/bin/spire-agent','--version');assert AGENT['sourceSHA'] in version.stdout+version.stderr
 assert api.get('/apis/apps/v1/namespaces/kube-system/daemonsets/cilium')['spec']==baseline['baselineCiliumDS']['spec']
 assert api.get('/api/v1/namespaces/kube-system/configmaps/cilium-config')['data']==baseline['baselineCiliumCM']['data']
 server=api.get('/apis/apps/v1/namespaces/cilium-spire/statefulsets/spire-server');assert server['metadata']['uid']==baseline['baselineServer']['metadata']['uid'] and server['spec']==baseline['baselineServer']['spec']
 assert api.get('/api/v1/namespaces/cilium-spire/persistentvolumeclaims/spire-data-spire-server-0')['metadata']['uid']==baseline['baselinePVC']['metadata']['uid']
 controller=api.get('/apis/apps/v1/namespaces/cmtc-system/deployments/cmtc-controller');assert controller['metadata']['uid']==baseline['baselineProducer']['metadata']['uid'] and controller['spec']==baseline['baselineProducer']['spec']
 assert '--issuer-profile-producer=true' in controller['spec']['template']['spec']['containers'][0]['args']
 assert api.get('/api/v1/namespaces/cmtc-system/configmaps/cmtc-issuer-publication')['metadata']['uid']==baseline['baselinePublication']['metadata']['uid']
 assert {n['metadata']['name']:n['metadata']['uid'] for n in api.get('/api/v1/nodes')['items']}==PINS[cluster]['nodes']
 state['final']['agents']=agents;state['phase']='native-credentials-qualified-no-proxy';save();print('PASS',cluster,'final all-node credentials, exact agent revision, preserved Cilium/PKI/producer/NodeUIDs',flush=True)
ledger['finalRuntimeChecksPassed']=True;save()
