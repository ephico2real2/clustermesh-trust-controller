from pathlib import Path
import sys,json,time
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
assert ledger['registrationRecoveryPassed']
for cluster,state in ledger['clusters'].items():
 api=API(cluster);node=next(n for n in state['positive'] if 'control-plane' in n);probe=state['probes'][node];wanted=state['positive'][node]['registration']
 entries=[e['wanted'] for e in state['entries'].values() if e['wanted']['role']=='delegate' and e['wanted']['podUID']==probe['metadata']['uid']];assert len(entries)==1;delegate=entries[0]
 if state['recovery'].get('delegateReadded'):
  print('PASS',cluster,'previous exact delegate recovery retained',flush=True);continue
 if not state['recovery'].get('delegateRemoval'):
  q.show_exact(api,delegate);state['recovery']['delegateRemoval']={'wanted':delegate,'phase':'delete-intended'};save()
  response=q.server_cli(api,['entry','delete','-socketPath',w.r.SERVER_SOCKET,'-entryID',delegate['entryID'],'-output','json']);assert len(response['results'])==1 and response['results'][0]['id']==delegate['entryID'] and response['results'][0].get('status',{}).get('code',0)==0
  state['recovery']['delegateRemoval'].update(phase='server-entry-deleted',response=response);save()
  start=time.monotonic()
  while True:
   result=q.bounded(api.argv+['exec','-n',state['namespace'],probe['metadata']['name'],'-c','probe','--',q.BINARY,'fetch',wanted['spiffeID'],wanted['podUID'],wanted['podName']],success=False)
   if result.returncode:
    assert 'no identity issued' in result.stderr and not result.stdout.strip()
    state['negative']['removed-delegate']={'credentialDenied':True,'elapsedSeconds':time.monotonic()-start,'publicDiagnostic':result.stderr,'packetProtectionTested':False};save();break
   assert time.monotonic()-start<30;time.sleep(.5)
 register(api,delegate);issuer=proof(api,'delegate-recovery')
 result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=probe,wanted=wanted,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);state['recovery']['delegateReadded']={'wanted':delegate,'result':result};save();print('PASS',cluster,'delegate removed -> PermissionDenied; exact re-add -> verified native SVID',flush=True)
ledger['delegateRecoveryPassed']=True;save()
