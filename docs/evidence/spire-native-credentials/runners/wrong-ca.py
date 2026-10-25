from pathlib import Path
import sys,json,time,copy
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
sys.path.insert(0,str(ROOT/'scripts/lab/pki'));import pki
BOOT=json.loads(Path('/private/tmp/cmtc-spire-workload-runtime-20261024/workload-ledger.json').read_text())
assert ledger['allNodeAgentRestartPassed'] and not ledger.get('wrongCAFixture'),'one owned fixture only; inspect prior ledger before resume'
cluster='cmtc-a';state=ledger['clusters'][cluster];api=API(cluster);node=next(n for n in state['positive'] if 'control-plane' in n);other=next(n for n in state['positive'] if n!=node)
path='/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent';ds=api.get(path);original=copy.deepcopy(ds['spec']['template']);assert original==BOOT['clusters'][cluster]['expectedTemplate']
volume=next(v for v in original['spec']['volumes'] if v['name']=='cmtc-kubelet-pins');ca=api.get('/api/v1/namespaces/cilium-spire/configmaps/'+volume['configMap']['name']);assert ca['immutable'] and ca['data'][node+'.pem']!=ca['data'][other+'.pem']
obj={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'cmtc-wrong-kubelet-ca-'+ledger['owner'][:10],'namespace':'cilium-spire','labels':{'security.cmtc.io/credential-owner':ledger['owner']}},'immutable':True,'data':copy.deepcopy(ca['data'])};obj['data'][node+'.pem']=ca['data'][other+'.pem']
fixture={'cluster':cluster,'node':node,'phase':'create-intended','intent':obj,'originalDaemonSet':ds};ledger['wrongCAFixture']=fixture;save()
created=json.loads(api.k('create','-f','-','-o','json',input=json.dumps(obj)).stdout);fixture['configMap']=created;save()
changed=copy.deepcopy(original);next(v for v in changed['spec']['volumes'] if v['name']=='cmtc-kubelet-pins')['configMap']['name']=created['metadata']['name']
def patch_template(expected,wanted,label):
 current=api.get(path);m=current['metadata'];assert m['uid']==ds['metadata']['uid'] and current['spec']['template']==expected
 ops=[{'op':'test','path':'/metadata/uid','value':m['uid']},{'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']},{'op':'test','path':'/spec/template','value':expected},{'op':'replace','path':'/spec/template','value':wanted}]
 dry=json.loads(api.k('-n','cilium-spire','patch','daemonset','spire-agent','--type=json','--dry-run=server','-p',json.dumps(ops),'-o','json').stdout);assert dry['spec']['template']==wanted
 response=json.loads(api.k('-n','cilium-spire','patch','daemonset','spire-agent','--type=json','-p',json.dumps(ops),'-o','json').stdout);assert response['spec']['template']==wanted
 fixture[label]=response;save();api.k('-n','cilium-spire','rollout','status','daemonset/spire-agent','--timeout=180s',timeout=195)
 return api.get(path)
try:
 fixture['phase']='installing-wrong-ca';save();patch_template(original,changed,'wrongCAPatch')
 pods=api.get('/api/v1/namespaces/cilium-spire/pods?labelSelector=app%3Dspire-agent')['items'];selected=[p for p in pods if p['spec']['nodeName']==node and not p['metadata'].get('deletionTimestamp')];assert len(selected)==1;agent=selected[0];fixture['wrongCAAgent']=agent;save()
 wanted=state['positive'][node]['registration'];probe=state['probes'][node];q.show_exact(api,wanted)
 result=q.bounded(api.argv+['exec','-n',state['namespace'],probe['metadata']['name'],'-c','probe','--',q.BINARY,'fetch',wanted['spiffeID'],wanted['podUID'],wanted['podName']],success=False)
 assert result.returncode!=0 and not result.stdout.strip(),'wrong kubelet CA unexpectedly issued a native SVID'
 logs=api.k('-n','cilium-spire','logs',agent['metadata']['name'],'-c','spire-agent','--tail=80').stdout
 assert 'x509: certificate signed by unknown authority' in logs,'actual kubelet TLS cause missing from new agent logs'
 fixture.update(phase='wrong-ca-credential-rejected',credentialDiagnostic=result.stderr,agentLogs=logs,wrongCARejected=True);save();print('PASS wrong kubelet CA causes actual attestation TLS rejection; no SVID emitted',flush=True)
finally:
 current=api.get(path)
 if current['spec']['template']==changed:
  fixture['phase']='restoring-approved-template';save();patch_template(changed,original,'restoredPatch')
 else:assert current['spec']['template']==original,'unexpected third-party DS template; refuse rollback overwrite'
 fixture['phase']='approved-template-restored';save()
assert fixture['wrongCARejected']
issuer=proof(api,'wrong-kubelet-ca-recovered');result=q.native_fetch_registered(api,emit=lambda x:print(json.dumps(x),flush=True),probe_pod=probe,wanted=wanted,issuer_proof=issuer,expected_probe_image=IMAGE['canonicalImage']);fixture['recoveredSVID']=result;save()
cmPath='/api/v1/namespaces/cilium-spire/configmaps/'+created['metadata']['name']
with pki.Proxy('/private/tmp/cmtc-a-b-20261024.kubeconfig','kind-'+cluster) as proxy:
 cm=proxy.get(cmPath);assert cm['metadata']['uid']==created['metadata']['uid'] and cm['metadata']['labels']['security.cmtc.io/credential-owner']==ledger['owner'] and cm['data']==obj['data']
 proxy.request('DELETE',cmPath,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':cm['metadata']['uid'],'resourceVersion':cm['metadata']['resourceVersion']}})
 try:proxy.get(cmPath);raise AssertionError('wrong-CA CM still present')
 except pki.APIError as e:assert e.status==404
fixture['phase']='recovery-verified-and-owned-config-absent';ledger['wrongKubeletCARecoveryPassed']=True;save();print('PASS approved template restored; fresh native SVID verified; wrong-CA ConfigMap removed',flush=True)
