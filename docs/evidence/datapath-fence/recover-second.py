import importlib.util,json,sys,types
from pathlib import Path
root=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller')
sys.path.insert(0,str(root/'scripts/lab'))
spec=importlib.util.spec_from_file_location('fence_recovery',root/'scripts/lab/test-fence.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=Path('/private/tmp/cmtc-fence-20261024/lab-second/report.json');old=json.loads(source.read_text());m.require(old.get('finished') and old['status']=='failed','original runner must have finished')
a=types.SimpleNamespace(out='/private/tmp/cmtc-fence-20261024/recovery-second',kubeconfig='/private/tmp/cmtc-a-b-20261024.kubeconfig',template=str(root/'config/experimental/datapath-fence.yaml'),image=old['image'],image_id=old['expectedImageID'],expected_revision=old['expectedRevision'])
h=m.FenceHarness(a);h.run_id=old['run'];h.ns='cmtc-fence-lab-'+old['run'];state=old['clusters']['cmtc-a'];h.report.update(run=old['run'],scope='exact-defunct-fence-recovery-after-parser-failure',started=old['started'],sourceFailedReport=str(source),sourceFailure=old['error'],clusters={'cmtc-a':state},status='recovering');h.flush()
try:
 m.require(h.get('cmtc-a','namespace',h.ns,absent=True) is None,'old namespace still exists')
 m.require(h.get('cmtc-a','daemonset',m.DS,m.SYSTEM,absent=True) is None,'old DS still exists')
 for pod in h.get('cmtc-a','pods',namespace=m.SYSTEM)['items']:
  m.require(pod['metadata'].get('labels',{}).get(m.OWNER)!=old['run'],'old task process remains')
 for r in state['roots'].values():m.require(h.root_stat('cmtc-a',r['path'])==r['stat'],'retained root incarnation changed')
 p=state['phases'][0];m.require(len(state['phases'])==1 and not p.get('retired'),'unexpected recovery scope')
 m.require(h.get('cmtc-a','configmap',p['configMap'],m.SYSTEM,absent=True) is None,'old configmap unexpectedly exists')
 h.create('cmtc-a',{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':p['configMap'],'namespace':m.SYSTEM},'immutable':True,'data':{p['config']['node']+'.json':json.dumps(p['config'])}})
 h.retire_phase('cmtc-a',p)
 h.report['status']='recovered-exact-defunct-fence'
finally:
 h.cleanup();h.flush()
 m.require(not h.report['cleanupErrors'],'recovery cleanup failed: '+repr(h.report['cleanupErrors']))
print(json.dumps({'status':h.report['status'],'retired':p['retired'],'cleanupErrors':h.report['cleanupErrors']}))
