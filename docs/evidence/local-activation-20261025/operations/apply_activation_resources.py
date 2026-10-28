from pathlib import Path
import sys,json,subprocess
cluster=sys.argv[1];assert cluster in ['cmtc-a','cmtc-b'];out=Path('/private/tmp/cmtc-primary-operations-20261025')/('activation-'+cluster)
k=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+cluster]
def get(kind,name,ns='kube-system'):return json.loads(subprocess.check_output(k+['-n',ns,'get',kind,name,'-o','json']))
resources=json.loads((out/'public-resources.json').read_text())
for obj in resources['items']:
 m=obj['metadata'];r=subprocess.run(k+['-n',m['namespace'],'get',obj['kind'],m['name'],'-o','json'],capture_output=True,text=True)
 if r.returncode==0:assert json.loads(r.stdout)['metadata'].get('labels',{}).get('app.kubernetes.io/managed-by')=='cmtc-local-qualification','Foreign resource; preserve'
 else:assert 'NotFound' in r.stderr,r.stderr
subprocess.run(k+['apply','-f',str(out/'public-resources.json')],check=True)
for kind,name,file,before in [('ds','cilium','agent-mount-patch.json','cilium-ds-before.json'),('cm','cilium-config','agent-config-patch.json','cilium-config-before.json')]:
 obj=get(kind,name);old=json.loads((out/before).read_text());field='spec' if kind=='ds' else 'data'
 assert obj['metadata']['uid']==old['metadata']['uid'] and obj[field]==old[field],kind+' changed; inspect before applying'
 patch=json.loads((out/file).read_text());patch['metadata']['resourceVersion']=obj['metadata']['resourceVersion']
 p=out/('applied-'+file);p.write_text(json.dumps(patch)+'\n')
 subprocess.run(k+['-n','kube-system','patch',kind,name,'--type='+('strategic' if kind=='ds' else 'merge'),'--patch-file',str(p)],check=True)
print(cluster,'strict native runtime configuration applied; no application namespace is enrolled')
