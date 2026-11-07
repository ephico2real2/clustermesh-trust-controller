import json,subprocess,sys
from pathlib import Path
cluster=sys.argv[1];assert cluster in ['cmtc-a','cmtc-b'];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+cluster]
OUT=Path('/private/tmp/cmtc-primary-operations-20261025')/cluster;OUT.mkdir(exist_ok=True)
for kind,name in [('deployment','cmtc-controller'),('ds','cmtc-node-agent')]:
 obj=json.loads(subprocess.check_output(K+['-n','cmtc-system','get',kind,name,'-o','json']))
 p=OUT/(name+'-before.json');assert not p.exists();p.write_text(json.dumps(obj,indent=2)+'\n')
 cs=obj['spec']['template']['spec']['containers'];assert len(cs)==1
 assert cs[0]['image']=='localhost/cmtc:lineage-f5fe9992da'
 patch=[{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},{'op':'test','path':'/spec/template/spec/containers/0/image','value':cs[0]['image']},{'op':'replace','path':'/spec/template/spec/containers/0/image','value':'localhost/cmtc:current-96cbc9eeca'}]
 subprocess.run(K+['-n','cmtc-system','patch',kind,name,'--type=json','-p',json.dumps(patch)],check=True)
