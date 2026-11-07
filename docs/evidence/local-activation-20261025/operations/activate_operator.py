import subprocess,json,sys
from pathlib import Path
c=sys.argv[1];assert c in ['cmtc-a','cmtc-b'];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c];O=Path('/private/tmp/cmtc-primary-operations-20261025')/('activation-'+c)
o=json.loads(subprocess.check_output(K+['-n','kube-system','get','deployment','cilium-operator','-o','json']))
b=json.loads((O/'operator-before.json').read_text());assert o['metadata']['uid']==b['metadata']['uid'] and o['spec']==b['spec']
cs=o['spec']['template']['spec']['containers'];assert len(cs)==1
args=[x for x in cs[0].get('args',[]) if not any(x.startswith(p) for p in ['--enable-ztunnel','--ztunnel-ca-type','--ztunnel-spire-external-exact-registrar'])]
args+=['--enable-ztunnel=true','--ztunnel-ca-type=spire','--ztunnel-spire-external-exact-registrar=true']
p=[{'op':'test','path':'/metadata/uid','value':o['metadata']['uid']},{'op':'test','path':'/spec/template/spec/containers/0/image','value':cs[0]['image']},{'op':'replace','path':'/spec/template/spec/containers/0/image','value':'localhost/cilium-operator:dev-overlay-51170b1239'},{'op':'add','path':'/spec/template/spec/containers/0/args','value':args}]
subprocess.run(K+['-n','kube-system','patch','deployment','cilium-operator','--type=json','-p',json.dumps(p)],check=True)
# Advertise the enabled native exporter to pod discovery before the controlled agent restarts.
d=json.loads(subprocess.check_output(K+['-n','kube-system','get','ds','cilium','-o','json']))
agent=next(x for x in d['spec']['template']['spec']['containers'] if x['name']=='cilium-agent')
assert not any(x.get('name')=='prometheus' and x['containerPort']!=9962 for x in agent.get('ports',[]))
patch={'metadata':{'uid':d['metadata']['uid']},'spec':{'template':{'spec':{'containers':[{'name':'cilium-agent','ports':[{'name':'prometheus','containerPort':9962,'protocol':'TCP'}]}]}}}}
subprocess.run(K+['-n','kube-system','patch','ds','cilium','--type=strategic','-p',json.dumps(patch)],check=True)
