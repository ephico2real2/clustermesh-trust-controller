import subprocess,json,sys,time
from pathlib import Path
c,node=sys.argv[1:];assert c in ['cmtc-a','cmtc-b'];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c];O=Path('/private/tmp/cmtc-primary-operations-20261025')/('activation-'+c)
def pods():return json.loads(subprocess.check_output(K+['-n','kube-system','get','pods','-l','k8s-app=cilium','--field-selector','spec.nodeName='+node,'-o','json']))['items']
items=pods();assert len(items)==1;old=items[0];assert old['spec']['containers'][0]['image']=='localhost/cilium:dev-overlay-51170b1239'
options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':old['metadata']['uid']}}
p=O/('delete-agent-'+node+'.json');p.write_text(json.dumps(options)+'\n')
r=subprocess.run(K+['delete','--raw','/api/v1/namespaces/kube-system/pods/'+old['metadata']['name'],'-f',str(p)],capture_output=True,text=True);assert r.returncode==0,r.stderr
print(c,node,'old agent deleted by UID',flush=True)
for attempt in range(36):
 time.sleep(5);ps=[p for p in pods() if p['metadata']['uid']!=old['metadata']['uid']]
 if not ps:continue
 new=ps[0]
 if any(x.get('type')=='Ready' and x.get('status')=='True' for x in new.get('status',{}).get('conditions',[])):
  (O/('agent-ready-'+node+'.json')).write_text(json.dumps({'pod':new['metadata']['name'],'uid':new['metadata']['uid'],'node':node,'imageIDs':[x.get('imageID') for x in new['status'].get('containerStatuses',[])]},indent=2)+'\n')
  print(c,node,'new agent Ready',new['metadata']['name'],flush=True);sys.exit(0)
 if attempt in [5,11,23]:print(c,node,'waiting for Ready',new['metadata']['name'],new.get('status',{}).get('phase'),flush=True)
(O/('agent-start-failed-'+node+'.json')).write_text(json.dumps(new,indent=2)+'\n')
r=subprocess.run(K+['-n','kube-system','logs',new['metadata']['name'],'-c','cilium-agent','--tail=100'],capture_output=True,text=True)
(O/('agent-start-failed-'+node+'.log')).write_text(r.stdout+r.stderr)
print(r.stdout[-4500:],flush=True);sys.exit(1)
