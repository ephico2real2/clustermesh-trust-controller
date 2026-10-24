import json,pathlib,subprocess
bin='/private/tmp/cmtc-mac-qualification/.tmp/bin/kubectl';out=pathlib.Path('/private/tmp/cmtc-dashboard-redesign');results=[]
for name,context in [('cmtc-a',['--context','kind-cmtc-a']),('cmtc-b',['--context','kind-cmtc-b']),('cmtc-mtls',['--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike'])]:
 k=[bin]+context
 pods=json.loads(subprocess.check_output(k+['-n','kube-system','get','pods','-o','json'],text=True))
 selected=[]
 for p in pods['items']:
  if p['metadata']['name'].startswith(('cilium-','ztunnel-')):
   selected.append({'pod':p['metadata']['name'],'node':p['spec'].get('nodeName'),'containers':[{'name':c['name'],'image':c['image'],'imageID':c.get('imageID'),'ready':c['ready']} for c in p['status'].get('containerStatuses',[])]})
 version=subprocess.run(k+['-n','kube-system','exec','ds/cilium','-c','cilium-agent','--','cilium-dbg','version'],text=True,capture_output=True)
 if version.returncode:
  version=subprocess.run(k+['-n','kube-system','exec','ds/cilium','-c','cilium','--','cilium-dbg','version'],text=True,capture_output=True)
 assert version.returncode==0,version.stderr
 results.append({'cluster':name,'pods':selected,'version':version.stdout.strip()})
(out/'runtime-images.json').write_text(json.dumps(results,indent=2)+'\n');print('PASS running source/image IDs retained for all three owned fixture clusters')
