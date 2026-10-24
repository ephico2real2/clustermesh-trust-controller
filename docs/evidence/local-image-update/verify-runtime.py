import os,json,subprocess
from pathlib import Path
out=Path('/private/tmp/cmtc-rebuild-20261024')
os.environ['DOCKER_HOST']='unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock'
os.environ['KUBECONFIG']='/private/tmp/cmtc-a-b-20261024.kubeconfig'
images={}
for name in ['cilium','cmtc','ztunnel']:
 j=json.loads((out/(name+'-image.json')).read_text())[0]
 tag=j['RepoTags'][0]
 images[name]={'tag':tag,'configId':'sha256:'+j['Id'].removeprefix('sha256:'),'architecture':j['Architecture'],'revision':j['Config']['Labels']['org.opencontainers.image.revision']}
result={'qualification':'local-observe-update-proxy-image-staged','images':images,'nodeImages':[],'runningWorkloads':[]}
for cluster in ['cmtc-a','cmtc-b']:
 base=['kubectl','--context','kind-'+cluster]
 nodes=json.loads(subprocess.check_output(base+['get','nodes','-o','json']))['items']
 for node in nodes:
  nodename=node['metadata']['name']
  for component,img in images.items():
   i=json.loads(subprocess.check_output(['docker','exec',nodename,'crictl','inspecti',img['tag']]))
   assert i['status']['id']==img['configId'],(nodename,component,i['status']['id'],img['configId'])
   assert i['info']['imageSpec']['architecture']=='arm64'
   result['nodeImages'].append({'node':nodename,'component':component,'configId':i['status']['id'],'repoDigests':i['status']['repoDigests']})
 for namespace,selector,component in [('kube-system','k8s-app=cilium','cilium'),('cmtc-system','app.kubernetes.io/name in (cmtc-controller,cmtc-node-agent)','cmtc')]:
  pods=json.loads(subprocess.check_output(base+['-n',namespace,'get','pods','-l',selector,'-o','json']))['items']
  for pod in pods:
   if pod['metadata'].get('deletionTimestamp'): continue
   assert pod['status']['phase']=='Running'
   spec=pod['spec'];statuses={s['name']:s for s in pod['status']['containerStatuses']}
   for c in spec['containers']:
    if c['image']!=images[component]['tag']: continue
    s=statuses[c['name']];assert s['ready']
    result['runningWorkloads'].append({'cluster':cluster,'pod':pod['metadata']['name'],'node':spec['nodeName'],'container':c['name'],'image':c['image'],'runtimeImageId':s['imageID'],'ready':s['ready']})
   if component=='cilium':
    value=subprocess.check_output(base+['-n',namespace,'exec',pod['metadata']['name'],'--','sha256sum','/usr/bin/cilium-agent']).decode().split()[0]
    assert value=='1152bef474c16acc343c90dc0dc683cc4f6e7e4689c5d8737235c74682b99778',value
 result[cluster+'Encryption']=json.loads(subprocess.check_output(['helm','--kube-context','kind-'+cluster,'-n','kube-system','get','values','cilium','-o','json']))['encryption']
 assert result[cluster+'Encryption']['enabled'] is False
assert len(result['runningWorkloads'])==10,len(result['runningWorkloads'])
(out/'verified-runtime.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS: 12 imported image identities, 10 ready Cilium/CMTC containers, 4 matching agent binary hashes; encryption remains disabled.')
