from pathlib import Path
import subprocess,json,os
out=Path('/private/tmp/cmtc-daemonset-20261024')
records=json.loads((out/'images.json').read_text())
env={**os.environ,'DOCKER_HOST':'unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock'}
for r in records.values():r['configID']='sha256:'+r['configID'].removeprefix('sha256:')
(out/'images.json').write_text(json.dumps(records,indent=2)+'\n')
for cluster in ('cmtc-a','cmtc-b'):
 for profile in ('fence','observer'):
  print('Loading',cluster,profile,flush=True)
  with (out/f'load-{cluster}-{profile}.log').open('w') as log:
   subprocess.run(['kind','load','image-archive',str(out/f'{profile}-arm64.tar'),'--name',cluster],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
verified={}
for cluster in ('cmtc-a','cmtc-b'):
 for node in (cluster+'-control-plane',cluster+'-worker'):
  verified[node]={}
  for profile,r in records.items():
   raw=subprocess.check_output(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,'crictl','inspecti',r['image']],text=True)
   actual=json.loads(raw)
   (out/f'loaded-{node}-{profile}.json').write_text(raw)
   assert actual['status']['id']==r['configID'],(node,profile,actual['status']['id'])
   assert actual['info']['imageSpec']['architecture']=='arm64'
   verified[node][profile]={'image':r['image'],'configID':actual['status']['id'],'architecture':'arm64','repoDigests':actual['status']['repoDigests']}
(out/'loaded-images.json').write_text(json.dumps(verified,indent=2)+'\n')
print('Verified both exact images on all four owned nodes.',flush=True)
