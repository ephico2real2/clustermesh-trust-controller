from pathlib import Path
import hashlib,json,re,subprocess
out=Path('/private/tmp/cmtc-spire-workload-runtime-20261024');pin=json.loads((out/'image-pin.json').read_text());loaded=json.loads((out/'loaded-images.json').read_text());descriptors=[]
def run(node,*args):return subprocess.check_output(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,*args])
for node,record in loaded.items():
 rows=run(node,'ctr','--namespace','k8s.io','images','list','name=='+pin['image']).decode().splitlines();assert len(rows)==2
 fields=rows[1].split();assert fields[0]==pin['image'] and re.fullmatch('sha256:[0-9a-f]{64}',fields[2]);digest=fields[2]
 manifest=run(node,'ctr','--namespace','k8s.io','content','get',digest);assert 'sha256:'+hashlib.sha256(manifest).hexdigest()==digest
 obj=json.loads(manifest);assert obj['config']['digest']==pin['configurationID'];(out/('manifest-'+node+'.json')).write_bytes(manifest)
 alias='localhost/cmtc-spire-agent@'+digest
 run(node,'ctr','--namespace','k8s.io','images','tag',pin['image'],alias)
 cri=json.loads(run(node,'crictl','inspecti',alias));assert cri['status']['id']==pin['configurationID'] and cri['info']['imageSpec']['architecture']=='arm64'
 record.update(canonicalImage=alias,importedManifestDigest=digest,repoDigests=cri['status']['repoDigests']);descriptors.append(digest)
 (out/('canonical-'+node+'.json')).write_text(json.dumps(cri,indent=2)+'\n')
 print(node,'PASS verified content-addressable import',alias,flush=True)
assert len(set(descriptors))==1
(out/'loaded-images.json').write_text(json.dumps(loaded,indent=2)+'\n');pin['canonicalImage']=loaded['cmtc-a-worker']['canonicalImage'];pin['importedManifestDigest']=descriptors[0];(out/'image-pin.json').write_text(json.dumps(pin,indent=2)+'\n')
