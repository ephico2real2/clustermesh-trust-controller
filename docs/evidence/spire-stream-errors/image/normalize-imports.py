from pathlib import Path
import hashlib,json,os,subprocess,tarfile
out=Path('/private/tmp/cmtc-spire-stream-image-20261025');pin=json.loads((out/'image-pin.json').read_text());names=['cmtc-a-control-plane','cmtc-a-worker','cmtc-b-control-plane','cmtc-b-worker']
first=json.loads((out/'manifest-cmtc-a-control-plane.json').read_text());raw=(out/'manifest-cmtc-a-control-plane.json').read_bytes();digest='sha256:'+hashlib.sha256(raw).hexdigest();canonical='localhost/cmtc-spire-workload-check@'+digest
assert first['config']['digest']==pin['configurationID']
with (out/'canonical-oci.tar').open('wb') as target,(out/'oci-export.log').open('wb') as log:
 subprocess.run(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',names[0],'ctr','--namespace','k8s.io','images','export','-',canonical],stdout=target,stderr=log,check=True,timeout=90)
with tarfile.open(out/'canonical-oci.tar') as archive:
 member='blobs/sha256/'+digest.removeprefix('sha256:');actual=archive.extractfile(member).read();assert actual==raw
 assert json.loads(archive.extractfile('blobs/sha256/'+pin['configurationID'].removeprefix('sha256:')).read())['architecture']=='arm64'
env={**os.environ,'DOCKER_HOST':'unix:///Users/olasumbo/.colima/cmtc-cilium/docker.sock','KIND_EXPERIMENTAL_PROVIDER':'docker'}
for cluster in ['cmtc-a','cmtc-b']:
 with (out/('oci-import-'+cluster+'.log')).open('w') as log:subprocess.run(['kind','load','image-archive',str(out/'canonical-oci.tar'),'--name',cluster],stdout=log,stderr=subprocess.STDOUT,env=env,check=True,timeout=120)
verified={}
for node in names:
 def cmd(*args):return subprocess.check_output(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,*args],timeout=30)
 content=cmd('ctr','--namespace','k8s.io','content','get',digest);assert content==raw
 cri=json.loads(cmd('crictl','inspecti',canonical));assert cri['status']['id']==pin['configurationID'] and cri['info']['imageSpec']['architecture']=='arm64'
 old=out/('canonical-'+node+'.json');old.rename(out/('docker-archive-canonical-'+node+'.json'))
 old.write_text(json.dumps(cri,indent=2)+'\n');verified[node]={'image':canonical,'manifestSHA256':digest,'configurationID':cri['status']['id'],'sourceRevision':cri['info']['imageSpec']['config']['Labels']['org.opencontainers.image.revision']};assert verified[node]['sourceRevision']==pin['sourceSHA']
 print('PASS',node,'exact preserved OCI manifest',digest,flush=True)
pin.update(canonicalImage=canonical,importedManifestDigest=digest,normalization='Docker archive reused different compressed base blobs with identical uncompressed diffIDs; export one verified OCI manifest and import it unchanged')
(out/'image-pin.json').write_text(json.dumps(pin,indent=2)+'\n');(out/'normalized-images.json').write_text(json.dumps(verified,indent=2)+'\n');(out/'canonical-oci.tar.sha256').write_text(hashlib.sha256((out/'canonical-oci.tar').read_bytes()).hexdigest()+'  canonical-oci.tar\n')
