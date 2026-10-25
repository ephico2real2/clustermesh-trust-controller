from pathlib import Path
import subprocess,json,io,tarfile,hashlib
out=Path('/private/tmp/cmtc-daemonset-20261024')
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
assert sha=='5b1bc205fee9c6bc999c7d545e23ac0ff6f29bf2'
source=out/'committed-source';source.mkdir()
with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','archive',sha]))) as tf:tf.extractall(source,filter='data')
base=['podman','--connection','cmtc-ubuntu-build']
records={}
for profile in ('fence','observer'):
 image=f'localhost/cmtc-bpf-{profile}:metrics-{sha[:10]}'
 cmd=base+['build','--platform','linux/arm64','--jobs','1','--memory','3g','--env','GOMAXPROCS=2','--env','GOMEMLIMIT=1536MiB','--env','GOFLAGS=-p=2','--unsetenv','GOMAXPROCS','--unsetenv','GOMEMLIMIT','--unsetenv','GOFLAGS','--build-arg','BUILD_IMAGE=f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529','--build-arg','SOURCE_SHA='+sha,'-f',str(source/f'build/Containerfile.bpf-{profile}'),'-t',image,str(source)]
 print('Building',image,flush=True)
 with (out/f'{profile}-build.log').open('w') as log:subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=True)
 metadata=json.loads(subprocess.check_output(base+['image','inspect',image]))
 (out/f'{profile}-image.json').write_text(json.dumps(metadata,indent=2)+'\n')
 actual=metadata[0]
 assert actual['Architecture']=='arm64' and actual['Os']=='linux'
 assert actual['Labels']['org.opencontainers.image.revision']==sha
 version=subprocess.check_output(base+['run','--rm','--network','none',image,'--version'],text=True)
 assert 'revision='+sha in version
 (out/f'{profile}-version.txt').write_text(version)
 archive=out/f'{profile}-arm64.tar'
 subprocess.run(base+['save','--format','docker-archive','--output',str(archive),image],check=True)
 archive_hash=hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()
 (out/f'{profile}-arm64.tar.sha256').write_text(archive_hash+'  '+archive.name+'\n')
 extraction=out/f'{profile}-package';extraction.mkdir()
 cid=subprocess.check_output(base+['create','--network','none',image,'--version'],text=True).strip()
 try:
  for path,name in ((f'/cmtc-bpf-{profile}',f'cmtc-bpf-{profile}'),(f'/usr/share/cmtc/{profile}_bpfel.o',f'{profile}_bpfel.o')):
   subprocess.run(base+['cp',cid+':'+path,str(extraction/name)],check=True)
 finally:subprocess.run(base+['rm',cid],check=True,stdout=subprocess.DEVNULL)
 hashes={p.name:hashlib.file_digest(p.open('rb'),'sha256').hexdigest() for p in extraction.iterdir()}
 records[profile]={'source':sha,'image':image,'configID':actual['Id'],'architecture':actual['Architecture'],'archiveSHA256':archive_hash,'packagedFiles':hashes,'version':version.strip()}
 (out/'images.json').write_text(json.dumps(records,indent=2)+'\n')
 print(profile,actual['Id'],flush=True)
