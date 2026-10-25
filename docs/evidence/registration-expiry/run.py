from pathlib import Path
import json,subprocess,sys,time
out=Path('/private/tmp/cmtc-registration-expiry-20261025'); mode=sys.argv[1]
source='/private/tmp/cmtc-opus-final-20261025/cmtc'
command=['go','test','-p','2','-count=1','-v','-timeout=8m','./internal/spireregistrar/']
if mode=='before':command+=['-run','^TestSingleWriterRejectsMismatchedIdentityFilterBeforeCleanup$']
else:command.insert(2,'-race')
cmd=['podman','--connection','cmtc-ubuntu-build','run','--rm','--name','cmtc-primary-registrar-'+mode,'--platform','linux/arm64','--cpus','2','--memory','4g','-e','GOMAXPROCS=2','-e','GOMEMLIMIT=3GiB','-e','GOTOOLCHAIN=local','-e','GOFLAGS=-buildvcs=false','-e','GOCACHE=/cache','-e','GOMODCACHE=/modcache','-v',source+':/src:ro','-v','/private/tmp/cilium-ztunnel-linux-go-cache:/cache','-v','/private/tmp/cmtc-spire-go-modules:/modcache','-w','/src','f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529',*command]
(out/(mode+'-command.json')).write_text(json.dumps(cmd,indent=2)+'\n')
with (out/(mode+'.log')).open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
(out/(mode+'.exit')).write_text(str(r.returncode)+'\n')
print('Registrar '+mode+' exit '+str(r.returncode)); print((out/(mode+'.log')).read_text()[-5000:])
sys.exit(r.returncode)
