import argparse,datetime,json,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--fixture',required=True);p.add_argument('--out');a=p.parse_args();fixture=Path(a.fixture)
trial=json.loads((fixture/'result.json').read_text());assert trial['passed'];uid=trial['podUID']
out=Path(a.out) if a.out else fixture/'postdelete';out.mkdir(exist_ok=False)
kube=['kubectl','--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike']
node='cmtc-mtls-worker'
def run(argv,check=True,timeout=90):
 r=subprocess.run(argv,text=True,capture_output=True,timeout=timeout)
 with (out/'commands.ndjson').open('a') as f:f.write(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':argv,'exitCode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})+'\n')
 if check and r.returncode:raise RuntimeError(r.stderr or r.stdout)
 return r
assert run(kube+['config','current-context']).stdout.strip()=='kind-cmtc-mtls'
pod=json.loads((fixture/'pod-final.json').read_text());ns=pod['metadata']['namespace']
run(kube+['-n',ns,'wait','--for=delete','pod/app','--timeout=60s'])
def dump():
 r=run(['docker','exec',node,'curl','-fsS','--max-time','2','http://127.0.0.1:15000/config_dump'],check=False,timeout=5)
 if r.returncode:return None
 d=json.loads(r.stdout);assert d['version']['gitRevision']=='d79d3dfaef3d7afeb3552ea53cf90213141e95d3';assert d['config']['requireInboundMtls'] is True
 return d
def await_clean(stage):
 end=time.monotonic()+45;attempt=0
 while True:
  attempt+=1;d=dump()
  if d is not None and uid not in d['workloadState'] and any(w['info']['name']=='client' and w['state']=='Up' for w in d['workloadState'].values()):
   (out/(stage+'.json')).write_text(json.dumps(d,indent=2)+'\n');return attempt
  if time.monotonic()>=end:raise RuntimeError('deleted UID absent + healthy client snapshot failed: '+stage)
  time.sleep(.5)
before=await_clean('before-worker-proxy-restart')
proxies=json.loads(run(kube+['-n','kube-system','get','pods','-l','app=ztunnel-cilium','-o','json']).stdout)['items'];old=next(p for p in proxies if p['spec']['nodeName']==node)
run(kube+['-n','kube-system','delete','pod',old['metadata']['name'],'--wait=false'])
end=time.monotonic()+90
while True:
 pods=json.loads(run(kube+['-n','kube-system','get','pods','-l','app=ztunnel-cilium','-o','json']).stdout)['items'];fresh=[p for p in pods if p['spec']['nodeName']==node and p['metadata']['uid']!=old['metadata']['uid'] and any(c['type']=='Ready' and c['status']=='True' for c in p.get('status',{}).get('conditions',[]))]
 if len(fresh)==1:break
 if time.monotonic()>=end:raise RuntimeError('worker proxy did not recover')
 time.sleep(1)
after=await_clean('after-worker-proxy-restart')
responses=run(kube+['-n','mtls-spike','exec','client','--','sh','-c','for n in $(seq 1 20); do wget -T 3 -S -O /dev/null http://server.mtls-spike/ || exit 1; done'])
statuses=re.findall(r'HTTP/\S+\s+(\d{3})',responses.stdout+responses.stderr)
assert len(statuses)==20 and set(statuses)=={'200'},statuses
server=json.loads(run(kube+['-n','mtls-spike','get','pods','-l','app=mtls-server','-o','json']).stdout)['items'];ip=next(p for p in server if p['status']['phase']=='Running')['status']['podIP']
for _ in range(10):
 r=run(['docker','exec',node,'curl','--max-time','2','--silent','--show-error','--include','http://'+ip+'/'],check=False,timeout=5)
 assert r.returncode!=0 and 'HTTP/' not in r.stdout and 'CMTC' not in r.stdout,'unauthenticated host reached protected target'
report={'passed':True,'retiredPodUID':uid,'deletedUIDAbsentBeforeAndAfterRestart':True,'healthyClientSnapshotRestored':True,'clientHTTP200':20,'unauthenticatedHostRejected':10,'proxyOldUID':old['metadata']['uid'],'proxyNewUID':fresh[0]['metadata']['uid'],'adminAttemptsBefore':before,'adminAttemptsAfter':after}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
