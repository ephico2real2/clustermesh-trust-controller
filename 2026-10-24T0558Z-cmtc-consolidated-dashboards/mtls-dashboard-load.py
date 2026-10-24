import datetime,json,pathlib,subprocess,sys
out=pathlib.Path('/private/tmp/cmtc-dashboard-redesign/mtls-load');out.mkdir(exist_ok=True)
k=['/private/tmp/cmtc-mac-qualification/.tmp/bin/kubectl','--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike']
def run(*args):return subprocess.check_output(k+list(args),text=True)
streams=[('mtls-spike','authenticated-load-service','dashboard-mtls-service'),('mtls-spike','authenticated-load-pod','dashboard-mtls-pod'),('mtls-plaintext-control','authenticated-deny-load','dashboard-deny')]
if sys.argv[1]=='start':
 for ns,old,name in streams:
  original=json.loads(run('-n',ns,'get','job',old,'-o','json'))
  obj=json.loads(original['metadata']['annotations']['kubectl.kubernetes.io/last-applied-configuration'])
  obj['metadata']={'name':name,'namespace':ns,'annotations':{'cmtc.io/evidence-run':'dashboard-consolidation'}}
  path=out/(name+'-job.json');path.write_text(json.dumps(obj,indent=2)+'\n')
  subprocess.run(k+['create','-f',str(path)],check=True)
 (out/'started.json').write_text(json.dumps({'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()})+'\n')
else:
 results=[]
 for ns,old,name in streams:
  status=json.loads(run('-n',ns,'get','job',name,'-o','json'))
  assert status['status'].get('succeeded')==1,(name,status['status'])
  if name=='dashboard-deny':
   raw=run('-n',ns,'logs','job/'+name,'-c','probe');(out/(name+'.log')).write_text(raw)
   lines=[x for x in raw.splitlines() if x.startswith('DENY attempt=')]
   assert len(lines)==900 and all('HTTP=none' in x for x in lines) and 'FAIL' not in raw
   results.append({'stream':name,'rejectedWithoutHTTP':len(lines)})
  else:
   raw=run('-n',ns,'logs','job/'+name,'-c','results');data=json.loads(raw)
   (out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n');(out/(name+'.log')).write_text(run('-n',ns,'logs','job/'+name,'-c','fortio'))
   total=data['DurationHistogram']['Count'];assert total==data['RetCodes'].get('200') and total>=2900
   results.append({'stream':name,'requests':total,'http200':data['RetCodes']['200'],'durationSeconds':data['ActualDuration']/1e9,'actualQPS':data['ActualQPS']})
  (out/(name+'-status.json')).write_text(json.dumps(status['status'],indent=2)+'\n')
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
