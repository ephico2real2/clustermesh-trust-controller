import json,pathlib,subprocess
k=['/private/tmp/cmtc-mac-qualification/.tmp/bin/kubectl','--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike']
backend=subprocess.check_output(k+['-n','mtls-spike','get','pods','-l','app=mtls-server','-o','jsonpath={.items[0].status.podIP}'],text=True)
name='authenticated-deny-load'
existing=subprocess.check_output(k+['-n','mtls-plaintext-control','get','job',name,'--ignore-not-found','-o','name'],text=True)
assert not existing.strip(),'Refusing existing load job'
script='''set -u
for i in $(seq 1 900); do
 wget -T 1 -S -O - http://BACKEND/ > /tmp/probe-output 2>&1
 result=$?
 if [ "$result" -eq 0 ] || grep -q 'HTTP/' /tmp/probe-output; then
  echo "FAIL unexpected application HTTP attempt=$i exit=$result"
  cat /tmp/probe-output
  exit 1
 fi
 echo "DENY attempt=$i HTTP=none exit=$result"
 sleep 0.3
done
echo 'PASS: 900 unauthenticated requests rejected without HTTP response'
'''.replace('BACKEND',backend)
job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':'mtls-plaintext-control'},'spec':{'backoffLimit':0,'activeDeadlineSeconds':390,'template':{'metadata':{'labels':{'app':'cmtc-auth-deny-load'}},'spec':{'nodeSelector':{'kubernetes.io/hostname':'cmtc-mtls-worker'},'automountServiceAccountToken':False,'restartPolicy':'Never','securityContext':{'runAsNonRoot':True,'runAsUser':65532},'containers':[{'name':'probe','image':'alpine:3.20','command':['sh','-c',script],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'memory':'32Mi'}}}]}}}}
subprocess.run(k+['apply','-f','-'],input=json.dumps(job),text=True,check=True)
p=pathlib.Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike/authenticated-only-f052d127')
(p/'negative-load-job.json').write_text(json.dumps(job,indent=2)+'\n')
subprocess.run(k+['-n','mtls-plaintext-control','wait','job/'+name,'--for=condition=Complete','--timeout=400s'],check=True)
log=subprocess.check_output(k+['-n','mtls-plaintext-control','logs','job/'+name],text=True)
(p/'negative-load.log').write_text(log)
assert log.count('DENY attempt=')==900 and 'FAIL' not in log
(p/'negative-load-results.json').write_text(json.dumps({'attempts':900,'noHTTPResponse':900,'unexpectedHTTP':0},indent=2)+'\n')
print('PASS: 900/900 unauthenticated probes rejected; raw output retained')
