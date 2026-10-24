import json,subprocess,os
from pathlib import Path
out=Path('/private/tmp/cmtc-rebuild-20261024')
os.environ['KUBECONFIG']='/private/tmp/cmtc-a-b-20261024.kubeconfig'
for cluster in ['cmtc-a','cmtc-b']:
 base=['kubectl','--context','kind-'+cluster]
 nodes=json.loads(subprocess.check_output(base+['get','nodes','-o','json']))['items']
 for node in nodes:
  node_name=node['metadata']['name']; name='ztunnel-image-8106c02662-'+node_name
  job={'apiVersion':'batch/v1','kind':'Job','metadata':{'name':name,'namespace':'cmtc-system','labels':{'app.kubernetes.io/managed-by':'cmtc-local-validation'}},'spec':{'activeDeadlineSeconds':120,'backoffLimit':0,'template':{'metadata':{'labels':{'app.kubernetes.io/name':'ztunnel-image-validation'}},'spec':{'nodeName':node_name,'restartPolicy':'Never','automountServiceAccountToken':False,'tolerations':[{'operator':'Exists'}],'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'version','image':'localhost/cmtc-ztunnel:strict-8106c02662','imagePullPolicy':'Never','args':['version'],'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'128Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}}}
  (out/(name+'.json')).write_text(json.dumps(job,indent=2)+'\n')
  subprocess.run(base+['apply','-f','-'],input=json.dumps(job).encode(),check=True)
  subprocess.run(base+['-n','cmtc-system','wait','--for=condition=Complete','job/'+name,'--timeout=120s'],check=True)
  log=subprocess.check_output(base+['-n','cmtc-system','logs','job/'+name]).decode()
  assert '8106c026621a6bbf51fbd9190585e6d3549aa527' in log and 'BuildStatus:"Clean"' in log,log
  (out/(name+'.log')).write_text(log)
  pods=subprocess.check_output(base+['-n','cmtc-system','get','pods','-l','job-name='+name,'-o','json'])
  (out/(name+'-pods.json')).write_bytes(pods)
  print('PASS',node_name,log.strip(),flush=True)
