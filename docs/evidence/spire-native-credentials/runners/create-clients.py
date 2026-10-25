from pathlib import Path
import sys,json
sys.argv=['qualify.py','--resume']
p=Path('/private/tmp/cmtc-native-credentials-20261025/qualify.py');exec(compile(p.read_text().split('\nsave()\nfor cluster')[0],str(p),'exec'))
assert ledger['finalRuntimeChecksPassed']
name='cmtc-credential-client-'+ledger['owner'][:10]
for cluster,state in ledger['clusters'].items():
 api=API(cluster);original=api.get('/api/v1/namespaces/mesh-example/pods/mesh-client');image=original['spec']['containers'][0]['image'];assert image=='curlimages/curl:8.14.1'
 node=cluster+'-worker';assert api.get('/api/v1/nodes/'+node)['metadata']['uid']==PINS[cluster]['nodes'][node]
 pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'mesh-example'},'spec':{'nodeName':node,'restartPolicy':'Never','activeDeadlineSeconds':900,'automountServiceAccountToken':False,'securityContext':{'runAsUser':65532,'runAsGroup':65532,'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'client','image':image,'imagePullPolicy':'Never','command':['sh','-c','sleep 600'],'resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}
 created=api.create(pod);api.k('-n','mesh-example','wait','--for=condition=Ready','pod/'+name,'--timeout=90s',timeout=105)
 current=api.get('/api/v1/namespaces/mesh-example/pods/'+name);assert current['metadata']['uid']==created['metadata']['uid'] and all(s['ready'] for s in current['status']['containerStatuses'])
 version=api.k('-n','mesh-example','exec',name,'--','curl','--version');assert 'curl 8.14.1' in version.stdout
 state['regressionClient']={'pod':current,'version':version.stdout,'originalCompletedClientUID':original['metadata']['uid']};save();print('PASS',cluster,'owned cached-image client Ready; original mesh-client retained',flush=True)
script=Path('/private/tmp/cmtc-native-credentials-20261025/check-apps.sh');script.write_text(script.read_text().replace('exec mesh-client --','exec '+name+' --'))
