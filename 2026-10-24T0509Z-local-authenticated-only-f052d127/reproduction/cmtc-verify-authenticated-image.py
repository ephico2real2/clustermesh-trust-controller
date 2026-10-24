import hashlib,json,pathlib,re,subprocess
out=pathlib.Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike/authenticated-only-f052d127')
expected=json.loads(pathlib.Path('/private/tmp/cmtc-authentication-agent-podman-image.json').read_text())[0]
expected_id='sha256:'+expected['Id'].removeprefix('sha256:');records=[]
k=['/private/tmp/cmtc-mac-qualification/.tmp/bin/kubectl','--kubeconfig','/home/olasumbo.guest/.kube/cmtc-mtls-spike']
pods=json.loads(subprocess.check_output(k+['-n','kube-system','get','pods','-l','k8s-app=cilium','-o','json']))['items']
for pod in pods:
 node=pod['spec']['nodeName'];image=next(i for i in pod['status']['containerStatuses'] if i['name']=='cilium-agent')
 digest=re.search('sha256:[0-9a-f]{64}',image['imageID']).group()
 chain=[]
 for step in range(4):
  raw=subprocess.check_output(['docker','exec',node,'ctr','--namespace','k8s.io','content','get',digest])
  assert 'sha256:'+hashlib.sha256(raw).hexdigest()==digest
  doc=json.loads(raw);chain.append({'digest':digest,'mediaType':doc.get('mediaType'),'keys':list(doc)})
  if 'manifests' in doc:
   manifests=[m for m in doc['manifests'] if m.get('platform',{}).get('architecture')=='arm64']
   if not manifests and len(doc['manifests'])==1:manifests=doc['manifests']
   assert len(manifests)==1
   digest=manifests[0]['digest']
  elif 'config' in doc and 'digest' in doc['config']:digest=doc['config']['digest']
  else:
   assert digest==expected_id,(node,digest,expected_id)
   assert doc['architecture']=='arm64' and doc['os']=='linux'
   assert doc['config']['Labels']['org.opencontainers.image.revision']=='f052d1276b0fb1619809db0059fbbb7898c9cfae'
   break
 else:raise RuntimeError('Image resolution did not reach config')
 records.append({'node':node,'pod':pod['metadata']['name'],'runtimeImageID':image['imageID'],'verifiedConfig':expected_id,'source':'f052d1276b0fb1619809db0059fbbb7898c9cfae','contentChain':chain})
(out/'deployed-image-verification.json').write_text(json.dumps(records,indent=2)+'\n')
for node in ['cmtc-mtls-control-plane','cmtc-mtls-worker']:
 dump=json.loads(subprocess.check_output(['docker','exec',node,'curl','-fsS','http://127.0.0.1:15000/config_dump']))
 print(node,'admin dump top-level keys',list(dump))
 # Retain only policy data, not configuration or certificate material.
 policy={key:val for key,val in dump.items() if 'polic' in key.lower()}
 (out/(node+'-native-policies.json')).write_text(json.dumps(policy,indent=2)+'\n')
 assert 'cilium_require_mtls' in json.dumps(policy),(node,list(policy))
print('PASS: both deployed CRI image chains resolve to exact Podman config/source; both native proxies contain authenticated-only policy')
