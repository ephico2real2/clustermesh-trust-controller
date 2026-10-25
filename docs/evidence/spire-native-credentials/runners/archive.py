from pathlib import Path
import datetime,gzip,hashlib,json,re,subprocess
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');TASK=Path('/private/tmp/cmtc-native-credentials-20261025')
ledger=json.loads((TASK/'ledger.json').read_text());assert ledger['cleanupPassed'] and ledger['success']
private=re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')
def put(src,dst,compressed=False):
 data=src.read_bytes();assert not private.search(data),f'private marker in {src.name}'
 dst.parent.mkdir(parents=True,exist_ok=True)
 if compressed:dst=dst.with_name(dst.name+'.gz');dst.write_bytes(gzip.compress(data,mtime=0))
 else:dst.write_bytes(data)
 return {'path':str(dst.relative_to(ROOT)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'storedSHA256':hashlib.sha256(dst.read_bytes()).hexdigest()}
def group(base):
 (base/'files').mkdir(parents=True,exist_ok=True);return []
base=ROOT/'docs/evidence/spire-native-credentials';files=group(base)
for src in sorted(TASK.iterdir()):
 if src.suffix in ['.py','.sh']:files.append(put(src,base/'runners'/src.name))
 elif src.suffix=='.log':files.append(put(src,base/'logs'/src.name))
 elif src.suffix=='.json':files.append(put(src,base/'runtime'/src.name,src.name=='ledger.json'))
for src in sorted((TASK/'apps').iterdir()):files.append(put(src,base/'apps'/src.name))
img=Path('/private/tmp/cmtc-native-credential-image-20261025')
for src in sorted(img.iterdir()):
 if src.is_file() and src.suffix in ['.json','.log','.sh','.py','.txt','.sha256','.exit']:
  files.append(put(src,base/'image'/src.name,src.name=='compile.log'))
files.append(put(img/'image-context/Containerfile',base/'image/Containerfile'))
summary={'scope':'native workload credentials only; no traffic proxy or encryption claim','sourceSHA':'3b1a6a9e8fa3fcc9d3de499835feeafc0e735d39','image':json.loads((img/'image-pin.json').read_text()),'allNodePositives':4,'credentialNegativeCases':sum(len(s['negative']) for s in ledger['clusters'].values()),'wrongKubeletCATLSFailureAndRecovery':True,'allNodeAgentRestarts':4,'appPathsPassed':36,'freshIssuerMetricQueries':10,'hostTestsPassed':76,'temporaryRegistrationEntriesRemoved':sum(len(s['cleanup']['entries']) for s in ledger['clusters'].values()),'temporaryUIDBoundObjectsRemoved':sum(len(s['cleanup']['objects']) for s in ledger['clusters'].values()),'wrongCAConfigRemoved':True,'fixtureCleaned':True,'privateKeysExported':False,'packetProtectionTested':False,'productionProxySocketDACQualified':False,'files':files}
(base/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
for task,folder,sha,parent,counts in [
 ('cmtc-native-source-binding-20261025','source-binding','1609bfd38abdf4be671ad0d8144fecfa0b6d94b0','3b1a6a9e8fa3fcc9d3de499835feeafc0e735d39',{'library':513,'direct':20,'namespace':30,'diagnostic':2,'constructorDenialRegression':1}),
 ('cmtc-native-source-lease-20261025','source-membership','79c521646c94946d7a0f3817ce54902e6baa60c6','1a84f9279df4fa295edcf4b9a49c2dc5f51e476b',{'topLevelRace':304,'subtests':328,'actualEtcdTopLevelInvocations':9})]:
 out=ROOT/'docs/evidence/native-issuer-profile'/folder;manifest=group(out);srcdir=Path('/private/tmp')/task
 for src in sorted(srcdir.iterdir()):
  if src.is_file() and src.suffix in ['.log','.jsonl','.sh','.json']:
   manifest.append(put(src,out/src.name,src.suffix in ['.jsonl'] or src.name.startswith('full-')))
 repo='/private/tmp/cmtc-ztunnel-upstream' if folder=='source-binding' else '/private/tmp/cilium-ztunnel-authorization-runtime'
 patch=subprocess.check_output(['git','-C',repo,'diff',parent,sha,'--']);assert not private.search(patch);(out/'source.patch').write_bytes(patch)
 (out/'summary.json').write_text(json.dumps({'scope':'source qualification only; not deployed','sourceSHA':sha,'parentSHA':parent,'passed':counts,'fmt':True,'requiredLint':True,'newImageBuilt':False,'deployed':False,'Protected':False,'diagnosticsRetained':True,'files':manifest},indent=2)+'\n')
print('PASS archived public credential runtime, cleanup, source/test evidence; no binary archives or private keys')
