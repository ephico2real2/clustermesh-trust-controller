import datetime as dt,importlib.util,json,subprocess,sys,time,urllib.parse,urllib.request
from pathlib import Path
root=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller');out=Path('/private/tmp/cmtc-native-credentials-20261025')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
pub=load('live_publisher',root/'scripts/lab/issuer-profile/publish_issuers.py');checker=load('publication_check',root/'scripts/lab/issuer-profile/test-issuer-profile.py')
owner=json.loads(Path('/Users/olasumbo/.local/share/cmtc-issuer-profile/live-a-b/ledger.json').read_text());result={}
for c,v in owner['clusters'].items():
 args=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c,'--request-timeout=20s','-n','cmtc-system','get','configmap','cmtc-issuer-publication','-o','json']
 raw=subprocess.check_output(args,timeout=30,text=True);obj=json.loads(raw);pub.owned(obj,owner['owner'],v['uids']['ConfigMap/cmtc-issuer-publication'])
 p=checker.publication(obj['data']['profile.json'],c,obj['metadata']['uid']);pub.check_floor(p,v['lastPublication']);assert p['approval']==owner['approval'] and p['state']=='published' and p['reason']=='Validated' and p['sequence']>v['lastPublication']['sequence']
 now=dt.datetime.now(dt.timezone.utc);until=dt.datetime.fromisoformat(p['validUntil'].replace('Z','+00:00'));assert 0<(until-now).total_seconds()<=31
 queries=[]
 for old in v['metrics']:
  endpoint=('http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom' if c=='cmtc-a' else 'http://127.0.0.1:19091')+'/api/v1/query?'+urllib.parse.urlencode({'query':old['query']})
  with urllib.request.urlopen(endpoint,timeout=15) as response:data=json.load(response)
  assert data['status']=='success' and data['data']['result']
  for sample in data['data']['result']:
   assert -2<=time.time()-sample['value'][0]<20
   value=float(sample['value'][1])
   if 'enforcement_available' in old['query']:assert value==0
   elif 'source_checked_timestamp' in old['query']:assert -2<=time.time()-value<20
   elif 'acknowledged_valid_until' in old['query']:assert -2<value-time.time()<=31
   else:assert value>=1
  queries.append({'query':old['query'],'response':data})
 result[c]={'sequenceBefore':v['lastPublication']['sequence'],'sequenceNow':p['sequence'],'validUntil':p['validUntil'],'outputUID':obj['metadata']['uid'],'publication':p,'metrics':queries};print('PASS',c,'publication remains current, source/floors retained, all5metricqueries fresh',flush=True)
(out/'publication-after-bootstrap.json').write_text(json.dumps(result,indent=2)+'\n')
