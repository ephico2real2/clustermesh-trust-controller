import datetime,json,pathlib,urllib.parse,urllib.request
p=pathlib.Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike')
d=json.loads(pathlib.Path('/private/tmp/cmtc-mtls-spike-dashboard.json').read_text())
results=[]
for panel in d['panels']:
 for target in panel.get('targets',[]):
  expr=target['expr']
  url='http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom/api/v1/query?'+urllib.parse.urlencode({'query':expr})
  response=json.load(urllib.request.urlopen(url))
  assert response['status']=='success' and response['data']['result'],(panel['title'],response)
  results.append({'panel':panel['title'],'query':expr,'response':response})
  if panel['id'] in [2,5,6,7]:assert any(float(i['value'][1])>0 for i in response['data']['result']),(panel['title'],response)
(p/'dashboard-query-evidence.json').write_text(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'panels':results},indent=2)+'\n')
print('Verified all 7 metric panels: nonempty vectors; both native node targets and live traffic rates positive')
