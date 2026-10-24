import datetime,importlib.util,json,pathlib
spec=importlib.util.spec_from_file_location('kit','/private/tmp/cmtc-diagram-kit-metrics.py'); kit=importlib.util.module_from_spec(spec);spec.loader.exec_module(kit)
out=pathlib.Path('/private/tmp/cmtc-spire-workload-qualification/artifacts/mtls-spike/authenticated-only-f052d127')
window=json.loads((out/'capture-time-window.json').read_text());end=window['queryTimeSeconds']
raw=kit.http_get('http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom',None,None)
def get(path,params):
 params=dict(params)
 if path=='/api/v1/query':params['time']=str(end)
 if path=='/api/v1/series':params.update(start=str(end-3600),end=str(end))
 return raw(path,params)
rows=kit.inventory_from_api(get,'{job="cmtc-spire-ztunnel",cluster="cmtc-mtls"}','1h')
body=kit.render(rows,'`{job="cmtc-spire-ztunnel",cluster="cmtc-mtls"}`; query end 2026-10-24T04:50:52Z; measured 2026-10-24','1h')
pin='\nGenerated with [diagram-kit metrics-inventory](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/diagram_kit/metrics.py). API queries and label discovery are anchored to the recorded load window; declared types come from current Prometheus metadata.\n'
pathlib.Path('examples/observability/ztunnel-spike/METRICS_INVENTORY.md').write_text(body+pin)
(out/'metrics-inventory.json').write_text(json.dumps(rows,indent=2)+'\n')
print(f'Inventory: {len(rows)} metric names, {len(set(r["family"] for r in rows))} families, {sum(r["series"] for r in rows)} series')
