#!/usr/bin/env python3
"""Check consolidated dashboard semantics and optionally retain real query evidence."""
import argparse
import datetime
import importlib.util
import json
import math
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('dashboard_build',ROOT/'build.py')
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
PALETTE={build.BLUE,build.RED,build.YELLOW,build.PURPLE,build.GREEN,build.ORANGE}

def static_check(path):
    d=json.loads(path.read_text());assert d==build.build(),'Generated dashboard differs from its source'
    assert len(list((ROOT/'dashboards').glob('*.json')))==1,'Duplicate active operations dashboards'
    panels=[p for p in d['panels'] if p['type']!='row'];assert len(panels)==18
    assert all(p.get('description') for p in panels)
    assert len(set(p['id'] for p in d['panels']))==len(d['panels'])
    contract=json.loads((ROOT/'metrics.json').read_text())['metrics']
    for p in panels:
        for t in p.get('targets',[]):
            for name in re.findall(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\{',t['expr']):
                family=name[:-7] if name.endswith('_bucket') else name
                kind='gauge' if family=='up' else contract[family]['kind']
                if kind=='gauge':assert not re.search(r'(?:rate|increase)\(\s*'+re.escape(name),t['expr']), 'Gauge used as a counter: '+name
                if kind=='counter':assert 'rate(' in t['expr'] or 'increase(' in t['expr'], 'Raw counter shown without a window: '+name
                if kind=='histogram':assert 'histogram_quantile(' in t['expr'] and 'le)' in t['expr'], 'Latency percentile needs actual buckets'
    actual=set(re.findall(r'\bcmtc_[a-zA-Z0-9_]+',' '.join(t['expr'] for p in panels for t in p.get('targets',[]))))
    available={'cmtc_enforcement_available','cmtc_namespace_decisions','cmtc_namespaces_selected','cmtc_namespaces_enrolled','cmtc_namespaces_eligible','cmtc_node_agent_ready','cmtc_pods_observed','cmtc_policy_evaluations_total'}
    assert actual<=available,actual-available
    for p in panels:
        assert set(re.findall('#[a-fA-F0-9]{6}',json.dumps(p.get('fieldConfig',{}))))<=PALETTE
        for target in p.get('targets',[]):
            assert 'cluster=~"$cluster"' in target['expr'] and 'component=' in target['expr']
            assert 'vector(0)' not in target['expr'],'Unavailable telemetry cannot be replaced with zero'
        if p['type'] in ['timeseries','piechart']:assert p['options']['legend']['placement']=='bottom'
        if p['type']=='timeseries':
            assert p['fieldConfig']['defaults']['custom']['lineWidth']==1
            assert p['fieldConfig']['defaults']['custom']['fillOpacity']==10
            assert p['fieldConfig']['defaults']['min']==0
    domains=json.loads((ROOT/'capabilities.json').read_text())['domains'];assert len(domains)==9
    contract=json.loads((ROOT/'metrics.json').read_text())['metrics']
    for domain in domains:
        proposal=json.loads((ROOT/domain['original_definition']).read_text())
        metrics=set(re.findall(r'\bcmtc_[a-zA-Z0-9_]+',' '.join(t['expr'] for p in proposal['panels'] for t in p.get('targets',[]))))
        assert metrics==set(domain['planned_metrics']),domain['domain']
        assert metrics<=set(contract),domain['domain']
        assert domain['stories'] and domain['dashboard'] in ['operations','workload-mtls']
    return d

def live_check(d,base):
    end=time.time();reports=[]
    def query(expr,allow_empty=False):
        url=base.rstrip('/')+'/api/v1/query?'+urllib.parse.urlencode({'query':expr,'time':end})
        start=time.monotonic()
        with urllib.request.urlopen(url,timeout=30) as response:body=json.load(response)
        elapsed=time.monotonic()-start
        assert body['status']=='success' and not body.get('warnings') and not body.get('infos'),body
        assert allow_empty or body['data']['result'],expr
        for row in body['data']['result']:
            assert math.isfinite(float(row['value'][1])) and float(row['value'][1])>=0,(expr,row)
        return body,elapsed
    for cluster,targets,agents,controllers in [('cmtc-a|cmtc-b',6,4,2),('cmtc-a',3,2,1),('cmtc-b',3,2,1)]:
        records=[];pie=[]
        for p in d['panels']:
            for t in p.get('targets',[]):
                expr=t['expr'].replace('$cluster',cluster).replace('$__rate_interval','60s')
                body,elapsed=query(expr);values=[float(r['value'][1]) for r in body['data']['result']]
                records.append({'panel':p['title'],'panelId':p['id'],'target':t['refId'],'query':expr,'elapsedSeconds':elapsed,'response':body})
                if p['id'] in [3,4,6,14]:assert values==[{3:controllers,4:agents,6:0,14:targets}[p['id']]],(p['title'],values)
                if p['id'] in [16,17]:assert any(v>0 for v in values),(p['title'],values)
                if p['id']==10:
                    assert len(values)==1;pie.append({'decision':t['legendFormat'],'namespaces':values[0]})
        denominator=f'sum(cmtc_namespace_decisions{{job="cmtc",cluster=~"{cluster}",component="cmtc-controller"}} @ end())'
        body,_=query(denominator);total=float(body['data']['result'][0]['value'][1]);assert total>0
        assert sum(p['namespaces'] for p in pie)==total
        for part in pie:part['percent']=100*part['namespaces']/total
        assert math.isclose(sum(p['percent'] for p in pie),100,abs_tol=1e-9)
        reports.append({'clusterSelection':cluster,'queries':records,'namespacePie':{'total':total,'categories':pie,'percentSum':100},'querySeconds':sum(r['elapsedSeconds'] for r in records)})
    unknown=d['panels'][2]['targets'][0]['expr'].replace('$cluster','cmtc-does-not-exist')
    empty,_=query(unknown,allow_empty=True);assert empty['data']['result']==[],'Missing target became false zero'
    return {'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'queryTimeSeconds':end,'rateInterval':'60s','selections':reports,'missingTelemetryRemainsUnavailable':True}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--dashboard',type=Path,default=ROOT/'dashboards/operations.json');parser.add_argument('--prometheus');parser.add_argument('--out',type=Path);args=parser.parse_args()
    d=static_check(args.dashboard);print('PASS one operations page, Tableau palette, descriptions, scoped queries and all nine planned domains preserved')
    if args.prometheus:
        assert args.out;report=live_check(d,args.prometheus);args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n')
        print('PASS actual queries for both clusters and each cluster separately; namespace pie totals 100%; missing telemetry remains unavailable')
if __name__=='__main__':main()
