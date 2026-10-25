#!/usr/bin/env python3
"""Check consolidated dashboard semantics and optionally retain real query evidence."""
import argparse
import hashlib
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
HISTORICAL=ROOT.parent/'examples/observability/ztunnel-spike/authenticated-only.json'
SELECTOR=re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}')
FUNCTIONS={'sum','max','min','count','rate','increase','histogram_quantile','label_replace','time','on','by','and','or','unless','end'}
DERIVED_LABELS={'source_trust_domain','destination_trust_domain','le'}
JOBS={'cmtc':'job="cmtc"','ztunnel':'job="ztunnel"','cilium':'job="cilium-agent"'}
# Families every baseline Observe lab exports; the unmodifiable capture walk requires
# data on every Operations panel outside the planned and opt-in prototype ranges.
BASELINE={'up','cmtc_enforcement_available','cmtc_namespace_decisions','cmtc_namespaces_selected','cmtc_namespaces_enrolled','cmtc_namespaces_eligible','cmtc_node_agent_ready','cmtc_pods_observed','cmtc_policy_evaluations_total','controller_runtime_reconcile_errors_total','controller_runtime_reconcile_time_seconds'}
MAX_GROUP_LABELS=7

def contract():
    return json.loads((ROOT/'metrics.json').read_text())['metrics']

def family_of(name):
    return name[:-7] if name.endswith('_bucket') else name

def selectors(expr):
    """Yield (metric, matcher text, start, end) for each metric selector in a PromQL string."""
    for m in SELECTOR.finditer(expr):
        if m.group(1) in FUNCTIONS:continue
        yield m.group(1),m.group(2),m.start(),m.end()

def windowed(expr,start):
    """True when the selector starting at start is the argument of rate() or increase()."""
    head=expr[:start].rstrip()
    return head.endswith('rate(') or head.endswith('increase(')

def query_checks(p,targets,metrics,page):
    for t in targets:
        expr=t['expr']
        assert 'vector(0)' not in expr,'Unavailable telemetry cannot be replaced with zero: '+p['title']
        assert 'clamp_min(' not in expr,'clamp_min turns an empty denominator into a value: '+p['title']
        found=list(selectors(expr));assert found,'Query has no metric selector: '+p['title']
        for name,matchers,start,_ in found:
            family=family_of(name)
            if family=='up':kind,emitter='gauge',None
            else:
                assert family in metrics,'Metric outside the contract: '+family
                kind,emitter=metrics[family]['kind'],metrics[family].get('emitter','cmtc')
            assert 'cluster=~"$cluster"' in matchers and 'component=' in matchers,'Unscoped selector in '+p['title']+': '+name
            if emitter:assert JOBS[emitter] in matchers,f'{family} is emitted by {emitter}; query it at its owner, not via another job: {p["title"]}'
            if kind=='gauge':assert not windowed(expr,start),'Gauge used as a counter: '+name
            if kind=='counter':assert windowed(expr,start),'Raw counter shown without a window: '+name+' in '+p['title']
            if kind=='histogram':
                assert name.endswith('_bucket') and windowed(expr,start) and 'histogram_quantile(' in expr and 'le)' in expr,'Latency percentile needs actual buckets: '+p['title']
        for by in re.findall(r'by\s*\(([^)]*)\)',expr):
            labels={x.strip() for x in by.split(',') if x.strip()}
            assert len(labels)<=MAX_GROUP_LABELS,'Label budget exceeded: '+p['title']
            allowed=set(DERIVED_LABELS)|{'cluster','node','component'}
            for name,_,_,_ in found:
                family=family_of(name)
                if family!='up':allowed|=set(metrics[family].get('labels',['cluster','node']))
            assert labels<=allowed,f'Grouping by labels outside the contract in {p["title"]}: {sorted(labels-allowed)}'
            assert not any('uid' in x.lower() for x in labels),'Pod/namespace UID labels are unbounded: '+p['title']

def style_checks(p):
    assert p.get('description'),'Missing description: '+p['title']
    assert set(re.findall('#[a-fA-F0-9]{6}',json.dumps(p.get('fieldConfig',{}))))<=PALETTE,'Colour outside the fixed Tableau palette: '+p['title']
    if p['type'] in ['timeseries','piechart']:assert p['options']['legend']['placement']=='bottom','Legend must sit below: '+p['title']
    if p['type']=='timeseries':
        custom=p['fieldConfig']['defaults']['custom']
        assert custom['lineWidth']==1 and custom['fillOpacity']==10 and p['fieldConfig']['defaults']['min']==0,'Line style: '+p['title']
        assert all(not t['instant'] for t in p['targets']),'A trend needs a range query: '+p['title']
    if p['type'] in ['stat','piechart','table']:
        assert all(t['instant'] for t in p['targets']),'A latest/selected-range reading must be an instant query: '+p['title']
    if p['type']=='piechart':
        assert all('$__range' in t['expr'] or ' @ end()' in t['expr'] for t in p['targets']),'A pie reads the end of its range: '+p['title']
    if p['type']=='table':
        assert p['transformations'][-1]['options']['excludeByName'].get('Time'),'Hide the table time column: '+p['title']

def pie_partition(security):
    """The workload pie must keep the five exclusive outcomes of the qualified historical source."""
    pie=next(p for p in list(build.all_panels(security)) if p['type']=='piechart')
    historical=next(p for p in json.loads(HISTORICAL.read_text())['panels'] if p['type']=='piechart')
    assert [t['legendFormat'] for t in pie['targets']]==[t['legendFormat'] for t in historical['targets']],'Outcome set changed'
    def outcome(expr):
        first=next(selectors(expr))[1]
        return sorted(x for x in first.split(',') if x.startswith(('connection_security_policy','response_flags')))
    for new,old in zip(pie['targets'],historical['targets']):
        assert outcome(new['expr'])==outcome(old['expr']),'Outcome selector changed: '+new['legendFormat']
        assert 'reporter="destination"' in new['expr'] and 'reporter="source"' not in new['expr'],'Pie must count each connection once'
        assert 'istio_tcp_connections_closed_total' in new['expr'] and '[$__range] @ end()' in new['expr']
        assert 'and on() (count(up{' in new['expr'] and 'unless on() (min(up{' in new['expr'],'Missing telemetry guard on '+new['legendFormat']
    colours={o['matcher']['options']:o['properties'][0]['value']['fixedColor'] for o in pie['fieldConfig']['overrides']}
    historical_colours={o['matcher']['options']:o['properties'][0]['value']['fixedColor'] for o in historical['fieldConfig']['overrides']}
    assert colours==historical_colours,'Outcome colours changed'
    return pie

def check_dashboards(operations,security,metrics=None):
    metrics=metrics or contract()
    for d in (operations,security):
        ids=[p['id'] for p in list(build.all_panels(d))];assert len(ids)==len(set(ids)),'Duplicate panel IDs in '+d['uid']
        assert {l['url'] for l in d['links']}=={'/d/'+build.OPERATIONS_UID,'/d/'+build.SECURITY_UID},'Cross-links lost'
        for p in list(build.all_panels(d)):
            if p['type']=='row':continue
            style_checks(p)
            query_checks(p,p.get('targets',[]),metrics,d['uid'])
            if p['id']>=100:assert '· planned' in p['title'] and 'missing data' in p['description'].lower()
            elif p.get('targets'):
                assert '· planned' not in p['title'],'Live panel titled planned: '+p['title']
                for t in p['targets']:
                    for name,_,_,_ in selectors(t['expr']):
                        family=family_of(name)
                        assert family=='up' or metrics[family]['status']=='implemented','Live panel queries an unqualified family: '+family
    assert (operations['uid'],security['uid'])==(build.OPERATIONS_UID,build.SECURITY_UID),'Stable dashboard UIDs changed'
    for p in list(build.all_panels(operations)):
        if p.get('targets') and p['id']<100 and not (30<=p['id']<=45):
            for t in p['targets']:
                names={family_of(n) for n,_,_,_ in selectors(t['expr'])}
                assert names<=BASELINE,'Operations panel needs data in every baseline Observe capture: '+p['title']
    pie_partition(security)
    return True

def domain_coverage(operations,security,metrics=None):
    metrics=metrics or contract()
    domains=json.loads((ROOT/'capabilities.json').read_text())['domains'];assert len(domains)==9
    page_of={'operations':operations,'workload-mtls':security}
    def queried(page):return {family_of(n) for p in list(build.all_panels(page)) for t in p.get('targets',[]) for n,_,_,_ in selectors(t['expr'])}
    for domain in domains:
        source=ROOT/domain['original_definition']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==domain['original_sha256'],'Original dashboard changed: '+str(source)
        proposal=json.loads(source.read_text())
        names=set(re.findall(r'\bcmtc_[a-zA-Z0-9_]+',' '.join(t['expr'] for p in proposal['panels'] for t in p.get('targets',[]))))
        assert names==set(domain['planned_metrics']),domain['domain']
        assert names<=set(metrics),domain['domain']
        assert domain['stories'] and domain['dashboard'] in page_of
        for name in names:
            destination=domain.get('metric_destinations',{}).get(name,domain['dashboard']);page=page_of[destination]
            if name in build.REPLACEMENTS:
                owner,panel_id,replacement=build.REPLACEMENTS[name]
                assert owner==destination,name
                assert replacement in next(p for p in list(build.all_panels(page)) if p['id']==panel_id)['targets'][0]['expr'],name
            else:
                family=metrics[name].get('family',name)
                assert family in queried(page),'Domain coverage lost: '+domain['domain']+' / '+name
                if family!=name:
                    assert any(p['description'].endswith('Metric contract: '+name) for p in list(build.all_panels(page)) if p['type']!='row'),'Contract name not traceable: '+name
    return domains

def rule_checks(metrics=None):
    metrics=metrics or contract()
    for path in (ROOT/'prometheus/recording-rules.yaml',ROOT/'prometheus/alerts.yaml'):
        content=path.read_text()
        assert 'clamp_min(' not in content,'A ratio denominator must stay empty when there is no traffic: '+path.name
        for expr in re.findall(r'expr:\s*(.+)',content):
            for name in re.findall(r'\b((?:cmtc|istio)_[a-zA-Z0-9_]+)\b',expr):
                family=family_of(name)
                assert family in metrics,f'{path.name} references a metric outside the contract: {family}'
                if metrics[family]['kind']=='counter':
                    assert re.search(r'(?:rate|increase)\(\s*'+re.escape(name),expr),f'{path.name} uses raw counter {name}'

def static_check(path=None):
    operations=json.loads((ROOT/'dashboards/operations.json').read_text())
    security=json.loads((ROOT/'dashboards/workload-security.json').read_text())
    assert operations==build.build(),'Generated Operations differs from its source'
    assert security==build.security(),'Generated Workload Security differs from its source'
    assert len(list((ROOT/'dashboards').glob('*.json')))==11,'Keep nine originals and two consolidated sources'
    check_dashboards(operations,security);domain_coverage(operations,security);rule_checks()
    return operations

def substitute(expr,cluster):
    return expr.replace('$cluster',cluster).replace('$namespace','.*').replace('$__rate_interval','60s').replace('$__range','15m')

def live_check(d,base,expect_native=False,expect_producer=False,trust_domains=None,expected_nodes=None):
    end=time.time();reports=[]
    def query(expr,allow_empty=False):
        url=base.rstrip('/')+'/api/v1/query?'+urllib.parse.urlencode({'query':expr,'time':end})
        start=time.monotonic()
        with urllib.request.urlopen(url,timeout=30) as response:body=json.load(response)
        elapsed=time.monotonic()-start
        assert body['status']=='success' and not body.get('warnings') and not body.get('infos'),body
        assert allow_empty or body['data']['result'],expr
        for row in body['data']['result']:
            value=float(row['value'][1])
            assert math.isfinite(value),(expr,row)
        return body,elapsed
    for cluster,targets,agents,controllers in [('cmtc-a|cmtc-b',6,4,2),('cmtc-a',3,2,1),('cmtc-b',3,2,1)]:
        records=[];pie=[]
        for p in list(build.all_panels(d)):
            for t in p.get('targets',[]):
                expr=substitute(t['expr'],cluster)
                body,elapsed=query(expr,allow_empty=p['id']>=100 or 30<=p['id']<=36 or 40<=p['id']<=45);values=[float(r['value'][1]) for r in body['data']['result']]
                records.append({'panel':p['title'],'panelId':p['id'],'target':t['refId'],'query':expr,'elapsedSeconds':elapsed,'response':body})
                if p['id']>=100:assert not values,'A planned metric is now exported; qualify and update its contract: '+p['title']
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
    security=build.security();native=[];planned=[]
    for p in list(build.all_panels(security)):
        for t in p.get('targets',[]):
            expr=substitute(t['expr'],'cmtc-a|cmtc-b')
            producer='cmtc_issuer_profile' in expr
            required=p['id']<100 and ((expect_producer and producer) or (expect_native and not producer))
            body,elapsed=query(expr,allow_empty=not required)
            record={'panel':p['title'],'panelId':p['id'],'target':t['refId'],'query':expr,'response':body,'elapsedSeconds':elapsed}
            if p['id']>=100:
                assert not body['data']['result'],'Qualify newly exported planned metric: '+p['title'];planned.append(record)
            else:native.append(record)
    report={'nativePanels':native,'plannedSecurityPanels':planned,'missingDataMeans':'Not deployed, not scraped or not implemented; never zero or Protected'}
    if expect_native:report['nativeAcceptance']=native_acceptance(query,trust_domains,expected_nodes)
    reports.append(report)
    unknown=list(build.all_panels(d))[2]['targets'][0]['expr'].replace('$cluster','cmtc-does-not-exist')
    empty,_=query(unknown,allow_empty=True);assert empty['data']['result']==[],'Missing target became false zero'
    absent,_=query(substitute(next(p for p in list(build.all_panels(security)) if p['id']==7)['targets'][0]['expr'],'cmtc-does-not-exist'),allow_empty=True)
    assert absent['data']['result']==[],'Missing ztunnel telemetry became false zero'
    return {'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'queryTimeSeconds':end,'rateInterval':'60s','selections':reports,'missingTelemetryRemainsUnavailable':True}

def native_acceptance(query,trust_domains,expected_nodes):
    """Real-traffic checks for an activated two-cluster ztunnel profile."""
    assert trust_domains and set(trust_domains)=={'cmtc-a','cmtc-b'} and all(trust_domains.values()),'Supply exact trust domains from the independently verified cluster profiles'
    assert expected_nodes and set(expected_nodes)=={'cmtc-a','cmtc-b'} and all(nodes and len(nodes)==2 and len(set(nodes))==2 and all(nodes) for nodes in expected_nodes.values()),'Supply two distinct frozen node names for each cluster'
    expected={(cluster,node) for cluster,nodes in expected_nodes.items() for node in nodes}
    coverage=query(f'up{{{build.ZTUNNEL.replace("$cluster","cmtc-a|cmtc-b")}}}')[0]['data']['result']
    actual=[(r['metric'].get('cluster',''),r['metric'].get('node','')) for r in coverage]
    assert len(actual)==len(expected) and set(actual)==expected and all(float(r['value'][1])==1 for r in coverage),'Require exactly one reporting ztunnel target for each independently frozen node'
    for family in ['workload_manager_active_proxy_count','workload_manager_pending_proxy_count']:
        rows=query(f'{family}{{{build.ZTUNNEL.replace("$cluster","cmtc-a|cmtc-b")}}}')[0]['data']['result']
        nodes=[(r['metric'].get('cluster',''),r['metric'].get('node','')) for r in rows]
        assert len(nodes)==len(expected) and set(nodes)==expected,f'{family} must report once for every frozen node; reachable scrape targets alone are insufficient'
    pie=next(p for p in build.all_panels(build.security()) if p['type']=='piechart')
    parts={t['legendFormat']:float(query(substitute(t['expr'],'cmtc-a|cmtc-b'))[0]['data']['result'][0]['value'][1]) for t in pie['targets']}
    total=float(query(substitute(build.closed(build.DEST),'cmtc-a|cmtc-b'))[0]['data']['result'][0]['value'][1])
    assert total>0,'No completed destination-reported TCP attempts in the window'
    assert math.isclose(sum(parts.values()),total,rel_tol=1e-9,abs_tol=1e-6),('Outcomes do not exhaust the denominator',parts,total)
    # Keep both certificate principal domains. The presentation table groups only
    # source domain and cluster; it cannot prove the destination identity binding.
    authenticated=f'increase(istio_tcp_connections_closed_total{{{build.DEST},{build.MTLS},response_flags="-"}}{build.RANGE})'
    domains=build.trust_domain(build.trust_domain(authenticated,'source_trust_domain','source_principal'),'destination_trust_domain','destination_principal')
    pairs=query(substitute(f'sum by(cluster,source_trust_domain,destination_trust_domain) ({domains})','cmtc-a|cmtc-b'))[0]['data']['result']
    seen={(r['metric']['cluster'],r['metric'].get('source_trust_domain',''),r['metric'].get('destination_trust_domain','')) for r in pairs if float(r['value'][1])>0}
    for receiver,sender in [('cmtc-a','cmtc-b'),('cmtc-b','cmtc-a')]:
        assert (receiver,trust_domains[sender],trust_domains[receiver]) in seen,f'No authenticated {sender} to {receiver} traffic with the exact configured domains'
    assert parts['mTLS · no failure flag']>0,'No completed authenticated positive traffic'
    assert parts['Authenticated denied']>0,'No denied authenticated attempts: exercise effective authorization independently'
    assert parts['Unauthenticated blocked']>0,'No rejected unauthenticated attempts: run the negative traffic'
    assert parts['Unverified · no failure flag']==0,'Unverified connections completed without a failure flag: possible plaintext acceptance'
    return {'outcomes':parts,'denominator':total,'clusterPairs':sorted('/'.join(x) for x in seen),'reportingNodes':sorted('/'.join(x) for x in actual)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dashboard',type=Path,default=ROOT/'dashboards/operations.json');parser.add_argument('--prometheus');parser.add_argument('--out',type=Path)
    parser.add_argument('--expect-native',action='store_true',help='require node ztunnel data on every live Workload Security panel and two-way authenticated traffic')
    parser.add_argument('--expect-producer',action='store_true',help='require issuer-profile producer data')
    parser.add_argument('--trust-domain-a',help='exact independently verified cmtc-a trust domain; required with --expect-native')
    parser.add_argument('--trust-domain-b',help='exact independently verified cmtc-b trust domain; required with --expect-native')
    parser.add_argument('--node-a',action='append',help='frozen cmtc-a node name; repeat for both nodes with --expect-native')
    parser.add_argument('--node-b',action='append',help='frozen cmtc-b node name; repeat for both nodes with --expect-native')
    args=parser.parse_args()
    if args.expect_native:
        assert args.trust_domain_a and args.trust_domain_b,'Native acceptance requires both exact trust domains'
        assert all(nodes and len(nodes)==2 and len(set(nodes))==2 for nodes in [args.node_a,args.node_b]),'Native acceptance requires two distinct --node-a and two distinct --node-b names from frozen cluster inventory'
    d=static_check(args.dashboard);print('PASS two consolidated pages, all nine unchanged originals, owner-scoped queries, full metric coverage and typed planned panels')
    if args.prometheus:
        assert args.out;report=live_check(d,args.prometheus,args.expect_native,args.expect_producer,{'cmtc-a':args.trust_domain_a,'cmtc-b':args.trust_domain_b},{'cmtc-a':args.node_a,'cmtc-b':args.node_b});args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n')
        print('PASS actual queries for both clusters and each cluster separately; namespace pie totals 100%; missing telemetry remains unavailable')
if __name__=='__main__':main()
