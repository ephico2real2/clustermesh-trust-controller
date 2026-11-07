#!/usr/bin/env python3
"""Evaluate the generated dashboard queries and the Prometheus rules with promtool.

The expressions come from the generated dashboard JSON, not from copies, so a
semantic regression in build.py fails here. The series are synthetic inputs
with known per-minute slopes; they are not lab measurements.

Usage: promql_semantics.py [--write DIR] [--run]
  --write DIR  write the promtool test files to DIR (default: a temporary directory)
  --run        run promtool from the lab Prometheus image through the Podman build connection
"""
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent
IMAGE='docker.io/prom/prometheus:v3.7.0'
CONNECTION=os.environ.get('CMTC_PODMAN_CONNECTION','cmtc-ubuntu-build')
RANGE,RATE='15m','5m'
EVAL='15m'
A,B='spiffe://cmtc-a.mesh.example/ns/demo/sa/client','spiffe://cmtc-b.mesh.example/ns/demo/sa/client'
SA,SB='spiffe://cmtc-a.mesh.example/ns/demo/sa/server','spiffe://cmtc-b.mesh.example/ns/demo/sa/server'

def load():
    return {name:json.loads((ROOT/'dashboards'/name).read_text()) for name in ('operations.json','workload-security.json')}

def expr(page,panel,ref='A',cluster='.+',namespace='.+'):
    p=next(p for p in page['panels'] if p['id']==panel)
    e=next(t['expr'] for t in p['targets'] if t['refId']==ref)
    return (e.replace('$__rate_interval',RATE).replace('$__range',RANGE)
             .replace('$cluster',cluster).replace('$namespace',namespace))

def labels(**kw):
    return '{'+','.join(f'{k}="{v}"' for k,v in kw.items())+'}'

def zt(name,cluster,node,**kw):
    return name+labels(job='ztunnel',cluster=cluster,component='ztunnel',node=node,**kw)

def tcp(name,cluster,reporter,security,flag,src,dst,ns='demo'):
    node=cluster[-1]+'1'
    return zt(name,cluster,node,reporter=reporter,destination_workload_namespace=ns,connection_security_policy=security,
              response_flags=flag,source_principal=src,destination_principal=dst)

def up(cluster,value='1x20'):
    return {'series':zt('up',cluster,cluster[-1]+'1'),'values':value}

def counter(series,per_minute):
    return {'series':series,'values':f'0+{per_minute}x20'}

def bidirectional():
    """Known traffic: per-minute slope k gives increase 15k over 15m and rate k/60 over 5m."""
    closed='istio_tcp_connections_closed_total'
    return [
        up('cmtc-a'),up('cmtc-b'),
        counter(tcp(closed,'cmtc-a','destination','mutual_tls','-',B,SA),2),
        counter(tcp(closed,'cmtc-b','destination','mutual_tls','-',A,SB),1),
        counter(tcp(closed,'cmtc-a','destination','unknown','DENY','unknown',SA),1),
        counter(tcp(closed,'cmtc-b','destination','mutual_tls','DENY',A,SB),1),
        counter(tcp(closed,'cmtc-a','destination','unknown','TLS_FAILURE','unknown',SA),1),
        # The source side of the same connections; a pie that counted it would double count.
        counter(tcp(closed,'cmtc-b','source','mutual_tls','-',B,SA),100),
        counter(tcp('istio_tcp_connections_opened_total','cmtc-a','destination','mutual_tls','-',B,SA),2),
        counter(tcp('istio_tcp_connections_opened_total','cmtc-b','destination','mutual_tls','-',A,SB),1),
        counter(tcp('istio_tcp_connections_opened_total','cmtc-a','destination','unknown','-','unknown',SA),1),
        counter(tcp('istio_tcp_connections_failed_total','cmtc-a','destination','unknown','DENY','unknown',SA),1),
    ]

def samples(*pairs):
    return [{'labels':l,'value':v} for l,v in pairs]

def pie(page,expected,cluster='.+'):
    return [{'expr':expr(page,10,ref,cluster),'eval_time':EVAL,'exp_samples':samples(('{}',v)) if v is not None else []}
            for ref,v in zip('ABCDE',expected)]

def tests(pages):
    s=pages['workload-security.json']
    rate_a=1/60
    cases=[]
    cases.append({'name':'bidirectional traffic: destination-only partition, both cluster pairs, per-cluster DENY zero',
        'interval':'1m','input_series':bidirectional(),'promql_expr_test':[
        *pie(s,[45,15,15,0,15]),
        # The five outcomes partition exactly the destination-reported closes.
        {'expr':'sum(increase(istio_tcp_connections_closed_total{job="ztunnel",reporter="destination"}['+RANGE+'] @ end()))','eval_time':EVAL,'exp_samples':samples(('{}',90))},
        {'expr':expr(s,7),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a"}',30),('{cluster="cmtc-b"}',15))},
        {'expr':expr(s,8),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a"}',15))},
        {'expr':expr(s,9),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a"}',15))},
        {'expr':expr(s,16),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a",source_trust_domain="cmtc-b.mesh.example"}',30),('{cluster="cmtc-b",source_trust_domain="cmtc-a.mesh.example"}',15))},
        {'expr':expr(s,21),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a"}',rate_a),('{cluster="cmtc-b"}',0))},
    ]})
    cases.append({'name':'cluster filter selects one destination cluster',
        'interval':'1m','input_series':bidirectional(),'promql_expr_test':pie(s,[15,0,15,0,0],cluster='cmtc-b')})
    cases.append({'name':'no ztunnel telemetry stays unavailable, never zero',
        'interval':'1m','input_series':[{'series':'up'+labels(job='cmtc',cluster='cmtc-a',component='cmtc-controller',node='a1'),'values':'1x20'}],
        'promql_expr_test':[*pie(s,[None]*5),{'expr':expr(s,7),'eval_time':EVAL,'exp_samples':[]},{'expr':expr(s,21),'eval_time':EVAL,'exp_samples':[]}]})
    down=[i for i in bidirectional() if not i['series'].startswith('up{')]+[up('cmtc-a'),up('cmtc-b','1x10 0x10')]
    cases.append({'name':'one ztunnel target down hides the pie and the DENY rate',
        'interval':'1m','input_series':down,'promql_expr_test':[*pie(s,[None]*5),{'expr':expr(s,21),'eval_time':EVAL,'exp_samples':[]}]})
    idle=[up('cmtc-a'),{'series':tcp('istio_tcp_connections_closed_total','cmtc-a','destination','mutual_tls','-',B,SA),'values':'5x20'}]
    cases.append({'name':'idle but reporting ztunnel shows measured zero',
        'interval':'1m','input_series':idle,'promql_expr_test':pie(s,[0]*5)})
    ctl=lambda n:n+labels(job='cmtc',cluster='cmtc-a',component='cmtc-controller',node='a1')
    cases.append({'name':'issuer-profile producer: unset timestamps stay empty',
        'interval':'1m','input_series':[{'series':ctl('cmtc_issuer_profile_source_checked_timestamp_seconds'),'values':'0x20'},
                                        {'series':ctl('cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds'),'values':'0x20'}],
        'promql_expr_test':[{'expr':expr(s,24,'A'),'eval_time':EVAL,'exp_samples':[]},{'expr':expr(s,24,'B'),'eval_time':EVAL,'exp_samples':[]}],
        'alert_rule_test':[{'eval_time':EVAL,'alertname':'CMTCIssuerProfileLeaseExpired','exp_alerts':[]},
                           {'eval_time':EVAL,'alertname':'CMTCIssuerProfileSourceStale','exp_alerts':[]}]})
    cases.append({'name':'issuer-profile producer: age, lease and expiry',
        'interval':'1m','input_series':[{'series':ctl('cmtc_issuer_profile_source_checked_timestamp_seconds'),'values':'0+60x20'},
                                        {'series':ctl('cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds'),'values':'30+60x13 810x7'}],
        'promql_expr_test':[{'expr':expr(s,24,'A'),'eval_time':EVAL,'exp_samples':samples(('{cluster="cmtc-a"}',0))},
                            {'expr':expr(s,24,'B'),'eval_time':'12m','exp_samples':samples(('{cluster="cmtc-a"}',30))}],
        'alert_rule_test':[{'eval_time':'12m','alertname':'CMTCIssuerProfileLeaseExpired','exp_alerts':[]},
                           {'eval_time':EVAL,'alertname':'CMTCIssuerProfileLeaseExpired','exp_alerts':[{'exp_labels':{'severity':'warning','job':'cmtc','cluster':'cmtc-a','component':'cmtc-controller','node':'a1'},
                               'exp_annotations':{'summary':'The last acknowledged public issuer-profile lease has expired; consumers must treat the profile as unavailable'}}]}]})
    hs=lambda r:zt('istio_tls_handshakes_total','cmtc-a','a1',reporter='destination',result=r)
    cases.append({'name':'handshake success ratio is empty without handshakes and exact with them',
        'interval':'1m','input_series':[{'series':hs('success'),'values':'0x10 0+3x10'},{'series':hs('peer_verification_failed'),'values':'0x10 0+1x10'}],
        'promql_expr_test':[{'expr':'cmtc:ztunnel_tls_handshake_success:ratio_rate5m','eval_time':'8m','exp_samples':[]},
                            {'expr':'cmtc:ztunnel_tls_handshake_success:ratio_rate5m','eval_time':'18m','exp_samples':samples(('{__name__="cmtc:ztunnel_tls_handshake_success:ratio_rate5m",cluster="cmtc-a"}',0.75))}]})
    cases.append({'name':'unreachable ztunnel target alerts',
        'interval':'1m','input_series':[up('cmtc-a','1x5 0x15')],
        'alert_rule_test':[{'eval_time':'8m','alertname':'CMTCScrapeTargetDown','exp_alerts':[]},
                           {'eval_time':EVAL,'alertname':'CMTCScrapeTargetDown','exp_alerts':[{'exp_labels':{'severity':'critical','job':'ztunnel','cluster':'cmtc-a','component':'ztunnel','node':'a1'},
                               'exp_annotations':{'summary':'A CMTC or node ztunnel metrics target is unreachable; its panels are unavailable, not healthy'}}]}]})
    return cases

def write(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    for name in ('recording-rules.yaml','alerts.yaml'):shutil.copy(ROOT/'prometheus'/name,directory/name)
    document={'rule_files':['recording-rules.yaml','alerts.yaml'],'evaluation_interval':'1m','tests':tests(load())}
    (directory/'dashboard-semantics.test.json').write_text(json.dumps(document,indent=1)+'\n')
    return directory,len(document['tests']),sum(len(t.get('promql_expr_test',[]))+len(t.get('alert_rule_test',[])) for t in document['tests'])

def run(directory):
    command=['podman','--connection',CONNECTION,'run','--rm','--arch','arm64','--cpus','2','--memory','4g',
             '-v',f'{directory}:/w:ro','--workdir','/w','--entrypoint','/bin/promtool',IMAGE,
             'test','rules','dashboard-semantics.test.json']
    return subprocess.run(command).returncode

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--write');parser.add_argument('--run',action='store_true')
    args=parser.parse_args()
    # The Podman machine shares /private/tmp with the host; the default macOS temporary directory is not shared.
    directory,cases,checks=write(args.write or tempfile.mkdtemp(prefix='cmtc-promql-',dir='/private/tmp' if Path('/private/tmp').is_dir() else None))
    print(f'wrote {cases} cases, {checks} evaluations: {directory}')
    sys.exit(run(directory) if args.run else 0)
