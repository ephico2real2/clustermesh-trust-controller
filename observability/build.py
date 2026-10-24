#!/usr/bin/env python3
"""Generate the consolidated CMTC operations dashboard; --check verifies reproducibility."""
import argparse
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
DS={'type':'prometheus','uid':'${DS_PROMETHEUS}'}
BLUE,RED,YELLOW,PURPLE,GREEN,ORANGE='#4e79a7','#e15759','#edc948','#b07aa1','#59a14f','#f28e2b'
CLUSTERS={'cmtc-a':BLUE,'cmtc-b':RED}
DECISIONS={'selected':('Selected',BLUE),'excluded':('Excluded',RED),'platform':('Platform',YELLOW),'unselected':('Unselected',PURPLE)}
SEL='job="cmtc",cluster=~"$cluster"'
CONTROLLER=SEL+',component="cmtc-controller"'
AGENT=SEL+',component="cmtc-node-agent"'
ALL=SEL+',component=~"cmtc-controller|cmtc-node-agent"'

def metric(name,labels=CONTROLLER,end=False):
    return f'{name}{{{labels}}}'+(' @ end()' if end else '')

def target(expr,legend='',ref='A',instant=True,table=False):
    t={'refId':ref,'expr':expr,'legendFormat':legend,'instant':instant,'range':not instant}
    if table:t['format']='table'
    return t

def color_override(name,color,matcher='byName',extra=None):
    return {'matcher':{'id':matcher,'options':name},'properties':[{'id':'color','value':{'mode':'fixed','fixedColor':color}},*(extra or [])]}

def panel(i,title,kind,pos,description,targets=None,unit='short'):
    p={'id':i,'title':title,'type':kind,'description':description,'gridPos':dict(zip(['x','y','w','h'],pos)),
       'fieldConfig':{'defaults':{'unit':unit,'min':0},'overrides':[]},'options':{}}
    if targets:p.update(datasource=DS,targets=targets)
    return p

def text(i,title,pos,content):
    p=panel(i,title,'text',pos,'Visible context and scope; documented status is not a live health metric.')
    p['options']={'mode':'markdown','content':content};return p

def row(i,title,y):
    return {'id':i,'title':title,'type':'row','collapsed':False,'panels':[],'gridPos':{'x':0,'y':y,'w':24,'h':1}}

def stat(i,title,pos,expr,description,color=BLUE,unit='short',decimals=0):
    p=panel(i,title,'stat',pos,description,[target(expr)],unit)
    p['fieldConfig']['defaults'].update(color={'mode':'fixed','fixedColor':color},decimals=decimals)
    p['options']={'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},'colorMode':'value','graphMode':'none','textMode':'value','text':{'valueSize':40}}
    return p

def table(i,title,pos,expr,columns,description):
    p=panel(i,title,'table',pos,description,[target(expr,table=True)])
    p['options']={'showHeader':True,'cellHeight':'sm','footer':{'show':False}}
    p['transformations']=[{'id':'organize','options':{'excludeByName':{'Time':True},'indexByName':{key:n for n,key in enumerate(columns)},'renameByName':columns}}]
    p['fieldConfig']['defaults']['decimals']=0
    p['fieldConfig']['overrides']=[{'matcher':{'id':'byName','options':'Cluster'},'properties':[{'id':'custom.width','value':115},{'id':'custom.cellOptions','value':{'type':'color-background','mode':'basic'}},{'id':'mappings','value':[{'type':'value','options':{c:{'text':c,'color':v} for c,v in CLUSTERS.items()}}]}]}]
    return p

def series(i,title,pos,expr,description,unit):
    p=panel(i,title,'timeseries',pos,description,[target(expr,'{{cluster}}',instant=False)],unit)
    p['fieldConfig']['defaults']['custom']={'lineWidth':1,'fillOpacity':10,'drawStyle':'line','showPoints':'never'}
    p['fieldConfig']['overrides']=[color_override(c,v,extra=([{'id':'custom.lineStyle','value':{'fill':'dash','dash':[8,6]}}] if c=='cmtc-b' else [])) for c,v in CLUSTERS.items()]
    p['options']={'legend':{'displayMode':'list','placement':'bottom','calcs':['lastNotNull']},'tooltip':{'mode':'multi','sort':'none'}}
    return p

def build():
    panels=[text(1,'CMTC operations · observed intent and inventory',(0,0,24,4),
       '**Observe mode:** namespace selection, existing enrollment labels, node inventory and controller activity are live. **Enforcement verification is unavailable.** These readings do not establish workload protection.\n\nUse the cluster selector for one cluster or both. Blue identifies cmtc-a; red identifies cmtc-b in charts and table cells. [Workload mTLS evidence](https://github.com/ephico2real2/clustermesh-trust-controller/blob/1c192a5ee84fb5218cb1385fdd9c5bf45ca69e1a/2026-10-24T0509Z-local-authenticated-only-f052d127/README.md) is a separate isolated trial.'),
       row(2,'Is CMTC reporting?',4),
       stat(3,'Controllers reporting',(0,5,6,4),f'count({metric("cmtc_enforcement_available",end=True)})','Latest controller metric series at range end, one per reporting controller. Not application or datapath readiness.'),
       stat(4,'Node inventories ready',(6,5,6,4),f'sum({metric("cmtc_node_agent_ready",AGENT,True)})','Latest successful local inventory observations at range end. Not encrypted or protected node counts.'),
       stat(5,'Namespaces selected · intent',(12,5,6,4),f'sum({metric("cmtc_namespaces_selected",end=True)})','Latest namespace selection intent at range end. The Observe controller does not change labels or enforce traffic.'),
       stat(6,'Enforcement verification',(18,5,6,4),f'max({metric("cmtc_enforcement_available",end=True)})','Native CMTC capability gauge at range end. Zero means verification is unavailable in Observe mode; missing telemetry remains unavailable.',ORANGE),
       row(7,'Which namespaces are selected?',9),
       stat(8,'Enrollment labels observed',(0,10,12,4),f'sum({metric("cmtc_namespaces_enrolled",end=True)})','Latest namespaces carrying the Cilium enrollment label from any actor. Label presence is intent, not protection.'),
       stat(9,'Non-platform namespaces observed',(12,10,12,4),f'sum({metric("cmtc_namespaces_eligible",end=True)})','Latest non-platform namespace inventory, including explicitly excluded namespaces; not a count of safe-to-enroll namespaces.'),
    ]
    panels[5]['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'Unavailable','color':ORANGE}}}]
    pie=panel(10,'Namespace decisions · latest share','piechart',(0,14,12,14),
       'Latest namespace decisions at the selected range end. Selected, excluded, platform and unselected are disjoint and sum to all observed namespaces in the selected clusters. This is inventory/intent, not mTLS coverage. Missing telemetry stays unavailable.',
       [target(f'sum({metric("cmtc_namespace_decisions",CONTROLLER+",decision=\""+key+"\"",True)})',label,chr(65+n)) for n,(key,(label,_)) in enumerate(DECISIONS.items())])
    pie['fieldConfig']['defaults'].update(decimals=1)
    pie['fieldConfig']['overrides']=[color_override(label,color) for label,color in DECISIONS.values()]
    pie['options']={'pieType':'pie','displayLabels':['percent'],'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},'legend':{'displayMode':'table','placement':'bottom','values':['value','percent']},'tooltip':{'mode':'single'}}
    panels.extend([pie,table(11,'Namespace decisions by cluster',(12,14,12,8),f'sum by(cluster,decision) ({metric("cmtc_namespace_decisions",end=True)})',{'cluster':'Cluster','decision':'Decision','Value':'Namespaces'},'Latest namespace decision gauges at range end, one row per cluster and decision. Zero is an observed empty category; a missing controller is not zero.'),
       text(12,'Read the namespace categories',(12,22,12,6),'**Selected** = policy intent. **Excluded** = explicit exclusion. **Platform** = protected infrastructure. **Unselected** = remaining namespaces.\n\nThe pie includes platform namespaces in its denominator. Non-platform inventory includes excluded namespaces. Enrollment labels are observed from any actor. None of these counts proves mTLS or Protected status.'),
       row(13,'Do controllers and node agents keep up?',28),
       stat(14,'Metrics targets reachable',(0,29,12,4),f'sum({metric("up",ALL,True)})','Latest successful scrapes at range end. The two-cluster lab expects six: two controllers plus four node agents. Filtered views have fewer targets. Scrape reachability is not workload protection.',GREEN),
       stat(15,'Controller reconcile errors/s',(12,29,12,4),f'sum(rate({metric("controller_runtime_reconcile_errors_total")}[$__rate_interval]))','Controller-runtime reconcile errors per second over the adaptive rate interval. An observed zero means no recorded errors; missing data is unavailable.',ORANGE,unit='ops',decimals=3),
       series(16,'Policy evaluations/s · by cluster',(0,33,12,8),f'sum by(cluster) (rate({metric("cmtc_policy_evaluations_total")}[$__rate_interval]))','Successful CMTC policy evaluations per second over $__rate_interval. A fall to zero can mean idle work; it is not protection readiness. Missing metrics remain unavailable.','ops'),
       series(17,'Controller reconcile p95 · seconds',(12,33,12,8),f'histogram_quantile(0.95, sum by(cluster,le) (rate({metric("controller_runtime_reconcile_time_seconds_bucket")}[$__rate_interval])))','95th-percentile controller-runtime reconcile duration from real histogram buckets, over $__rate_interval. It measures controller work, not network or TLS latency. No observations mean the percentile is unavailable.','s'),
       table(18,'Pod inventory by node',(0,41,12,10),f'sum by(cluster,node,network) ({metric("cmtc_pods_observed",AGENT,True)})',{'cluster':'Cluster','node':'Node','network':'Network','Value':'Pods'},'Latest node-local pod inventory at range end. pod and host classify network mode. Counts are not protected pods or successful platform probes.'),
       table(19,'Metrics targets · current state',(12,41,12,10),f'max by(cluster,component,node) ({metric("up",ALL,True)})',{'cluster':'Cluster','component':'Component','node':'Node','Value':'Scrape'},'Latest Prometheus target reachability at range end, with authoritative scrape cluster/component/node labels. UP does not establish workload or certificate readiness.'),
       text(20,'Inventory and controller telemetry boundaries',(0,51,24,3),'Rates use the adaptive scrape/zoom interval; lines start at zero, with solid blue cmtc-a and dashed red cmtc-b. Tables show the latest observations at range end. **hostNetwork inventory is not platform safety.** API, DNS, probe health, certificate rotation and layered encryption still require their own verified instrumentation.'),
       row(21,'What is still awaiting security qualification?',54),
       text(22,'Implementation status · documented scope, not live health',(0,55,24,8),'| Capability | Current evidence boundary |\n| --- | --- |\n| Namespace intent / node inventory | Live CMTC telemetry above; Observe remains read-only |\n| Workload mTLS / native DENY | Tested in the isolated two-node SPIRE fixture; see the separate mTLS evidence |\n| Persistent strict admission / authorization | Missing-policy, first-packet, finer caller permissions and restart/revocation gates remain open |\n| CA trust / rotation / remote identity | Public SVID validation demonstrated locally; rotation, issuer faults and cluster identity isolation remain open |\n| ClusterMesh / WireGuard / IPsec | Observe ClusterMesh baseline tested; cross-cluster workload mTLS and transport composition remain unqualified |\n| Kubernetes / OpenShift platform safety | Platform namespace exclusion implemented; required traffic/probe checks remain separate gates |\n\n**Missing security metrics are unknown.** No invented handshake, protected-pod, trust-ready or transport-success numbers are substituted. Original requirements remain in the observability proposals and agile backlog.'),
    ])
    for p in panels:
        if p['id']==11:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Decision'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-background','mode':'basic'}},{'id':'mappings','value':[{'type':'value','options':{key:{'text':label,'color':color} for key,(label,color) in DECISIONS.items()}}]}]})
        if p['id']==19:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Scrape'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-text'}},{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'DOWN','color':RED},'1':{'text':'UP','color':GREEN}}}]}]})
    return {'uid':'cmtc-observe-lab','title':'CMTC | Operations','schemaVersion':41,'version':1,'editable':False,'tags':['cmtc','observe'],'timezone':'utc','refresh':'5s','time':{'from':'now-15m','to':'now'},
       'templating':{'list':[{'name':'DS_PROMETHEUS','type':'datasource','query':'prometheus','current':{'text':'CMTC Prometheus','value':'cmtc-prom'}},
       {'name':'cluster','label':'Cluster','type':'query','datasource':DS,'query':{'query':'label_values(cmtc_enforcement_available{job="cmtc",component="cmtc-controller"},cluster)','refId':'ClusterVariable'},'refresh':1,'multi':True,'includeAll':True,'allValue':'.*','current':{'text':'All','value':'$__all'}}]},'annotations':{'list':[]},'panels':panels}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    path=ROOT/'dashboards/operations.json';text=json.dumps(build(),indent=2,ensure_ascii=False)+'\n'
    if args.check:
        assert path.read_text()==text,'Run python3 observability/build.py to refresh operations.json'
        print('PASS operations dashboard is reproducible')
    else:path.write_text(text)

if __name__=='__main__':main()
