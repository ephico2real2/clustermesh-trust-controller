#!/usr/bin/env python3
"""Generate the consolidated CMTC operations dashboard; --check verifies reproducibility."""
import argparse
import copy
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
OBSERVER=SEL+',component="cmtc-bpf-observer"'
FENCE=SEL+',component="cmtc-bpf-fence"'
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

def operations():
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
    panels.extend([pie,table(11,'Namespace decisions by cluster',(12,14,12,10),f'sum by(cluster,decision) ({metric("cmtc_namespace_decisions",end=True)})',{'cluster':'Cluster','decision':'Decision','Value':'Namespaces'},'Latest namespace decision gauges at range end, one row per cluster and decision. Zero is an observed empty category; a missing controller is not zero.'),
       text(12,'Read the namespace categories',(12,24,12,4),'**Selected** = policy intent. **Excluded** = explicit exclusion. **Platform** = protected infrastructure. **Unselected** = remaining namespaces.\n\nThe pie includes platform namespaces in its denominator. Non-platform inventory includes excluded namespaces. Enrollment labels are observed from any actor. None of these counts proves mTLS or Protected status.'),
       row(13,'Do controllers and node agents keep up?',28),
       stat(14,'Inventory/controller targets reachable',(0,29,12,4),f'sum({metric("up",ALL,True)})','Latest successful scrapes at range end. The two-cluster lab expects six inventory/controller targets: two controllers plus four node agents. Opt-in fence targets are shown separately below. Filtered views have fewer targets. Read the target table for individual failures; this count is not an all-healthy verdict.',BLUE),
       stat(15,'Controller reconcile errors/s',(12,29,12,4),f'sum(rate({metric("controller_runtime_reconcile_errors_total")}[$__rate_interval]))','Controller-runtime reconcile errors per second over the adaptive rate interval. An observed zero means no recorded errors; missing data is unavailable.',ORANGE,unit='ops',decimals=3),
       series(16,'Policy evaluations/s · by cluster',(0,33,12,8),f'sum by(cluster) (rate({metric("cmtc_policy_evaluations_total")}[$__rate_interval]))','Successful CMTC policy evaluations per second over $__rate_interval. A fall to zero can mean idle work; it is not protection readiness. Missing metrics remain unavailable.','ops'),
       series(17,'Controller reconcile p95 · seconds',(12,33,12,8),f'histogram_quantile(0.95, sum by(cluster,le) (rate({metric("controller_runtime_reconcile_time_seconds_bucket")}[$__rate_interval])))','95th-percentile controller-runtime reconcile duration from real histogram buckets, over $__rate_interval. It measures controller work, not network or TLS latency. No observations mean the percentile is unavailable.','s'),
       table(18,'Pod inventory by node',(0,41,12,10),f'sum by(cluster,node,network) ({metric("cmtc_pods_observed",AGENT,True)})',{'cluster':'Cluster','node':'Node','network':'Network','Value':'Pods'},'Latest node-local pod inventory at range end. pod and host classify network mode. Counts are not protected pods or successful platform probes.'),
       table(19,'Inventory/controller targets · current state',(12,41,12,10),f'max by(cluster,component,node) ({metric("up",ALL,True)})',{'cluster':'Cluster','component':'Component','node':'Node','Value':'Scrape'},'Latest Prometheus target reachability at range end, with authoritative scrape cluster/component/node labels. UP does not establish workload or certificate readiness.'),
       text(20,'Inventory and controller telemetry boundaries',(0,51,24,3),'Rates use the adaptive scrape/zoom interval; lines start at zero, with solid blue cmtc-a and dashed red cmtc-b. Tables show the latest observations at range end. **hostNetwork inventory is not platform safety.** API, DNS, probe health, certificate rotation and layered encryption still require their own verified instrumentation.'),
       row(21,'What is still awaiting security qualification?',54),
       text(22,'Implementation status · documented scope, not live health',(0,55,24,10),'| Capability | Current evidence boundary |\n| --- | --- |\n| Namespace intent / node inventory | Live CMTC telemetry above; Observe remains read-only |\n| Workload mTLS / native DENY | Tested in the isolated two-node SPIRE fixture; see the separate mTLS evidence |\n| Persistent strict admission / authorization | Missing-policy, first-packet, finer caller permissions and restart/revocation gates remain open |\n| CA trust / rotation / remote identity | Public SVID validation demonstrated locally; rotation, issuer faults and cluster identity isolation remain open |\n| ClusterMesh / WireGuard / IPsec | Observe ClusterMesh baseline tested; cross-cluster workload mTLS and transport composition remain unqualified |\n| Kubernetes / OpenShift platform safety | Platform namespace exclusion implemented; required traffic/probe checks remain separate gates |\n\n**Missing security metrics are unknown.** No invented handshake, protected-pod, trust-ready or transport-success numbers are substituted. Planned panels below retain every original domain; their metrics will be implemented as the agile stories progress.'),
    ])
    for p in panels:
        if p['id']==11:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Decision'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-background','mode':'basic'}},{'id':'mappings','value':[{'type':'value','options':{key:{'text':label,'color':color} for key,(label,color) in DECISIONS.items()}}]}]})
        if p['id']==19:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Scrape'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-text'}},{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'DOWN','color':RED},'1':{'text':'UP','color':GREEN}}}]}]})
    return {'uid':'cmtc-observe-lab','title':'CMTC | Operations','schemaVersion':41,'version':1,'editable':False,'tags':['cmtc','observe'],'timezone':'utc','refresh':'5s','time':{'from':'now-15m','to':'now'},
       'templating':{'list':[{'name':'DS_PROMETHEUS','type':'datasource','query':'prometheus','current':{'text':'CMTC Prometheus','value':'cmtc-prom'}},
       {'name':'cluster','label':'Cluster','type':'query','datasource':DS,'query':{'query':'label_values(cmtc_enforcement_available{job="cmtc",component="cmtc-controller"},cluster)','refId':'ClusterVariable'},'refresh':1,'multi':True,'includeAll':True,'allValue':'.*','current':{'text':'All','value':'$__all'}}]},'annotations':{'list':[]},'panels':panels}

# Retain the original nine definitions unchanged; these grouped panels replace
# repeated copies of the same metric in the two live pages.
GROUPS={
 'operations':[
  ('Can workloads be verified as protected? · planned',[
   ('Verified cluster gates','cmtc_cluster_ready'),('Pods protected','cmtc_pods_protected'),
   ('Pods awaiting enforcement','cmtc_pods_pending'),('Pods enforcement failed','cmtc_pods_enforcement_failed')]),
  ('Are platform dependencies safe? · planned',[
   ('Platform dependency health','cmtc_platform_dependency_healthy'),('API probe result','cmtc_apiserver_probe_success'),
   ('Rollouts aborted/s','cmtc_rollout_aborted_total')]),
  ('Are enrollment and node configurations drifting? · planned',[
   ('Enrollment label drift/s','cmtc_namespace_label_drift_total'),('Node configuration drift/s','cmtc_node_config_drift_total'),
   ('Proxy configuration ready','cmtc_ztunnel_ready')]),
 ],
 'workload-mtls':[
  ('How do real TLS handshakes and remote identity look? · planned',[
   ('TLS handshakes/s','cmtc_mtls_handshakes_total'),('Active mTLS connections','cmtc_mtls_active_connections'),
   ('Peer identity validation failures/s','cmtc_mtls_identity_validation_failures_total'),('Remote identity cache misses/s','cmtc_remote_identity_cache_misses_total'),
   ('TLS handshake p95','cmtc_mtls_handshake_duration_seconds')]),
  ('Are trust, issuer and rotation healthy? · planned',[
   ('Trust bundle consumed','cmtc_trust_bundle_ready'),('SPIRE API acknowledged','cmtc_spire_ready'),
   ('Issuer chain verified','cmtc_issuer_ready'),('Certificate rotation failures/s','cmtc_certificate_rotation_failures_total')]),
  ('Do workload and node encryption compose? · planned',[
   ('Transport profile verified','cmtc_transport_compatibility_ready'),('Dual encryption probe result','cmtc_dual_encryption_probe_success'),
   ('Transport encryption failures/s','cmtc_transport_encryption_failures_total'),('MTU validation failures/s','cmtc_mtu_validation_failures_total')]),
  ('Which security violations are observed? · planned',[
   ('Authorization denials/s','cmtc_mtls_authorization_denials_total'),('Plaintext bypass incidents/s','cmtc_plaintext_bypass_detected_total'),
   ('Namespace policy conflicts/s','cmtc_namespace_policy_conflicts_total')]),
 ]}
# Existing live signals already answer these requirements; keep their original
# proposed names in the metric contract, without inventing duplicate exporters.
REPLACEMENTS={
 'cmtc_namespaces_excluded':('operations',10,'cmtc_namespace_decisions'),
 'cmtc_hostnetwork_pods_total':('operations',18,'cmtc_pods_observed'),
 'cmtc_reconcile_errors_total':('operations',15,'controller_runtime_reconcile_errors_total'),
}

def add_planned(dashboard,page,y):
    contract=json.loads((ROOT/'metrics.json').read_text())['metrics']
    next_id=100
    for title,items in GROUPS[page]:
        dashboard['panels'].append(row(next_id,title,y));next_id+=1;y+=1
        for index,(label,name) in enumerate(items):
            c=contract[name];kind=c['kind'];height=7
            pos=((index%2)*12,y+(index//2)*height,12,height)
            desc='Planned instrumentation; missing data means not implemented, never success. '+c['meaning']+' '+c['presentation']+' Proposed labels/source must be qualified in the delivering story.'
            if kind=='counter':
                p=series(next_id,label+' · planned',pos,f'sum by(cluster) (rate({name}{{{ALL}}}[$__rate_interval]))',desc,'ops')
            elif kind=='histogram':
                p=series(next_id,label+' · planned',pos,f'histogram_quantile(0.95, sum by(cluster,le) (rate({name}_bucket{{{ALL}}}[$__rate_interval])))',desc,'s')
            else:
                state=any(x in name for x in ['ready','healthy','probe_success'])
                aggregate='min' if state else 'sum'
                p=stat(next_id,label+' · planned',pos,f'{aggregate} by(cluster) ({name}{{{ALL}}} @ end())',desc)
                p['targets'][0]['legendFormat']='{{cluster}}'
                if name=='cmtc_platform_dependency_healthy':
                    p['targets'][0]['expr']=f'{name}{{{ALL}}} @ end()'
                    p['targets'][0]['legendFormat']='{{cluster}} · {{dependency}}'
                p['options']['textMode']='value_and_name'
                p['fieldConfig']['overrides']=[color_override(c,v) for c,v in CLUSTERS.items()]
                if state:p['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'Not ready','color':ORANGE},'1':{'text':'Verified','color':GREEN}}}]
            # Metadata is for source validation; no synthetic values or fake exporter.
            p['description']+=' Metric contract: '+name
            dashboard['panels'].append(p);next_id+=1
        y+=((len(items)+1)//2)*7
    return dashboard

def security():
    d=copy.deepcopy(json.loads((ROOT.parent/'examples/observability/ztunnel-spike/authenticated-only.json').read_text()))
    d['title']='CMTC | Workload Security'
    d['description']='Native two-node mTLS trial plus retained TLS, trust, transport and violation panels. Planned instrumentation is explicitly unavailable; TCP starts are not TLS handshakes.'
    # The cluster selector below affects planned CMTC panels only. Native panels
    # deliberately stay pinned to the isolated cmtc-mtls fixture.
    d['templating']=copy.deepcopy(operations()['templating'])
    d['panels'][0]['options']['content']='**Native panels: isolated cmtc-mtls fixture only.** The Cluster selector affects planned CMTC panels below. **Planned panels: not implemented; No data is expected until their stories land.**\n\n'+d['panels'][0]['options']['content']
    d['panels'][0]['gridPos']['h']=7
    for p in d['panels'][1:]:p['gridPos']['y']+=2
    d['panels'].append(text(90,'Future security instrumentation',(0,44,24,4),'**The four sections below preserve the original mTLS Performance, CA Trust and Rotation, Network Encryption and Security Violations dashboards.** Peer-identity failures appear once under TLS performance. Native TCP counters above do not replace actual TLS handshake metrics.\n\nPlanned counters use rates, gauges show latest levels/states, and TLS p95 requires actual handshake histogram buckets. Missing instrumentation is unknown, not zero.'))
    return add_planned(d,'workload-mtls',48)

def add_datapath(dashboard):
    desc='Explicit deny-only disposable-veth prototype. Packets are not requests, connections or TLS handshakes. Missing telemetry remains unavailable; quarantine verification is not Protected or mTLS. '
    dashboard['panels'].extend([
        row(30,'Audited datapath quarantine · opt-in lab only',65),
        text(31,'Packet counters and quarantine scope',(0,66,24,4),'**One audited workload veth/hook per selected node.** These panels observe the opt-in deny-only DaemonSet, not whole-node traffic or workload mTLS. Packet retransmissions count; counters are not HTTP request totals. **No mTLS or Protected claim.**\n\nA fresh verified sample permits counters to be exported; stale/unverified samples omit counters and report verification 0. Missing exporter/scrape is unavailable. Exact pinned-map adoption retains counters; a newly installed map resets them. There is no meaningful success-percentage pie from these counters.'),
        table(32,'Audited quarantine · latest by node',(0,70,12,8),f'min by(cluster,node,direction) ({metric("cmtc_datapath_fence_quarantine_verified",FENCE,True)}) and on(cluster,node) ({metric("up",FENCE,True)} == 1)',{'cluster':'Cluster','node':'Node','direction':'Hook','Value':'Quarantine'},desc+'Latest 0/1 sample at range end, filtered to reachable scrapes. Do not sum away individual failed or missing nodes.'),
        series(33,'Packets rejected by audited quarantine/s',(12,70,12,8),f'sum by(cluster) (rate({metric("cmtc_datapath_fence_dropped_packets_total",FENCE)}[$__rate_interval]))',desc+'Rate of actual TCX DROP packets over the adaptive scrape interval; an idle verified hook can report zero.','pps'),
        stat(34,'Quarantine rejected packets · selected range',(0,78,12,6),f'sum by(cluster) (increase({metric("cmtc_datapath_fence_dropped_packets_total",FENCE)}[$__range]))',desc+'Prometheus extrapolated selected-range packet increase; retransmits count. This is not an exact application-attempt ledger.'),
        series(35,'skb bytes rejected by quarantine/s',(12,78,12,6),f'sum by(cluster) (rate({metric("cmtc_datapath_fence_dropped_bytes_total",FENCE)}[$__rate_interval]))',desc+'skb byte lengths per second, including network headers; not payload or encrypted bytes.','Bps'),
        table(36,'Fence metrics targets · latest reachability',(0,84,24,8),f'max by(cluster,node) ({metric("up",FENCE,True)})',{'cluster':'Cluster','node':'Node','Value':'Scrape'},desc+'UP means only scrape reachable. Missing expected nodes must be checked against the explicit selected-node ledger; this table cannot invent a missing target.'),
    ])
    for p in dashboard['panels']:
        if p['id']==32:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Quarantine'},'properties':[{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'Unverified','color':ORANGE},'1':{'text':'Quarantine verified','color':BLUE}}}]}]})
        if p['id']==34:
            p['targets'][0]['legendFormat']='{{cluster}}'
            p['options']['textMode']='value_and_name'
            p['fieldConfig']['defaults']['decimals']=1
            p['fieldConfig']['overrides']=[color_override(c,v) for c,v in CLUSTERS.items()]
    return dashboard

def add_observer(dashboard):
    desc='Opt-in Observe prototype at one audited TCX hook per selected node, before native Cilium verdict. The observer returns NEXT, so its counters do not prove forwarding, a Cilium decision, requests, TLS or protection. '
    dashboard['panels'].extend([
        row(40,'Audited packet observation · opt-in lab only',92),
        text(41,'Read observation separately from quarantine',(0,93,24,4),'**Observer counts packets at an audited TCX hook before native Cilium makes its verdict.** It returns NEXT and does not allow/deny traffic itself. Native Cilium can still drop a counted packet. These are skb/packet totals, not HTTP attempts, connections or TLS handshakes.\n\nThe observer and deny-only fence have different hooks/lifecycles. They are qualified sequentially and cannot be combined into an outcome pie. Missing observer telemetry means it is not installed or not reporting; no successful zero is invented. A fresh idle observer can report zero, and unpinned maps reset on process/attachment restart.'),
        table(42,'Audited observer · latest by node',(0,97,12,8),f'min by(cluster,node,direction) ({metric("cmtc_datapath_observer_ready",OBSERVER,True)}) and on(cluster,node) ({metric("up",OBSERVER,True)} == 1)',{'cluster':'Cluster','node':'Node','direction':'Hook','Value':'Observation'},desc+'Latest fresh0/1 sample at range end, filtered to reachable scrapes. Failed/missing expected nodes remain an explicit evidence gate.'),
        series(43,'Packets observed before Cilium verdict/s',(12,97,12,8),f'sum by(cluster) (rate({metric("cmtc_datapath_observer_packets_total",OBSERVER)}[$__rate_interval]))',desc+'Packet rate over the adaptive scrape interval. Retransmits/non-HTTP traffic count; zero can mean idle. Missing/stale counters remain unavailable.','pps'),
        series(44,'skb bytes observed before Cilium verdict/s',(0,105,12,8),f'sum by(cluster) (rate({metric("cmtc_datapath_observer_bytes_total",OBSERVER)}[$__rate_interval]))',desc+'skb byte lengths per second over the adaptive interval, including network headers; not payload or encrypted bytes.','Bps'),
        table(45,'Observer metrics targets · latest reachability',(12,105,12,8),f'max by(cluster,node) ({metric("up",OBSERVER,True)})',{'cluster':'Cluster','node':'Node','Value':'Scrape'},desc+'Latest scrape UP is reachability only. The two-worker observer qualification expects one selected worker per cluster; this is separate from the four-node fence profile.'),
    ])
    for p in dashboard['panels']:
        if p['id']==42:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Observation'},'properties':[{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'Unverified','color':ORANGE},'1':{'text':'Observation verified','color':BLUE}}}]}]})
    return dashboard

def build():
    return add_planned(add_observer(add_datapath(operations())),'operations',113)

def dashboards():
    return {'operations.json':build(),'workload-security.json':security()}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for name,d in dashboards().items():
        path=ROOT/'dashboards'/name;content=json.dumps(d,indent=2,ensure_ascii=False)+'\n'
        if args.check:assert path.read_text()==content,'Run python3 observability/build.py to refresh '+name
        else:path.write_text(content)
    if args.check:print('PASS both consolidated pages are reproducible; original nine definitions remain intact')

if __name__=='__main__':main()
