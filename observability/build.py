#!/usr/bin/env python3
"""Generate the two consolidated CMTC dashboards; --check verifies reproducibility."""
import argparse
import copy
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
DS={'type':'prometheus','uid':'${DS_PROMETHEUS}'}
BLUE,RED,YELLOW,PURPLE,GREEN,ORANGE='#4e79a7','#e15759','#edc948','#b07aa1','#59a14f','#f28e2b'
CLUSTERS={'cmtc-a':BLUE,'cmtc-b':RED}
DECISIONS={'selected':('Selected',BLUE),'excluded':('Excluded',RED),'platform':('Platform',YELLOW),'unselected':('Unselected',PURPLE)}
OPERATIONS_UID,SECURITY_UID='cmtc-observe-lab','cmtc-authenticated-only'
SEL='job="cmtc",cluster=~"$cluster"'
CONTROLLER=SEL+',component="cmtc-controller"'
AGENT=SEL+',component="cmtc-node-agent"'
OBSERVER=SEL+',component="cmtc-bpf-observer"'
FENCE=SEL+',component="cmtc-bpf-fence"'
ALL=SEL+',component=~"cmtc-controller|cmtc-node-agent"'
# Node ztunnel is scraped by each cluster's own Prometheus (scripts/lab/monitoring.py)
# and cmtc-b reaches cmtc-a through the existing remote-write path.
ZTUNNEL='job="ztunnel",cluster=~"$cluster",component="ztunnel"'
CILIUM='job="cilium-agent",cluster=~"$cluster",component="cilium-agent"'
DEST=ZTUNNEL+',reporter="destination",destination_workload_namespace=~"$namespace"'
SOURCE=ZTUNNEL+',reporter="source",destination_workload_namespace=~"$namespace"'
MTLS='connection_security_policy="mutual_tls"'
PLAIN='connection_security_policy!="mutual_tls"'
RANGE='[$__range] @ end()'
EMITTERS={'cmtc':ALL,'ztunnel':ZTUNNEL,'cilium':CILIUM}
# The five exclusive destination-reported outcomes of a completed TCP attempt,
# carried unchanged from the qualified examples/observability/ztunnel-spike source.
OUTCOMES=[
 ('mTLS · no failure flag',MTLS+',response_flags="-"',GREEN),
 ('Unauthenticated blocked',PLAIN+',response_flags="DENY"',ORANGE),
 ('Authenticated denied',MTLS+',response_flags="DENY"',YELLOW),
 ('Unverified · no failure flag',PLAIN+',response_flags="-"',RED),
 ('Other failures','response_flags!="-",response_flags!="DENY"',PURPLE),
]

def metric(name,labels=CONTROLLER,end=False):
    return f'{name}{{{labels}}}'+(' @ end()' if end else '')

def target(expr,legend='',ref='A',instant=True,table=False):
    t={'refId':ref,'expr':expr,'legendFormat':legend,'instant':instant,'range':not instant}
    if table:t['format']='table'
    return t

def color_override(name,color,matcher='byName',extra=None):
    return {'matcher':{'id':matcher,'options':('/'+name+'/' if matcher=='byRegexp' else name)},'properties':[{'id':'color','value':{'mode':'fixed','fixedColor':color}},*(extra or [])]}

DASHED={'id':'custom.lineStyle','value':{'fill':'dash','dash':[8,6]}}

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

def cluster_stat(i,title,pos,expr,description,decimals=0):
    """A latest/selected-range number per cluster, coloured by cluster identity."""
    p=stat(i,title,pos,expr,description,decimals=decimals)
    p['targets'][0]['legendFormat']='{{cluster}}'
    p['options']['textMode']='value_and_name'
    p['fieldConfig']['overrides']=[color_override(c,v) for c,v in CLUSTERS.items()]
    return p

def cluster_cell():
    return {'matcher':{'id':'byName','options':'Cluster'},'properties':[{'id':'custom.width','value':115},{'id':'custom.cellOptions','value':{'type':'color-background','mode':'basic'}},{'id':'mappings','value':[{'type':'value','options':{c:{'text':c,'color':v} for c,v in CLUSTERS.items()}}]}]}

def table(i,title,pos,expr,columns,description,extra=()):
    targets=[target(expr,table=True)]+[target(e,ref=chr(66+n),table=True) for n,e in enumerate(extra)]
    p=panel(i,title,'table',pos,description,targets)
    p['options']={'showHeader':True,'cellHeight':'sm','footer':{'show':False}}
    organize={'id':'organize','options':{'excludeByName':{'Time':True},'indexByName':{key:n for n,key in enumerate(columns)},'renameByName':columns}}
    p['transformations']=([{'id':'merge','options':{}}] if extra else [])+[organize]
    p['fieldConfig']['defaults']['decimals']=0
    p['fieldConfig']['overrides']=[cluster_cell()]
    return p

def series(i,title,pos,expr,description,unit,legend='{{cluster}}'):
    p=panel(i,title,'timeseries',pos,description,[target(expr,legend,instant=False)],unit)
    p['fieldConfig']['defaults']['custom']={'lineWidth':1,'fillOpacity':10,'drawStyle':'line','showPoints':'never'}
    p['fieldConfig']['overrides']=[color_override(c,v,extra=([DASHED] if c=='cmtc-b' else [])) for c,v in CLUSTERS.items()]
    p['options']={'legend':{'displayMode':'list','placement':'bottom','calcs':['lastNotNull']},'tooltip':{'mode':'multi','sort':'none'}}
    return p

def outcome_series(i,title,pos,expr,description,unit,legend,colors):
    """Lines coloured by a closed outcome set; cmtc-b lines are dashed so cluster stays readable."""
    p=series(i,title,pos,expr,description,unit,legend)
    p['fieldConfig']['overrides']=[color_override(regex,color,'byRegexp') for regex,color in colors]+[{'matcher':{'id':'byRegexp','options':'/^cmtc-b/'},'properties':[DASHED]}]
    return p

def up_mapping(column):
    return {'matcher':{'id':'byName','options':column},'properties':[{'id':'custom.cellOptions','value':{'type':'color-text'}},{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'DOWN','color':RED},'1':{'text':'UP','color':GREEN}}}]}]}

def cluster_variable():
    return {'name':'cluster','label':'Cluster','type':'query','datasource':DS,'query':{'query':'label_values(cmtc_enforcement_available{job="cmtc",component="cmtc-controller"},cluster)','refId':'ClusterVariable'},'refresh':1,'multi':True,'includeAll':True,'allValue':'.*','current':{'text':'All','value':'$__all'}}

def links():
    return [{'title':'CMTC | Operations','type':'link','url':f'/d/{OPERATIONS_UID}','keepTime':True,'includeVars':True,'icon':'dashboard','tooltip':'Intent, inventory, controllers and opt-in datapath prototypes'},
            {'title':'CMTC | Workload Security','type':'link','url':f'/d/{SECURITY_UID}','keepTime':True,'includeVars':True,'icon':'dashboard','tooltip':'Node ztunnel mTLS, authorization, trust and transport'}]

def dashboard(uid,title,tags,description,variables,panels):
    return {'uid':uid,'title':title,'description':description,'schemaVersion':41,'version':1,'editable':False,'tags':tags,'timezone':'utc','refresh':'5s','time':{'from':'now-15m','to':'now'},'links':links(),
       'templating':{'list':[{'name':'DS_PROMETHEUS','type':'datasource','query':'prometheus','current':{'text':'CMTC Prometheus','value':'cmtc-prom'}},*variables]},'annotations':{'list':[]},'panels':panels}

def operations():
    panels=[text(1,'CMTC operations · observed intent and inventory',(0,0,24,4),
       '**Observe mode:** namespace selection, existing enrollment labels, node inventory and controller activity are live. **Enforcement verification is unavailable.** These readings do not establish workload protection.\n\nUse the cluster selector for one cluster or both. Blue identifies cmtc-a; red identifies cmtc-b in charts and table cells. Workload mTLS, authorization, trust and transport evidence is on the linked **CMTC | Workload Security** page.'),
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
    errors=cluster_stat(15,'Controller reconcile errors · selected range',(12,29,12,4),f'sum by(cluster) (increase({metric("controller_runtime_reconcile_errors_total")}[$__range]))','Controller-runtime reconcile errors counted over the whole selected time range, per cluster. Prometheus extrapolates the increase, so a value can be fractional. An observed zero means no recorded errors in the range; a missing controller is unavailable, not zero.',decimals=1)
    errors['fieldConfig']['defaults']['thresholds']={'mode':'absolute','steps':[{'color':GREEN,'value':None},{'color':ORANGE,'value':1}]}
    panels.extend([pie,table(11,'Namespace decisions by cluster',(12,14,12,10),f'sum by(cluster,decision) ({metric("cmtc_namespace_decisions",end=True)})',{'cluster':'Cluster','decision':'Decision','Value':'Namespaces'},'Latest namespace decision gauges at range end, one row per cluster and decision. Zero is an observed empty category; a missing controller is not zero.'),
       text(12,'Read the namespace categories',(12,24,12,4),'**Selected** = policy intent. **Excluded** = explicit exclusion. **Platform** = protected infrastructure. **Unselected** = remaining namespaces.\n\nThe pie includes platform namespaces in its denominator. Non-platform inventory includes excluded namespaces. Enrollment labels are observed from any actor. None of these counts proves mTLS or Protected status.'),
       row(13,'Do controllers and node agents keep up?',28),
       stat(14,'Inventory/controller targets reachable',(0,29,12,4),f'sum({metric("up",ALL,True)})','Latest successful scrapes at range end. The two-cluster lab expects six inventory/controller targets: two controllers plus four node agents. Opt-in fence targets are shown separately below. Filtered views have fewer targets. Read the target table for individual failures; this count is not an all-healthy verdict.',BLUE),
       errors,
       series(16,'Policy evaluations/s · by cluster',(0,33,12,8),f'sum by(cluster) (rate({metric("cmtc_policy_evaluations_total")}[$__rate_interval]))','Successful CMTC policy evaluations per second over $__rate_interval. A fall to zero can mean idle work; it is not protection readiness. Missing metrics remain unavailable.','ops'),
       series(17,'Controller reconcile p95 · seconds',(12,33,12,8),f'histogram_quantile(0.95, sum by(cluster,le) (rate({metric("controller_runtime_reconcile_time_seconds_bucket")}[$__rate_interval])))','95th-percentile controller-runtime reconcile duration from real histogram buckets, over $__rate_interval. It measures controller work, not network or TLS latency. No observations mean the percentile is unavailable.','s'),
       table(18,'Pod inventory by node',(0,41,12,10),f'sum by(cluster,node,network) ({metric("cmtc_pods_observed",AGENT,True)})',{'cluster':'Cluster','node':'Node','network':'Network','Value':'Pods'},'Latest node-local pod inventory at range end. pod and host classify network mode. Counts are not protected pods or successful platform probes.'),
       table(19,'Inventory/controller targets · current state',(12,41,12,10),f'max by(cluster,component,node) ({metric("up",ALL,True)})',{'cluster':'Cluster','component':'Component','node':'Node','Value':'Scrape'},'Latest Prometheus target reachability at range end, with authoritative scrape cluster/component/node labels. UP does not establish workload or certificate readiness.'),
       text(20,'Inventory and controller telemetry boundaries',(0,51,24,3),'Rates use the adaptive scrape/zoom interval; counts use the whole selected range. Lines start at zero, with solid blue cmtc-a and dashed red cmtc-b. Tables show the latest observations at range end. **hostNetwork inventory is not platform safety.** API, DNS, probe health, certificate rotation and layered encryption still require their own verified instrumentation.'),
       row(21,'What is still awaiting security qualification?',54),
       text(22,'Implementation status · documented scope, not live health',(0,55,24,10),'| Capability domain | Where it is shown | Current evidence boundary |\n| --- | --- | --- |\n| Namespace intent / node inventory | This page, live | Observe is read-only; labels and inventory are intent, not protection |\n| Workload mTLS / native DENY | Workload Security, native ztunnel sections | Native panels fill only when node ztunnel runs in cmtc-a/cmtc-b; it is OFF in the combined profile |\n| Persistent admission / authorization | Workload Security and planned panels below | Mandatory capture, restore quarantine, effective policy and challenge-bound ACKs remain open |\n| CA trust / issuer / rotation | Workload Security trust section | The public issuer-profile producer is live and opt-in; consumption, rotation and cluster identity isolation remain open |\n| ClusterMesh / WireGuard / IPsec | Workload Security transport section | ClusterMesh reachability is tested; cross-cluster workload mTLS and layered transport are unqualified |\n| Kubernetes / OpenShift platform safety | Planned panels below | Platform namespace exclusion is implemented; required traffic/probe checks remain separate gates |\n\n**Missing security metrics are unknown.** No invented handshake, protected-pod, trust-ready or transport-success numbers are substituted. Planned panels keep every original domain visible until the owning story delivers its collector and real scrape evidence.'),
    ])
    for p in panels:
        if p['id']==11:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Decision'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-background','mode':'basic'}},{'id':'mappings','value':[{'type':'value','options':{key:{'text':label,'color':color} for key,(label,color) in DECISIONS.items()}}]}]})
        if p['id']==19:
            p['fieldConfig']['overrides'].append(up_mapping('Scrape'))
    return dashboard(OPERATIONS_UID,'CMTC | Operations',['cmtc','observe'],'Namespace intent, node inventory, controller activity and opt-in datapath prototypes. No panel on this page establishes Protected.',[cluster_variable()],panels)

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
  ('Which other security violations are observed? · planned',[
   ('Plaintext bypass incidents/s','cmtc_plaintext_bypass_detected_total'),
   ('Namespace policy conflicts/s','cmtc_namespace_policy_conflicts_total')]),
 ]}
# Existing live signals already answer these requirements; keep their original
# proposed names in the metric contract, without inventing duplicate exporters.
REPLACEMENTS={
 'cmtc_namespaces_excluded':('operations',10,'cmtc_namespace_decisions'),
 'cmtc_hostnetwork_pods_total':('operations',18,'cmtc_pods_observed'),
 'cmtc_reconcile_errors_total':('operations',15,'controller_runtime_reconcile_errors_total'),
 'cmtc_mtls_authorization_denials_total':('workload-mtls',21,'istio_tcp_connections_failed_total'),
}

def planned_expr(name,c):
    """Query a planned contract at its owning emitter, never through a CMTC aggregator."""
    family=c.get('family',name);labels=EMITTERS[c.get('emitter','cmtc')]+(','+c['matchers'] if c.get('matchers') else '')
    if c['kind']=='counter':
        by='cluster,result' if c.get('by_result') else 'cluster'
        return f'sum by({by}) (rate({family}{{{labels}}}[$__rate_interval]))'
    if c['kind']=='histogram':
        return f'histogram_quantile(0.95, sum by(cluster,le) (rate({family}_bucket{{{labels}}}[$__rate_interval])))'
    aggregate='min' if any(x in name for x in ['ready','healthy','probe_success']) else 'sum'
    if name=='cmtc_platform_dependency_healthy':return f'{family}{{{labels}}} @ end()'
    return f'{aggregate} by(cluster) ({family}{{{labels}}} @ end())'

def add_planned(dashboard,page,y,next_id=100):
    contract=json.loads((ROOT/'metrics.json').read_text())['metrics']
    for title,items in GROUPS[page]:
        dashboard['panels'].append(row(next_id,title,y));next_id+=1;y+=1
        for index,(label,name) in enumerate(items):
            c=contract[name];kind=c['kind'];height=7
            pos=((index%2)*12,y+(index//2)*height,12,height)
            owner=c.get('family',name)
            scope=('Collector implemented and source-tested; deployment and scrape qualification pending. Missing data is unavailable, never success. ' if c.get('source_status')=='implemented-and-source-tested' else 'Planned instrumentation; missing data means not implemented, never success. ')
            desc=scope+c['meaning']+' '+c['presentation']+' Owner: '+c['owner']+'.'+(' Expected emitted family: '+owner+(' {'+c['matchers']+'}' if c.get('matchers') else '')+'.' if owner!=name else '')+' Proposed labels/source must be qualified in the delivering story.'
            expr=planned_expr(name,c)
            if kind=='counter':
                if c.get('by_result'):
                    p=outcome_series(next_id,label+' · planned',pos,expr,desc,'ops','{{cluster}} · {{result}}',[('success$',GREEN),('peer_verification_failed$',RED),('protocol_error$',ORANGE),('timeout$',PURPLE)])
                else:p=series(next_id,label+' · planned',pos,expr,desc,'ops')
            elif kind=='histogram':
                p=series(next_id,label+' · planned',pos,expr,desc,'s')
            else:
                state=any(x in name for x in ['ready','healthy','probe_success'])
                p=cluster_stat(next_id,label+' · planned',pos,expr,desc)
                if name=='cmtc_platform_dependency_healthy':p['targets'][0]['legendFormat']='{{cluster}} · {{dependency}}'
                if state:p['fieldConfig']['defaults']['mappings']=[{'type':'value','options':{'0':{'text':'Not ready','color':ORANGE},'1':{'text':'Verified','color':GREEN}}}]
            # Metadata is for source validation; no synthetic values or fake exporter.
            p['description']+=' Metric contract: '+name
            dashboard['panels'].append(p);next_id+=1
        y+=((len(items)+1)//2)*7
    return dashboard

def guard(expr,denominator,match='',at=' @ end()'):
    """Return zero for an absent outcome only while its own denominator telemetry exists
    and no selected ztunnel target is DOWN. Missing telemetry stays unavailable."""
    return (f'({expr} or on({match}) (0 * {denominator})) and on() (count(up{{{ZTUNNEL}}}{at}) > 0)'
            f' unless on() (min(up{{{ZTUNNEL}}}{at}) == 0)')

def opened(labels):return f'sum(increase(istio_tcp_connections_opened_total{{{labels}}}{RANGE}))'
def closed(labels):return f'sum(increase(istio_tcp_connections_closed_total{{{labels}}}{RANGE}))'

def trust_domain(expr,label,source):
    return f'label_replace({expr}, "{label}", "$1", "{source}", "spiffe://([^/]+)/.*")'

def namespace_variable():
    return {'name':'namespace','label':'Destination namespace','type':'query','datasource':DS,'query':{'query':'label_values(istio_tcp_connections_opened_total{job="ztunnel",component="ztunnel"},destination_workload_namespace)','refId':'NamespaceVariable'},'refresh':2,'multi':True,'includeAll':True,'allValue':'.*','current':{'text':'All','value':'$__all'}}

def security():
    ztunnel_scope='Native node-ztunnel telemetry scraped from cmtc-a and cmtc-b (job ztunnel, /stats/prometheus on port 15020). Missing telemetry means ztunnel is not deployed, not scraped or not reporting; it is never zero or healthy. '
    dest_scope='Destination-reported only, so each observed connection counts once at the receiving node. Counts cover reporting targets; missing nodes or clusters make coverage incomplete. Read the coverage table and verify expected deployment inventory before treating these as full-cluster totals. '
    panels=[text(1,'CMTC workload security · node ztunnel mTLS, authorization and trust',(0,0,24,6),
       '**No application sidecars.** CMTC manages intent and trust, SPIRE issues credentials, Cilium owns discovery, capture, policy and xDS, and node ztunnel performs workload TLS and authorization. **Native sections fill only when node ztunnel runs in cmtc-a/cmtc-b; it is OFF in the current combined profile.** Empty native panels then mean *not deployed*, never zero or healthy.\n\n'
       '**Quantities stay separate:** TCP attempts, policy rejections, authenticated connections, TLS handshakes and HTTP requests are different things. The pie partitions one stated denominator. Cluster colours are blue cmtc-a and red cmtc-b; outcome colours are fixed. **No panel establishes Protected**: that needs mandatory capture, verified identity, effective policy and real traffic evidence together.\n\n'
       '**Start with telemetry coverage and the live issuer profile below.** Expand native diagnostics when ztunnel reports. Planned capabilities remain in collapsed sections until their owning story delivers real scrape evidence; missing data is never a healthy zero.'),
       row(2,'Is node ztunnel deployed and reporting?',6)]
    # A reporting count is not a protection metric. Zero below means no discovered
    # scrape target for a cluster whose CMTC controller is actually reporting.
    anchor=f'group by(cluster) ({metric("cmtc_enforcement_available",CONTROLLER,True)})'
    discovered=f'(count by(cluster) (up{{{ZTUNNEL}}} @ end())) or on(cluster) (0 * {anchor})'
    reachable=f'(sum by(cluster) (up{{{ZTUNNEL}}} @ end())) or on(cluster) (0 * {anchor})'
    t=table(3,'ztunnel telemetry coverage · latest by cluster',(0,7,24,8),discovered,{'cluster':'Cluster','Value #A':'Discovered targets','Value #B':'Scrapes UP'},
        ztunnel_scope+'Counts only discovered metrics targets and their successful scrapes. Zero means none discovered/reporting, not zero connections, healthy TLS or protection. Rows exist only for clusters with reporting CMTC controllers. Expected node coverage is a separate deployment gate; one UP target cannot qualify the cluster.',extra=[reachable])
    for column in ('Discovered targets','Scrapes UP'):
        t['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':column},'properties':[{'id':'custom.cellOptions','value':{'type':'color-text'}},{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'None reporting','color':ORANGE}}}]}]})
    panels.append(t)
    panels.append(row(28,'Native proxy lifecycle · expand for node detail',15))
    panels.append(table(4,'Workloads managed by ztunnel · latest by node',(0,16,24,8),f'max by(cluster,node) (workload_manager_active_proxy_count{{{ZTUNNEL}}} @ end())',{'cluster':'Cluster','node':'Node','Value #A':'Active','Value #B':'Pending'},ztunnel_scope+'Latest in-pod proxy counts from the ZDS workload manager at range end. Active means ztunnel holds a proxy for the pod network namespace; it does not prove mandatory capture, enrollment or an issued certificate. Pending is waiting for a ZDS snapshot.',extra=[f'max by(cluster,node) (workload_manager_pending_proxy_count{{{ZTUNNEL}}} @ end())']))
    panels.append(series(5,'xDS stream terminations/s · by cluster',(0,24,24,7),f'sum by(cluster) (rate(istio_xds_connection_terminations_total{{{ZTUNNEL}}}[$__rate_interval]))',ztunnel_scope+'Ended ztunnel ADS streams per second over $__rate_interval, every reason combined. A steady zero is a stable stream. A burst follows agent restart, reconnect or a rejected update. It does not show ACK freshness or which policy version is applied.','ops'))
    panels.append(row(6,'Which TCP connections were authenticated, rejected or unverified? · destination-reported',22))
    for i,x,title,expr,desc in [
        (7,0,'mTLS TCP connections opened · selected range',f'sum by(cluster) (increase(istio_tcp_connections_opened_total{{{DEST},{MTLS}}}{RANGE}))','TCP opens after peer TLS authentication, labelled mutual_tls; authorization can still reject them. Not HTTP requests or TLS handshakes.'),
        (8,8,'TCP opens without verified mTLS · selected range',f'sum by(cluster) (increase(istio_tcp_connections_opened_total{{{DEST},{PLAIN}}}{RANGE}))','TCP opens at the destination without a verified peer principal, including attempts that policy then rejects. Not accepted plaintext.'),
        (9,16,'Connections rejected by policy (DENY) · selected range',f'sum by(cluster) (increase(istio_tcp_connections_failed_total{{{DEST},response_flags="DENY"}}{RANGE}))','Failed TCP connections with response flag DENY, authenticated or not. This overlaps both open counters: never add the three numbers.')]:
        panels.append(cluster_stat(i,title,(x,23,8,5),expr,ztunnel_scope+dest_scope+desc+' Prometheus extrapolates the selected-range increase, so values can be fractional. No series for a cluster means no observation of that kind there.',decimals=1))
    pie=panel(10,'Completed TCP attempts · share by outcome','piechart',(0,28,12,14),
       ztunnel_scope+dest_scope+'Denominator: destination-reported completed TCP attempts in the selected clusters, namespaces and time range, from increase(istio_tcp_connections_closed_total[$__range]) at range end. The five outcomes are disjoint and exhaust it. No failure flag is not HTTP success. A missing outcome reads zero only while the denominator exists and no selected ztunnel target is DOWN. Zero completed attempts has no meaningful share.',
       [target(guard(closed(DEST+','+sel),closed(DEST)),label,chr(65+n)) for n,(label,sel,_) in enumerate(OUTCOMES)])
    pie['fieldConfig']['defaults'].update(decimals=1)
    pie['fieldConfig']['overrides']=[color_override(label,color) for label,_,color in OUTCOMES]
    pie['options']={'pieType':'pie','displayLabels':['percent'],'reduceOptions':{'calcs':['lastNotNull'],'fields':'','values':False},'legend':{'displayMode':'table','placement':'bottom','values':['value','percent']},'tooltip':{'mode':'single','sort':'desc'}}
    panels.append(pie)
    outcomes=table(11,'Completed TCP attempts by cluster and outcome · selected range',(12,28,12,10),f'sum by(cluster,connection_security_policy,response_flags) (increase(istio_tcp_connections_closed_total{{{DEST}}}{RANGE}))',{'cluster':'Cluster','connection_security_policy':'Peer security','response_flags':'Response flag','Value':'Completed attempts'},ztunnel_scope+dest_scope+'The numbers behind the pie, per cluster. Response flag - means no failure flag; DENY is a policy rejection; other flags are transport or identity failures. Values are extrapolated selected-range increases.')
    outcomes['fieldConfig']['defaults']['decimals']=1;panels.append(outcomes)
    panels.append(text(12,'Read connection counts and shares',(12,38,12,4),'**Opens** count TCP starts; **DENY** counts policy rejections and overlaps opens; the **pie** counts completed attempts. Destination-only reporting avoids counting both ends of one connection. In-flight connections are outside the pie. **mutual_tls** means ztunnel verified a peer certificate chain; the principal is from that certificate, not from a label.'))
    panels.append(row(13,'Does authenticated traffic flow in both directions between clusters?',42))
    pair_colors=[('← cmtc-a\\.',BLUE),('← cmtc-b\\.',RED),('→ cmtc-a\\.',BLUE),('→ cmtc-b\\.',RED)]
    panels.append(outcome_series(14,'mTLS TCP opens/s · destination cluster ← source trust domain',(0,43,12,8),
       f'sum by(cluster,source_trust_domain) ({trust_domain(f"rate(istio_tcp_connections_opened_total{{{DEST},{MTLS}}}[$__rate_interval])","source_trust_domain","source_principal")})',
       ztunnel_scope+dest_scope+'Authenticated TCP opens per second over $__rate_interval, split by the receiving cluster and the trust domain in the verified source certificate. cmtc-a ← cmtc-b.* is B-to-A traffic; cmtc-b ← cmtc-a.* is A-to-B. Line colour is the source domain; dashed lines are received in cmtc-b. A trust-domain string is verified here only because ztunnel checked the chain; it is not cluster binding by itself.',
       'ops','{{cluster}} ← {{source_trust_domain}}',pair_colors))
    panels.append(outcome_series(15,'mTLS payload bytes/s · source cluster → destination trust domain',(12,43,12,8),
       f'sum by(cluster,destination_trust_domain) ({trust_domain(f"rate(istio_tcp_sent_bytes_total{{{SOURCE},{MTLS}}}[$__rate_interval]) + rate(istio_tcp_received_bytes_total{{{SOURCE},{MTLS}}}[$__rate_interval])","destination_trust_domain","destination_principal")})',
       ztunnel_scope+'Source-reported application bytes sent plus received inside authenticated connections, per second over $__rate_interval. Source-only reporting avoids counting both ends. These are payload bytes, not packets or TLS overhead, and not proof that WireGuard or IPsec also protected them.',
       'Bps','{{cluster}} → {{destination_trust_domain}}',pair_colors))
    pair=table(16,'Cluster-pair mTLS connections · selected range',(0,51,24,7),f'sum by(cluster,source_trust_domain) ({trust_domain(f"increase(istio_tcp_connections_opened_total{{{DEST},{MTLS}}}{RANGE})","source_trust_domain","source_principal")})',{'cluster':'Destination cluster','source_trust_domain':'Source trust domain','Value':'mTLS TCP opens'},ztunnel_scope+dest_scope+'Selected-range authenticated TCP opens for each receiving cluster and verified source trust domain. Bidirectional acceptance needs both cmtc-a ← cmtc-b.* and cmtc-b ← cmtc-a.* rows from real application traffic, plus the separate negative and packet evidence. Values are extrapolated increases.')
    pair['fieldConfig']['defaults']['decimals']=1
    pair['fieldConfig']['overrides']=[{**cluster_cell(),'matcher':{'id':'byName','options':'Destination cluster'}}]
    panels.append(pair)
    panels.append(row(17,'Which peers and verdicts did ztunnel record? · drilldown',58))
    drill=table(18,'TCP close verdicts and verified peer identities · selected range',(0,59,24,8),f'sum by(cluster,node,reporter,source_principal,destination_principal,connection_security_policy,response_flags) (increase(istio_tcp_connections_closed_total{{{ZTUNNEL},destination_workload_namespace=~"$namespace"}}{RANGE}) > 0)',
       {'cluster':'Cluster','node':'Node','reporter':'Reporter','source_principal':'Source principal','destination_principal':'Destination principal','connection_security_policy':'Peer security','response_flags':'Response flag','Value':'Closed connections'},
       ztunnel_scope+'Selected-range closed connections per reporting node, verdict and principal pair; rows with no closes in the range are hidden. Source and destination reporters describe the same connection from both ends, so do not add rows across reporters. Principals of unauthenticated peers show as unknown.')
    drill['fieldConfig']['defaults']['decimals']=1;panels.append(drill)
    panels.append(row(19,'Which security violations are observed?',67))
    panels.append(series(21,'Connections rejected by policy/s · ztunnel DENY',(0,68,12,7),
       guard(f'sum by(cluster) (rate(istio_tcp_connections_failed_total{{{DEST},response_flags="DENY"}}[$__rate_interval]))',f'sum by(cluster) (rate(istio_tcp_connections_opened_total{{{DEST}}}[$__rate_interval]))','cluster',''),
       ztunnel_scope+dest_scope+'Destination authorization rejections per second over $__rate_interval: the native owner of the original Authorization denials contract. Zero is shown only while the same cluster reports TCP opens; otherwise the panel is empty. A rejection is a working control, not a bypass.','ops'))
    panels.append(text(22,'Read violation signals',(12,68,12,7),'**DENY** counts connections that ztunnel authorization rejected at the destination. A rejected plaintext attempt is a working control, **not** a bypass. A plaintext bypass needs an independent verifier that sees unauthorized plaintext reach a destination that requires mTLS; that collector is planned below. Identity and certificate failures are separate from policy rejections.'))
    panels.append(row(23,'Is the public issuer profile current? · opt-in producer',75))
    producer='Optional CMTC public issuer-profile producer in the controller (component cmtc-controller); absent when the opt-in is disabled. It publishes the approved public issuer profile; it does not prove that ztunnel consumed it, that a handshake used it or that traffic is protected. '
    prod=table(24,'Issuer-profile producer · latest by cluster',(0,76,12,8),f'(time() - max by(cluster) ({metric("cmtc_issuer_profile_source_checked_timestamp_seconds",CONTROLLER,True)})) and on(cluster) (max by(cluster) ({metric("cmtc_issuer_profile_source_checked_timestamp_seconds",CONTROLLER,True)}) > 0)',{'cluster':'Cluster','Value #A':'Source read age (s)','Value #B':'Lease remaining (s)'},producer+'Source read age: seconds since the last successful uncached source read, valid or not; empty before the first read. Lease remaining: seconds until this process\'s last acknowledged publication lease expires; leases are at most 30 s. An empty lease cell means no acknowledged lease (process start or acknowledged withdrawal). A negative value is an expired lease.',
       extra=[f'(max by(cluster) ({metric("cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds",CONTROLLER,True)}) - time()) and on(cluster) (max by(cluster) ({metric("cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds",CONTROLLER,True)}) > 0)'])
    prod['fieldConfig']['defaults'].update(decimals=1,unit='s');del prod['fieldConfig']['defaults']['min']
    prod['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Lease remaining (s)'},'properties':[{'id':'custom.cellOptions','value':{'type':'color-text'}},{'id':'thresholds','value':{'mode':'absolute','steps':[{'color':RED,'value':None},{'color':ORANGE,'value':0},{'color':GREEN,'value':5}]}}]})
    panels.append(prod)
    panels.append(outcome_series(25,'Issuer-profile validation attempts/s · by result',(12,76,12,8),f'sum by(cluster,result) (rate({metric("cmtc_issuer_profile_validation_attempts_total",CONTROLLER)}[$__rate_interval]))',producer+'Producer passes per second over $__rate_interval, by closed result accepted/rejected/unavailable. Retries count as attempts, not distinct incidents. Process restart resets the counter.','ops','{{cluster}} · {{result}}',[('accepted$',GREEN),('rejected$',RED),('unavailable$',ORANGE)]))
    panels.append(outcome_series(26,'Issuer-profile publication writes/s · by state and result',(0,84,12,8),f'sum by(cluster,state,result) (rate({metric("cmtc_issuer_profile_publication_writes_total",CONTROLLER)}[$__rate_interval]))',producer+'Output API Update responses per second over $__rate_interval. An unchanged pass writes nothing, so idle reads zero. A lost response can count error even when the server committed; this is not an exact publication count.','ops','{{cluster}} · {{state}} · {{result}}',[('published · acknowledged$',GREEN),('withdrawn · acknowledged$',BLUE),('· error$',RED)]))
    panels.append(text(27,'Read issuer-profile signals',(12,84,12,8),'The chain is organization root → explicitly approved cluster intermediate → exact SPIRE signer → workload SVID. The producer publishes only public material with short leases. **Fresh reads and acknowledged leases show publication, not consumption.** Trust-bundle consumption, SPIRE acknowledgment, issuer verification and rotation are separate planned contracts below. A withdrawal tombstone denies availability; it is not certificate revocation.'))
    d=dashboard(SECURITY_UID,'CMTC | Workload Security',['cmtc','mtls','ztunnel'],'Node ztunnel workload mTLS, authorization, cross-cluster traffic, issuer profile and planned trust/transport signals. TCP starts are not TLS handshakes; no panel establishes Protected.',[cluster_variable(),namespace_variable()],panels)
    return compact_layout(add_planned(d,'workload-mtls',92),security_page=True)

def add_datapath(dashboard):
    desc='Explicit deny-only disposable-veth prototype. Packets are not requests, connections or TLS handshakes. Missing telemetry remains unavailable; quarantine verification is not Protected or mTLS. '
    dashboard['panels'].extend([
        row(30,'Audited datapath quarantine · opt-in lab only',65),
        text(31,'Packet counters and quarantine scope',(0,66,24,4),'**One audited workload veth/hook per selected node.** These panels observe the opt-in deny-only DaemonSet, not whole-node traffic or workload mTLS. Packet retransmissions count; counters are not HTTP request totals. **No mTLS or Protected claim.**\n\nA fresh verified sample permits counters to be exported; stale/unverified samples omit counters and report verification 0. Missing exporter/scrape is unavailable. Exact pinned-map adoption retains counters; a newly installed map resets them. There is no meaningful success-percentage pie from these counters.'),
        table(32,'Audited quarantine · latest by node',(0,70,12,8),f'min by(cluster,node,direction) ({metric("cmtc_datapath_fence_quarantine_verified",FENCE,True)}) and on(cluster,node) ({metric("up",FENCE,True)} == 1)',{'cluster':'Cluster','node':'Node','direction':'Hook','Value':'Quarantine'},desc+'Latest 0/1 sample at range end, filtered to reachable scrapes. Do not sum away individual failed or missing nodes.'),
        series(33,'Packets rejected by audited quarantine/s',(12,70,12,8),f'sum by(cluster) (rate({metric("cmtc_datapath_fence_dropped_packets_total",FENCE)}[$__rate_interval]))',desc+'Rate of actual TCX DROP packets over the adaptive scrape interval; an idle verified hook can report zero.','pps'),
        cluster_stat(34,'Quarantine rejected packets · selected range',(0,78,12,6),f'sum by(cluster) (increase({metric("cmtc_datapath_fence_dropped_packets_total",FENCE)}[$__range]))',desc+'Prometheus extrapolated selected-range packet increase; retransmits count. This is not an exact application-attempt ledger.',decimals=1),
        series(35,'skb bytes rejected by quarantine/s',(12,78,12,6),f'sum by(cluster) (rate({metric("cmtc_datapath_fence_dropped_bytes_total",FENCE)}[$__rate_interval]))',desc+'skb byte lengths per second, including network headers; not payload or encrypted bytes.','Bps'),
        table(36,'Fence metrics targets · latest reachability',(0,84,24,8),f'max by(cluster,node) ({metric("up",FENCE,True)})',{'cluster':'Cluster','node':'Node','Value':'Scrape'},desc+'UP means only scrape reachable. Missing expected nodes must be checked against the explicit selected-node ledger; this table cannot invent a missing target.'),
    ])
    for p in dashboard['panels']:
        if p['id']==32:
            p['fieldConfig']['overrides'].append({'matcher':{'id':'byName','options':'Quarantine'},'properties':[{'id':'mappings','value':[{'type':'value','options':{'0':{'text':'Unverified','color':ORANGE},'1':{'text':'Quarantine verified','color':BLUE}}}]}]})
        if p['id']==36:p['fieldConfig']['overrides'].append(up_mapping('Scrape'))
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
        if p['id']==45:p['fieldConfig']['overrides'].append(up_mapping('Scrape'))
    return dashboard

def all_panels(dashboard):
    """Yield every source panel, including collapsed future/optional sections."""
    def visit(panels):
        for item in panels:
            yield item
            yield from visit(item.get('panels',[]))
    return visit(dashboard['panels'])

def compact_layout(dashboard,security_page=False):
    """Keep current evidence first without deleting future capability panels.

    Native diagnostics remain expandable while the combined profile is off.
    Collapse state is presentation only; it never changes query validation.
    """
    prefix=[];groups=[]
    for item in dashboard['panels']:
        if item['type']=='row':groups.append([item])
        elif groups:groups[-1].append(item)
        else:prefix.append(item)
    if security_page:
        # Coverage and the current public producer have useful data before the
        # native combined profile is qualified. Do not lead with blank charts.
        groups.sort(key=lambda group:0 if group[0]['id']==2 else 1 if group[0]['id']==23 else 2)
    cursor=max((p['gridPos']['y']+p['gridPos']['h'] for p in prefix),default=0)
    result=list(prefix)
    for group in groups:
        heading,*children=group;old_y=heading['gridPos']['y']
        height=max([1]+[p['gridPos']['y']-old_y+p['gridPos']['h'] for p in children])
        collapsed=('· planned' in heading['title'] or heading['id'] in (30,40) or
                   (security_page and heading['id'] not in (2,23)))
        heading['gridPos']['y']=cursor
        for child in children:child['gridPos']['y']+=cursor-old_y
        heading['collapsed']=collapsed
        heading['panels']=children if collapsed else []
        result.append(heading)
        if not collapsed:result.extend(children)
        cursor+=1 if collapsed else height
    dashboard['panels']=result
    return dashboard

def build():
    return compact_layout(add_planned(add_observer(add_datapath(operations())),'operations',113))

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
