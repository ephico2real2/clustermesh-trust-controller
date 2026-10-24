#!/usr/bin/env python3
"""Small disposable monitoring fixture; serves both actual telemetry and clearly marked proposal dashboards."""
import json
from pathlib import Path
import sys

cluster,hub=sys.argv[1:]
items=[]
def add(api,kind,name,body=None,namespace='monitoring'):
    o={'apiVersion':api,'kind':kind,'metadata':{'name':name}}
    if namespace:o['metadata']['namespace']=namespace
    if body:o.update(body)
    items.append(o)

add('v1','Namespace','monitoring',namespace=None)
add('v1','ServiceAccount','prometheus')
add('rbac.authorization.k8s.io/v1','ClusterRole','cmtc-lab-prometheus',{'rules':[{'apiGroups':[''],'resources':['pods'],'verbs':['get','list','watch']}]},namespace=None)
add('rbac.authorization.k8s.io/v1','ClusterRoleBinding','cmtc-lab-prometheus',{'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'cmtc-lab-prometheus'},'subjects':[{'kind':'ServiceAccount','name':'prometheus','namespace':'monitoring'}]},namespace=None)
prom={'global':{'scrape_interval':'5s','external_labels':{'cluster':cluster}},'scrape_configs':[{'job_name':'cmtc','kubernetes_sd_configs':[{'role':'pod'}],'relabel_configs':[
    {'source_labels':['__meta_kubernetes_pod_label_security_cmtc_io_metrics'],'action':'keep','regex':'true'},
    {'source_labels':['__meta_kubernetes_pod_container_port_name'],'action':'keep','regex':'metrics'},
]}]}
if cluster=='cmtc-b':prom['remote_write']=[{'url':f'http://{hub}:30900/api/v1/write'}]
add('v1','ConfigMap','prometheus',{'data':{'prometheus.yml':json.dumps(prom)}})

def deploy(name,image,args,ports,mounts,volumes,env=None,sa=None):
    container={'name':name,'image':image,'args':args,'ports':[{'containerPort':p} for p in ports],'volumeMounts':mounts,'resources':{'requests':{'cpu':'25m','memory':'64Mi'},'limits':{'memory':'512Mi'}},'readinessProbe':{'httpGet':{'path':'/-/ready' if name=='prometheus' else '/api/health','port':ports[0]}}}
    if env:container['env']=[{'name':k,'value':v} for k,v in env.items()]
    spec={'containers':[container],'volumes':volumes}
    if sa:spec['serviceAccountName']=sa
    add('apps/v1','Deployment',name,{'spec':{'replicas':1,'selector':{'matchLabels':{'app':name}},'template':{'metadata':{'labels':{'app':name}},'spec':spec}}})

deploy('prometheus','prom/prometheus:v3.7.0',['--config.file=/etc/prometheus/prometheus.yml','--storage.tsdb.retention.time=1h','--web.enable-remote-write-receiver'],[9090],[{'name':'config','mountPath':'/etc/prometheus'},{'name':'data','mountPath':'/prometheus'}],[{'name':'config','configMap':{'name':'prometheus'}},{'name':'data','emptyDir':{}}],sa='prometheus')
add('v1','Service','prometheus',{'spec':{'type':'NodePort','selector':{'app':'prometheus'},'ports':[{'port':9090,'targetPort':9090,'nodePort':30900}]}})
if cluster=='cmtc-a':
    dashboards={}
    for p in Path('observability/dashboards').glob('*.json'):
        d=json.loads(p.read_text())
        d['description']='Experimental Observe lab. Selection/inventory metrics are real. Workload mTLS, trust lifecycle and transport composition are unimplemented; their missing data is unknown.'
        dashboards[p.name]=json.dumps(d)
    panels=[]
    for title,expr in [
        ('Selected namespaces — intent only','sum by (cluster) (cmtc_namespaces_selected)'),
        ('Node agents reporting inventory','sum by (cluster) (cmtc_node_agent_ready)'),
        ('Workload enforcement available — 0 means unavailable','max by (cluster) (cmtc_enforcement_available)'),
        ('Namespace decisions','sum by (cluster, decision) (cmtc_namespace_decisions)'),
        ('Pod inventory — not protection','sum by (cluster, network) (cmtc_pods_observed)'),
        ('Observed enrollment labels — not protection','sum by (cluster) (cmtc_namespaces_enrolled)'),
    ]:
        n=len(panels)
        panels.append({'id':n+1,'title':title,'type':'timeseries','datasource':{'type':'prometheus','uid':'cmtc-prom'},'gridPos':{'x':(n%2)*12,'y':(n//2)*8,'w':12,'h':8},'targets':[{'refId':'A','expr':expr,'legendFormat':'{{cluster}} {{decision}} {{network}}'}]})
    dashboards['00-observe-lab.json']=json.dumps({'uid':'cmtc-observe-lab','title':'CMTC | Deployed Observe Lab','schemaVersion':39,'version':1,'description':'Real controllers and inventory in two clusters. Workload mTLS / required transport verification is unavailable.','time':{'from':'now-15m','to':'now'},'refresh':'5s','panels':panels})
    add('v1','ConfigMap','cmtc-dashboards',{'data':dashboards})
    add('v1','ConfigMap','grafana-datasources',{'data':{'datasources.yaml':json.dumps({'apiVersion':1,'datasources':[{'name':'CMTC Prometheus','uid':'cmtc-prom','type':'prometheus','access':'proxy','url':'http://prometheus:9090','isDefault':True}]})}})
    add('v1','ConfigMap','grafana-providers',{'data':{'providers.yaml':json.dumps({'apiVersion':1,'providers':[{'name':'cmtc','folder':'CMTC','type':'file','updateIntervalSeconds':30,'options':{'path':'/var/lib/grafana/dashboards'}}]})}})
    deploy('grafana','grafana/grafana:12.2.0',[],[3000],
        [{'name':'datasources','mountPath':'/etc/grafana/provisioning/datasources'},{'name':'providers','mountPath':'/etc/grafana/provisioning/dashboards'},{'name':'dashboards','mountPath':'/var/lib/grafana/dashboards'},{'name':'data','mountPath':'/var/lib/grafana'}],
        [{'name':'datasources','configMap':{'name':'grafana-datasources'}},{'name':'providers','configMap':{'name':'grafana-providers'}},{'name':'dashboards','configMap':{'name':'cmtc-dashboards'}},{'name':'data','emptyDir':{}}],
        env={'GF_SECURITY_ADMIN_PASSWORD':'cmtc-disposable-lab','GF_AUTH_ANONYMOUS_ENABLED':'true','GF_AUTH_ANONYMOUS_ORG_ROLE':'Viewer','GF_ANALYTICS_REPORTING_ENABLED':'false','GF_ANALYTICS_CHECK_FOR_UPDATES':'false'})
    add('v1','Service','grafana',{'spec':{'selector':{'app':'grafana'},'ports':[{'port':3000,'targetPort':3000}]}})
print(json.dumps({'apiVersion':'v1','kind':'List','items':items}))
