#!/usr/bin/env python3
"""Small disposable monitoring fixture with two consolidated dashboards preserving all nine domains."""
import json
from pathlib import Path
import sys

ZTUNNEL_FAMILIES='istio_tcp_connections_(opened|closed|failed)_total|istio_tcp_(sent|received)_bytes_total|istio_xds_connection_terminations_total|istio_tls_handshakes_total|istio_tls_handshake_duration_seconds_(bucket|sum|count)|workload_manager_(active|pending)_proxy_count|istio_build'
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
    {'target_label':'cluster','replacement':cluster},
    {'source_labels':['__meta_kubernetes_pod_label_app_kubernetes_io_name'],'target_label':'component'},
    {'source_labels':['__meta_kubernetes_pod_node_name'],'target_label':'node'},
]},
# Node ztunnel (Cilium chart DaemonSet ztunnel-cilium) is hostNetwork and declares no
# container port; its stats listener binds the wildcard address on 15020. The job finds
# no target while ztunnel is disabled, so missing data stays unavailable.
{'job_name':'ztunnel','metrics_path':'/stats/prometheus','kubernetes_sd_configs':[{'role':'pod','namespaces':{'names':['kube-system']}}],'relabel_configs':[
    {'source_labels':['__meta_kubernetes_pod_label_app_kubernetes_io_name'],'action':'keep','regex':'ztunnel-cilium'},
    {'source_labels':['__meta_kubernetes_pod_container_name','__meta_kubernetes_pod_container_init'],'action':'keep','regex':'istio-proxy;false'},
    {'source_labels':['__meta_kubernetes_pod_phase'],'action':'keep','regex':'Running'},
    {'source_labels':['__meta_kubernetes_pod_ip'],'target_label':'__address__','regex':'(.+)','replacement':'$1:15020'},
    {'target_label':'cluster','replacement':cluster},
    {'target_label':'component','replacement':'ztunnel'},
    {'source_labels':['__meta_kubernetes_pod_node_name'],'target_label':'node'},
],'metric_relabel_configs':[
    # Keep only the families the dashboards and rules query; drop the per-locality labels.
    {'source_labels':['__name__'],'action':'keep','regex':ZTUNNEL_FAMILIES},
    {'action':'labeldrop','regex':'(source|destination)_(region|zone)'},
]},
# Hubble metrics (hubble_*) on every agent's hubble-metrics port (config/lab/cilium/base.yaml, hubble.metrics.port 9965).
{'job_name':'hubble','kubernetes_sd_configs':[{'role':'pod','namespaces':{'names':['kube-system']}}],'relabel_configs':[
    {'source_labels':['__meta_kubernetes_pod_label_k8s_app'],'action':'keep','regex':'cilium'},
    {'source_labels':['__meta_kubernetes_pod_container_port_name'],'action':'keep','regex':'hubble-metrics'},
    {'target_label':'cluster','replacement':cluster},
    {'target_label':'component','replacement':'hubble'},
    {'source_labels':['__meta_kubernetes_pod_node_name'],'target_label':'node'},
]},
# Hubble Relay metrics (hubble_relay_*) on its prometheus port (9966); the Relay runs in the control cluster only, so
# the job finds no target elsewhere.
{'job_name':'hubble-relay','kubernetes_sd_configs':[{'role':'pod','namespaces':{'names':['kube-system']}}],'relabel_configs':[
    {'source_labels':['__meta_kubernetes_pod_label_k8s_app'],'action':'keep','regex':'hubble-relay'},
    {'source_labels':['__meta_kubernetes_pod_container_port_name'],'action':'keep','regex':'prometheus'},
    {'target_label':'cluster','replacement':cluster},
    {'target_label':'component','replacement':'hubble-relay'},
    {'source_labels':['__meta_kubernetes_pod_node_name'],'target_label':'node'},
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
    for name in ['operations.json','workload-security.json']:
        p=Path('observability/dashboards')/name
        d=json.loads(p.read_text())
        dashboards[p.name]=json.dumps(d)
    add('v1','ConfigMap','cmtc-dashboards',{'data':dashboards})
    add('v1','ConfigMap','grafana-datasources',{'data':{'datasources.yaml':json.dumps({'apiVersion':1,'datasources':[{'name':'CMTC Prometheus','uid':'cmtc-prom','type':'prometheus','access':'proxy','url':'http://prometheus:9090','isDefault':True}]})}})
    add('v1','ConfigMap','grafana-providers',{'data':{'providers.yaml':json.dumps({'apiVersion':1,'providers':[{'name':'cmtc','folder':'CMTC','type':'file','updateIntervalSeconds':30,'options':{'path':'/var/lib/grafana/dashboards'}}]})}})
    deploy('grafana','grafana/grafana:12.2.0',[],[3000],
        [{'name':'datasources','mountPath':'/etc/grafana/provisioning/datasources'},{'name':'providers','mountPath':'/etc/grafana/provisioning/dashboards'},{'name':'dashboards','mountPath':'/var/lib/grafana/dashboards'},{'name':'data','mountPath':'/var/lib/grafana'}],
        [{'name':'datasources','configMap':{'name':'grafana-datasources'}},{'name':'providers','configMap':{'name':'grafana-providers'}},{'name':'dashboards','configMap':{'name':'cmtc-dashboards'}},{'name':'data','emptyDir':{}}],
        env={'GF_SECURITY_ADMIN_PASSWORD':'cmtc-disposable-lab','GF_AUTH_ANONYMOUS_ENABLED':'true','GF_AUTH_ANONYMOUS_ORG_ROLE':'Viewer','GF_ANALYTICS_REPORTING_ENABLED':'false','GF_ANALYTICS_CHECK_FOR_UPDATES':'false'})
    add('v1','Service','grafana',{'spec':{'selector':{'app':'grafana'},'ports':[{'port':3000,'targetPort':3000}]}})
print(json.dumps({'apiVersion':'v1','kind':'List','items':items}))
