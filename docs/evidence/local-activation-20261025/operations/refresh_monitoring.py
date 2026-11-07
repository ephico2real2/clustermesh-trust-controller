import subprocess,json,sys,hashlib
from pathlib import Path
c=sys.argv[1];assert c in ['cmtc-a','cmtc-b'];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c];O=Path('/private/tmp/cmtc-primary-operations-20261025')/('monitoring-'+c);O.mkdir(exist_ok=True)
obj=json.loads(subprocess.check_output(K+['-n','monitoring','get','cm','prometheus','-o','json']));old=obj['data']['prometheus.yml'];prom=json.loads(old)
(O/'prometheus-before.json').write_text(json.dumps(obj,indent=2)+'\n')
job={'job_name':'cilium-native','kubernetes_sd_configs':[{'role':'pod','namespaces':{'names':['kube-system']}}],'relabel_configs':[{'source_labels':['__meta_kubernetes_pod_label_k8s_app'],'action':'keep','regex':'cilium'},{'source_labels':['__meta_kubernetes_pod_container_name'],'action':'keep','regex':'cilium-agent'},{'source_labels':['__meta_kubernetes_pod_container_port_name'],'action':'keep','regex':'prometheus'},{'source_labels':['__meta_kubernetes_pod_phase'],'action':'keep','regex':'Running'},{'source_labels':['__meta_kubernetes_pod_ip'],'target_label':'__address__','regex':'(.+)','replacement':'$1:9962'},{'target_label':'cluster','replacement':c},{'target_label':'component','replacement':'cilium'},{'source_labels':['__meta_kubernetes_pod_node_name'],'target_label':'node'}],'metric_relabel_configs':[{'source_labels':['__name__'],'action':'keep','regex':'cilium_ztunnel_.*|cmtc_.*'}]}
prom['scrape_configs']=[j for j in prom['scrape_configs'] if j['job_name']!='cilium-native']+[job]
body=json.dumps(prom);patch={'metadata':{'uid':obj['metadata']['uid'],'resourceVersion':obj['metadata']['resourceVersion']},'data':{'prometheus.yml':body}}
p=O/'prometheus-patch.json';p.write_text(json.dumps(patch)+'\n')
subprocess.run(K+['-n','monitoring','patch','cm','prometheus','--type=merge','--patch-file',str(p)],check=True)
(O/'expected-config-sha256').write_text(hashlib.sha256(body.encode()).hexdigest()+'\n')
if c=='cmtc-a':
 d=json.loads(subprocess.check_output(K+['-n','monitoring','get','cm','cmtc-dashboards','-o','json']));(O/'dashboards-before.json').write_text(json.dumps(d,indent=2)+'\n')
 source=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller/observability/dashboards');data={f:json.dumps(json.loads((source/f).read_text())) for f in ['operations.json','workload-security.json']}
 patch={'metadata':{'uid':d['metadata']['uid'],'resourceVersion':d['metadata']['resourceVersion'],'annotations':{'cmtc.source-revision':'96cbc9eecaa95d830562c678f7e38041a17755a5'}},'data':data};p=O/'dashboard-patch.json';p.write_text(json.dumps(patch)+'\n')
 subprocess.run(K+['-n','monitoring','patch','cm','cmtc-dashboards','--type=merge','--patch-file',str(p)],check=True)
print(c,'scrape configuration updated without replacing storage; latest committed dashboards provisioned on hub')
