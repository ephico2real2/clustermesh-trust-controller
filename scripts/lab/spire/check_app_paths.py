#!/usr/bin/env python3
"""Create only two owned curl Pods; check 36 native application paths and clean up.

No existing application, Completed client, namespace, service, policy, SPIRE or
Cilium object is changed. This checks HTTP reachability, not mTLS protection.
"""
import argparse
import copy
from contextlib import ExitStack
from datetime import datetime,timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT=Path(__file__).resolve().parents[3]
CLUSTERS=('cmtc-a','cmtc-b')
PORTS=(80,8080,31337)
NS='mesh-example'
IMAGE='curlimages/curl:8.14.1'
OWNER='security.cmtc.io/app-audit-run'

class Refusal(RuntimeError):pass

def need(value,message):
    if not value:raise Refusal(message)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def sha(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
def strict_json(raw):
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'duplicate response JSON key');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(Refusal('nonfinite JSON')))

def live(obj):
    m=obj.get('metadata',{});need(m.get('uid') and m.get('resourceVersion') and not m.get('deletionTimestamp'),'object must be live and UID/RV pinned');return m

def digest(value):
    values=re.findall(r'sha256:[0-9a-f]{64}',value or '')
    need(len(values)==1,'one native image digest required');return values[0]

def client_plan(owner,node):
    need(str(uuid.UUID(owner))==owner and uuid.UUID(owner).int!=0,'canonical run owner required')
    need(node in ('cmtc-a-worker','cmtc-b-worker'),'only audited existing workers')
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'cmtc-app-audit-'+owner[:12],'namespace':NS,'labels':{OWNER:owner}},'spec':{'nodeName':node,'serviceAccountName':'default','automountServiceAccountToken':False,'restartPolicy':'Never','activeDeadlineSeconds':900,'terminationGracePeriodSeconds':5,'hostNetwork':False,'hostPID':False,'securityContext':{'runAsUser':65532,'runAsGroup':65532,'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'client','image':IMAGE,'imagePullPolicy':'Never','command':['/bin/sh','-ec','exec sleep 840'],'workingDir':'/','resources':{'requests':{'cpu':'10m','memory':'16Mi'},'limits':{'memory':'64Mi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}}

def assert_client_profile(pod,plan):
    m=live(pod);p=pod['spec'];want=plan['spec']
    need(m['name']==plan['metadata']['name'] and m['namespace']==NS and m.get('labels',{}).get(OWNER)==plan['metadata']['labels'][OWNER],'client ownership drift')
    for key in ('nodeName','serviceAccountName','automountServiceAccountToken','restartPolicy','activeDeadlineSeconds','terminationGracePeriodSeconds','hostNetwork','hostPID','securityContext'):
        actual=p.get(key,False) if key in ('hostNetwork','hostPID') else p.get(key)
        need(actual==want[key],'client profile differs: '+key)
    need(not p.get('volumes') and not p.get('initContainers') and not p.get('ephemeralContainers') and not p.get('hostIPC') and not p.get('shareProcessNamespace'),'unexpected client access or containers')
    need(len(p.get('containers',[]))==1,'one curl container required')
    actual=p['containers'][0];expected=want['containers'][0]
    for key in ('name','image','imagePullPolicy','command','workingDir','resources','securityContext'):
        need(actual.get(key)==expected[key],'curl profile differs: '+key)
    need(not actual.get('env') and not actual.get('envFrom') and not actual.get('volumeMounts') and not actual.get('volumeDevices'),'curl credentials/mounts refused')

def delete_options(obj,owner,uid):
    m=live(obj);need(m['uid']==uid and m.get('labels',{}).get(OWNER)==owner,'foreign/replaced client cannot be deleted')
    need(m.get('namespace')==NS and m.get('name')=='cmtc-app-audit-'+owner[:12],'cleanup path is not this run client')
    return {'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':uid,'resourceVersion':m['resourceVersion']}}

def running_identity(pod):
    m=live(pod);s=pod['spec'];st=pod.get('status',{});statuses=st.get('containerStatuses',[])
    need(st.get('phase')=='Running' and len(statuses)==len(s['containers']) and statuses and all(x.get('ready') and x.get('containerID') and x.get('imageID') and x.get('state',{}).get('running') for x in statuses),'Pod containers must be running/ready')
    return {'uid':m['uid'],'spec':copy.deepcopy(s),'podIP':st['podIP'],'containers':[{k:x.get(k) for k in ('name','containerID','imageID','restartCount','state')} for x in sorted(statuses,key=lambda x:x['name'])]}

def backend_inventory(pods,cluster,nodes):
    selected=[p for p in pods if p['metadata'].get('labels',{}).get('name')=='rebel-base' and p['metadata']['labels'].get('mesh.cmtc.io/cluster')==cluster and not p['metadata'].get('deletionTimestamp')]
    need(len(selected)==2 and {p['spec']['nodeName'] for p in selected}==set(nodes),'exactly one backend on each audited node required')
    result=[]
    for p in sorted(selected,key=lambda p:p['spec']['nodeName']):
        identity=running_identity(p);ip=ipaddress.ip_address(identity['podIP']);need(not ip.is_unspecified and not ip.is_multicast and not ip.is_loopback,'nonlocal unicast Pod IP required')
        result.append({'cluster':cluster,'node':p['spec']['nodeName'],'name':p['metadata']['name'],'ip':str(ip),'identity':identity})
    need(len({x['ip'] for x in result})==2,'duplicate backend address');return result

def path_matrix(inventory):
    need(set(inventory)==set(CLUSTERS),'both explicit cluster inventories required');cases=[]
    for source in CLUSTERS:
        for destination in CLUSTERS:
            allowed=sorted(x['name'] for x in inventory[destination])
            for port in PORTS:
                cases.append({'name':source+'-to-'+destination+'-service-'+str(port),'source':source,'destination':destination,'kind':'service','target':'rebel-base-'+destination+':'+str(port),'port':port,'allowedPods':allowed})
            for backend in inventory[destination]:
                address='['+backend['ip']+']' if ':' in backend['ip'] else backend['ip']
                for port in PORTS:
                    cases.append({'name':source+'-to-'+destination+'-podip-'+backend['node']+'-'+str(port),'source':source,'destination':destination,'kind':'pod-ip','target':address+':'+str(port),'port':port,'expectedPod':backend['name'],'allowedPods':[backend['name']]})
    need(len(cases)==36 and len({x['name'] for x in cases})==36,'exact36 unique cases required');return cases

def validate_response(case,body,headers):
    need(len(body)<=65536 and len(headers)<=65536 and 'PRIVATE KEY' not in body+headers,'bounded public application response required')
    lines=headers.replace('\r\n','\n').splitlines();status=[i for i,line in enumerate(lines) if line.startswith('HTTP/')]
    need(status and re.fullmatch(r'HTTP/1\.[01] 200(?: .*)?',lines[status[-1]]) is not None,'actual HTTP200 response required')
    values={}
    for line in lines[status[-1]+1:]:
        if not line:continue
        need(':' in line,'malformed HTTP header');key,value=line.split(':',1);values.setdefault(key.lower(),[]).append(value.strip())
    pod_values=values.get('x-cmtc-pod',[])
    need(len(pod_values)==1 and pod_values[0] in case['allowedPods'],'response did not identify an exact current destination Pod')
    if case['kind']=='pod-ip':need(pod_values[0]==case['expectedPod'],'Pod-IP reached wrong backend')
    result=strict_json(body);need(isinstance(result,dict) and result.get('cluster')==case['destination'],'body identified wrong destination cluster')
    return {'actualCluster':result['cluster'],'actualPod':pod_values[0],'httpStatus':200,'bodySHA256':hashlib.sha256(body.encode()).hexdigest()}

class Audit:
    def __init__(self,args):
        self.args=args;self.owner=str(uuid.uuid4());self.out=Path(args.out);self.out.mkdir(mode=0o700,parents=False,exist_ok=False)
        self.pins_raw=Path(args.cluster_pins).read_bytes();self.pins=strict_json(self.pins_raw);self.apis={}
        self.report={'schema':'cmtc-owned-application-paths/v1','owner':self.owner,'status':'running','scope':'native-HTTP-application-continuity-only','mtlsProven':False,'protected':False,'clusters':{},'cases':[],'cleanupErrors':[]};self.flush()
    def flush(self):
        tmp=self.out/'report.tmp';tmp.write_text(json.dumps(self.report,indent=2));os.replace(tmp,self.out/'report.json')
    def poll(self,fn,seconds=90):
        end=time.monotonic()+seconds
        while True:
            value=fn()
            if value:return value
            need(time.monotonic()<end,'bounded observation timed out');time.sleep(1)
    def command(self,c,args,timeout=15):
        result=subprocess.run(self.apis[c].argv+args,capture_output=True,text=True,timeout=timeout)
        need(len(result.stdout)<=131072 and len(result.stderr)<=65536 and 'PRIVATE KEY' not in result.stdout+result.stderr,'bounded public command required')
        need(result.returncode==0,'application audit command failed: exit='+str(result.returncode)+' diagnostic='+result.stderr[:4096]);return result
    def get(self,c,path):return self.apis[c].get(path)
    def maybe(self,c,path):
        try:return self.get(c,path)
        except self.pki.APIError as error:
            if error.status==404:return None
            raise
    def pod(self,c,name):return self.get(c,'/api/v1/namespaces/'+NS+'/pods/'+name)
    def prepare(self,c):
        st={'created':None};self.report['clusters'][c]=st;self.flush()
        need(self.get(c,'/api/v1/namespaces/kube-system')['metadata']['uid']==self.pins[c]['clusterUID'],'wrong cluster API')
        nodes=self.get(c,'/api/v1/nodes')['items'];need({p['metadata']['name']:p['metadata']['uid'] for p in nodes}==self.pins[c]['nodes'],'node inventory differs from independent pins')
        namespace=self.get(c,'/api/v1/namespaces/'+NS);st['namespace']={'uid':live(namespace)['uid'],'labels':copy.deepcopy(namespace['metadata'].get('labels',{}))}
        original=self.pod(c,'mesh-client');live(original);need(original['spec']['containers'][0]['image']==IMAGE and len(original['spec']['containers'])==1,'original client cached image differs')
        statuses=original.get('status',{}).get('containerStatuses',[]);need(len(statuses)==1,'original client image identity absent');st['originalClient']=copy.deepcopy(original);st['expectedClientImageDigest']=digest(statuses[0]['imageID'])
        services={}
        for target in CLUSTERS:
            s=self.get(c,'/api/v1/namespaces/'+NS+'/services/rebel-base-'+target);live(s);need(s['spec'].get('clusterIP') not in (None,'','None'),'native ClusterIP service required');need(set(PORTS)<={x['port'] for x in s['spec']['ports'] if x.get('protocol','TCP')=='TCP'},'all three native service TCP ports required');services[target]={'uid':s['metadata']['uid'],'spec':copy.deepcopy(s['spec'])}
        st['services']=services
        st['backends']=backend_inventory(self.get(c,'/api/v1/namespaces/'+NS+'/pods')['items'],c,self.pins[c]['nodes'])
        plan=client_plan(self.owner,c+'-worker');path='/api/v1/namespaces/'+NS+'/pods/'+plan['metadata']['name'];need(self.maybe(c,path) is None,'fresh audit client name collision')
        st['pendingCreate']=path;self.flush();created=self.apis[c].request('POST','/api/v1/namespaces/'+NS+'/pods',plan)
        st['created']={'path':path,'uid':live(created)['uid'],'name':created['metadata']['name']};st.pop('pendingCreate');self.flush()
        def ready():
            now=self.pod(c,st['created']['name']);need(now['metadata']['uid']==st['created']['uid'],'client replaced before readiness')
            if now.get('status',{}).get('phase') in ('Failed','Succeeded'):raise Refusal('owned client terminated before audit')
            statuses=now.get('status',{}).get('containerStatuses',[])
            return now if now.get('status',{}).get('phase')=='Running' and len(statuses)==1 and statuses[0].get('ready') and statuses[0].get('state',{}).get('running') else None
        pod=self.poll(ready);assert_client_profile(pod,plan);identity=running_identity(pod);need(digest(identity['containers'][0]['imageID'])==st['expectedClientImageDigest'],'new client native image differs from existing cached client')
        version=self.command(c,['exec','-n',NS,pod['metadata']['name'],'-c','client','--','curl','--version']).stdout;need(re.match(r'^curl 8\.14\.1(?: |\n)',version) is not None,'actual curl version differs');st['clientIdentity']=identity;st['curlVersion']=version;self.flush()
    def continuity(self):
        for c,st in self.report['clusters'].items():
            if 'originalClient' not in st:continue
            original=self.pod(c,'mesh-client');need(original==st['originalClient'],'original Completed client changed')
            ns=self.get(c,'/api/v1/namespaces/'+NS);need(live(ns)['uid']==st['namespace']['uid'] and ns['metadata'].get('labels',{})==st['namespace']['labels'],'application namespace changed')
            for target,saved in st.get('services',{}).items():
                s=self.get(c,'/api/v1/namespaces/'+NS+'/services/rebel-base-'+target);need(live(s)['uid']==saved['uid'] and s['spec']==saved['spec'],'application Service changed')
            if 'backends' in st:
                current=backend_inventory(self.get(c,'/api/v1/namespaces/'+NS+'/pods')['items'],c,self.pins[c]['nodes']);need(current==st['backends'],'application backend incarnation changed')
    def check_case(self,case):
        source=case['source'];st=self.report['clusters'][source];name=st['created']['name']
        need(running_identity(self.pod(source,name))==st['clientIdentity'],'source client incarnation changed')
        self.continuity()
        result=self.command(source,['exec','-n',NS,name,'-c','client','--','curl','--http1.1','--noproxy','*','--silent','--show-error','--fail-with-body','--connect-timeout','2','--max-time','5','--dump-header','/dev/stderr','http://'+case['target']+'/'],timeout=15)
        observed=validate_response(case,result.stdout,result.stderr)
        need(running_identity(self.pod(source,name))==st['clientIdentity'],'source client changed during request');self.continuity()
        stem=f'{len(self.report["cases"])+1:02d}-{case["name"]}'
        (self.out/(stem+'.headers')).write_text(result.stderr);(self.out/(stem+'.json')).write_text(result.stdout)
        self.report['cases'].append(dict(case,**observed,responseFile=stem+'.json',headersFile=stem+'.headers',passed=True));self.flush()
    def cleanup(self):
        for c,st in self.report['clusters'].items():
            if st.get('pendingCreate'):
                self.report['cleanupErrors'].append({'cluster':c,'error':'ambiguous create response; unpinned object preserved','path':st['pendingCreate']});self.flush();continue
            created=st.get('created')
            if not created:continue
            try:
                obj=self.maybe(c,created['path'])
                if obj is not None:
                    options=delete_options(obj,self.owner,created['uid']);self.apis[c].request('DELETE',created['path'],options)
                    def absent():
                        obj=self.maybe(c,created['path'])
                        if obj is None:return True
                        need(obj['metadata']['uid']==created['uid'],'replacement appeared during cleanup; never delete it');return False
                    self.poll(absent)
            except Exception as error:self.report['cleanupErrors'].append({'cluster':c,'path':created['path'],'error':str(error)})
            self.flush()
    def execute(self):
        spec=importlib.util.spec_from_file_location('app_audit_pki',ROOT/'scripts/lab/pki/pki.py');self.pki=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.pki)
        error=None
        with ExitStack() as stack:
            try:
                for c in CLUSTERS:self.apis[c]=stack.enter_context(self.pki.Proxy(self.args.kubeconfig,'kind-'+c))
                for c in CLUSTERS:self.prepare(c)
                matrix=path_matrix({c:self.report['clusters'][c]['backends'] for c in CLUSTERS})
                for case in matrix:self.check_case(case)
                need(len(self.report['cases'])==36,'all36 paths required');self.continuity()
            except Exception as exc:error=exc;self.report['error']=str(exc)
            finally:
                self.cleanup()
                try:self.continuity();need(Path(self.args.cluster_pins).read_bytes()==self.pins_raw,'cluster pin file changed')
                except Exception as exc:self.report['cleanupErrors'].append({'stage':'continuity','error':str(exc)})
                self.report['status']='passed' if error is None and not self.report['cleanupErrors'] and len(self.report['cases'])==36 else 'failed';self.report['finishedAt']=datetime.now(timezone.utc).isoformat();self.flush()
        if error:raise error
        need(self.report['status']=='passed','application audit cleanup/continuity failed');return self.report

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--out',required=True);a.add_argument('--kubeconfig',default='/private/tmp/cmtc-a-b-20261024.kubeconfig');a.add_argument('--cluster-pins',default='/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json');Audit(a.parse_args()).execute()
if __name__=='__main__':main()
