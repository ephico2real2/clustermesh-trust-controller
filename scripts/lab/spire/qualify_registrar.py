#!/usr/bin/env python3
"""Owned, explicit two-cluster native registrar qualification; never runs on import.

This runner intentionally changes only its fresh fixture objects and the exact
SPIRE server template it saved. No Secret reads, manual Entry create, key export,
image build, cluster creation, Cilium change or mTLS/Protected claim.
"""
import argparse
import copy
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts/lab/spire'))
import workload_api as w
import qualify_workload as q
import public_proof as proof
spec=importlib.util.spec_from_file_location('registrar_pki_transport',ROOT/'scripts/lab/pki/pki.py')
pki=importlib.util.module_from_spec(spec);spec.loader.exec_module(pki)

OWNER='security.cmtc.io/registrar-run'
NAMESPACE='cilium-spire'
SOCKET='/tmp/spire-server/private/api.sock'
REVISION='e39928bc4f79ad6da134e77583945c8e5e9d52bf'
REGISTRAR_CONFIG='1454f25c3d16c77cb9c2618b2cc34878d2e916d60f226cdc90d91259cd017524'
REGISTRAR_IMAGE='localhost/cmtc-spire-registrar@sha256:f1493a0145d6485d27e668c447c6addbbdafd8179ac7bdc9ee0ea8f000e2e7eb'
SERVER_SOCKET_PREPARE="""set -eu
p=/tmp/spire-server/private
test -d "$p"
test ! -L "$p"
test "$(stat -c '%u:%g' "$p")" = 0:1000
test -z "$(ls -A "$p")"
chmod 00770 "$p"
test "$(stat -c '%u:%g:%a' "$p")" = 0:1000:770
"""


class Refusal(RuntimeError):pass

def need(condition,message):
    if not condition:raise Refusal(message)

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def validate_probe_pins(args):
    need(re.fullmatch(r'[0-9a-f]{64}',args.probe_config) is not None,'exact probe configuration SHA256 required')
    need(re.fullmatch(r'[0-9a-f]{40}',args.probe_source) is not None,'exact clean probe source SHA required')
    proof.approved_server_image(args.probe_image)
    need((args.probe_uid,args.probe_gid)==(1000,0),'only the qualified diagnostic DAC profile is authorized')

def verify_probe_version(raw,source):
    need(len(raw)<4096 and 'PRIVATE KEY' not in raw,'bounded public binary version required')
    need(raw.strip().startswith('version.BuildInfo{') and ('GitRevision:"'+source+'"') in raw and 'BuildStatus:"Clean"' in raw,'actual diagnostic binary source/status differs')
    return raw.strip()

def target_absence(result):
    # This is an empty/unusable SDK SVID response, not gRPC authorization denial.
    if result.returncode==0:return False
    diagnostic=result.stderr
    need(result.returncode==1,'credential command exited abnormally; withdrawal inconclusive')
    need(not result.stdout.strip(),'failed credential request emitted a payload')
    need('native PID-attested credential fetch' in diagnostic and
         'Failed to receive X.509 SVID: empty Workload API response' in diagnostic and
         not any(x in diagnostic for x in ('PermissionDenied','The caller does not have permission','Unauthenticated','Unavailable','deadline','timed out','Timeout')),
         'withdrawal observation inconclusive: expected explicit empty/unusable SVID response')
    return True

def withdrawal_rows(wants,target_namespace):
    # Alias metadata can be last refreshed while iterating any namespace.
    # Only a workload leaf in the withdrawn namespace loses its entitlement.
    return {key:value for key,value in wants.items()
            if '/ns/' not in value['spiffeID'] or value['namespace']!=target_namespace}

def pair_controls(targets,target_namespace,control_namespace):
    groups={target_namespace:{},control_namespace:{}}
    for probe,pod,desired in targets:
        ns=pod['metadata']['namespace'];need(ns in groups,'unexpected fixture namespace')
        node=pod['spec']['nodeName'];need(node==probe['spec']['nodeName'],'control/target must use the local node probe')
        need(node not in groups[ns],'ambiguous same-node fixture workload')
        need(desired['namespace']==ns and desired['podUID']==pod['metadata']['uid'],'fixture desired binding differs')
        groups[ns][node]=(probe,pod,desired)
    a,b=groups[target_namespace],groups[control_namespace]
    need(len(a)==2 and set(a)==set(b),'exactly one target and control per audited node required')
    pairs=[]
    for node,target in a.items():
        control=b[node]
        need(target[0]['metadata']['uid']==control[0]['metadata']['uid'],'control uses a different probe incarnation')
        pairs.append((target,control))
    return pairs

def live(o):
    m=o.get('metadata',{});need(m.get('uid') and m.get('resourceVersion') and not m.get('deletionTimestamp'),'live UID/RV required');return m

def assert_owned(o,owner,uid):
    m=live(o);need(m['uid']==uid and m.get('labels',{}).get(OWNER)==owner,'owned object changed or replaced');return m

def deletion(o,owner,uid):
    m=assert_owned(o,owner,uid)
    return {'apiVersion':'v1','kind':'DeleteOptions','propagationPolicy':'Foreground','preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']}}

def template_patch(current,expected_uid,old,new):
    m=live(current);need(m['uid']==expected_uid and current['spec']['template']==old,'server template/incarnation drift')
    return [{'op':'test','path':'/metadata/uid','value':expected_uid},{'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']},{'op':'test','path':'/spec/template','value':old},{'op':'replace','path':'/spec/template','value':new}]

def wanted(options,pod,node,agent,namespace_uid,role):
    """Byte-equivalent to Go json.Marshal([]string{...}) + uuid.NewSHA1(URL)."""
    o=options;pm=live(pod);nm=live(node);am=live(agent)
    namespace=pod['metadata']['namespace'];sa=pod['spec']['serviceAccountName']
    alias='/cmtc/agents/'+nm['uid']+'/'+am['uid']
    def entry(r,nsuid,puid,path,parent,selectors):
        binding=json.dumps([o['installationID'],o['clusterUID'],nsuid,nm['uid'],am['uid'],puid,r],separators=(',',':'),ensure_ascii=False)
        eid=str(uuid.uuid5(uuid.NAMESPACE_URL,binding));identity='spiffe://'+o['trustDomain']+path
        return {'entryID':eid,'spiffeID':identity,'parentID':'spiffe://'+o['trustDomain']+parent,'selectors':selectors,'podUID':puid,'namespace':namespace,'podName':pm['name'],'hint':'cmtc-registrar/v1/'+o['clusterUID']+'/'+o['installationID'],'showArguments':['entry','show','-socketPath',SOCKET,'-entryID',eid,'-output','json']}
    alias_entry=entry('agent',o['agent']['namespaceUID'],am['uid'],alias,'/spire/server',['k8s_psat:cluster:'+o['clusterName'],'k8s_psat:agent_ns:'+o['agent']['namespace'],'k8s_psat:agent_sa:'+o['agent']['serviceAccount'],'k8s_psat:agent_pod_uid:'+am['uid'],'k8s_psat:agent_node_name:'+nm['name'],'k8s_psat:agent_node_uid:'+nm['uid']])
    path='/ztunnel-proxy' if role=='delegate' else '/ns/'+namespace+'/sa/'+sa
    leaf=entry(role,namespace_uid,pm['uid'],path,alias,['k8s:ns:'+namespace,'k8s:sa:'+sa,'k8s:pod-uid:'+pm['uid'],'k8s:node-name:'+nm['name']])
    return alias_entry,leaf

def approval(cluster,cluster_uid,domain,installation,namespace,account,agent_ds,agent_sa,delegate_ds,delegate_sa,spire_ns,extra_namespaces=()):
    def daemon(ds,sa,container):
        m=live(ds);sm=live(sa);nm=live(spire_ns)
        image=next(c['image'] for c in ds['spec']['template']['spec']['containers'] if c['name']==container)
        proof.approved_server_image(image)
        return {'namespace':NAMESPACE,'namespaceUID':nm['uid'],'name':m['name'],'uid':m['uid'],'serviceAccount':sm['name'],'serviceAccountUID':sm['uid'],'container':container,'image':image}
    return {'clusterName':cluster,'clusterUID':cluster_uid,'trustDomain':domain,'installationID':installation,'agent':daemon(agent_ds,agent_sa,'spire-agent'),'delegate':daemon(delegate_ds,delegate_sa,'probe'),'namespaces':[{'name':live(ns)['name'],'uid':live(ns)['uid'],'serviceAccounts':{live(sa)['name']:live(sa)['uid']}} for ns,sa in [(namespace,account),*extra_namespaces]],'excludedNamespaces':[]}

def sidecar_template(original,image,config_name,config_sha):
    t=copy.deepcopy(original);p=t['spec'];need(p['serviceAccountName']=='spire-server' and p['securityContext']['runAsUser']==1000 and p['securityContext']['runAsGroup']==1000,'server credential boundary differs')
    need({c['name'] for c in p['containers']}=={'spire-server','register-agent-node'},'unexpected existing server containers')
    need(next(v for v in p['volumes'] if v['name']=='spire-server-socket')=={'name':'spire-server-socket','emptyDir':{}},'private server socket volume differs')
    need(not any(v['name']=='cmtc-registrar-config' for v in p['volumes']),'registrar volume collision')
    need(not p.get('initContainers'),'unexpected existing server init container')
    p['initContainers']=[{'name':'prepare-registrar-socket','image':proof.SIDECAR_IMAGE,'imagePullPolicy':'Never','command':['/bin/sh','-ec',SERVER_SOCKET_PREPARE],'workingDir':'/','securityContext':{'runAsUser':0,'runAsGroup':1000,'runAsNonRoot':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'spire-server-socket','mountPath':'/tmp/spire-server/private'}],'resources':{'requests':{'cpu':'5m','memory':'8Mi'},'limits':{'memory':'32Mi'}}}]
    p['volumes'].append({'name':'cmtc-registrar-config','configMap':{'name':config_name,'defaultMode':0o444}})
    p['containers'].append({'name':'cmtc-spire-registrar','image':image,'imagePullPolicy':'Never','command':['/cmtc-spire-registrar'],'workingDir':'/','args':['--config=/etc/cmtc-registrar/approval.json','--config-sha256='+config_sha],'securityContext':{'runAsUser':1000,'runAsGroup':1000,'runAsNonRoot':True,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'spire-server-socket','mountPath':'/tmp/spire-server/private'},{'name':'cmtc-registrar-config','mountPath':'/etc/cmtc-registrar','readOnly':True}],'ports':[{'name':'registrar-http','containerPort':18086}],'readinessProbe':{'httpGet':{'path':'/readyz','port':18086},'periodSeconds':2,'timeoutSeconds':2,'failureThreshold':1},'livenessProbe':{'httpGet':{'path':'/healthz','port':18086},'periodSeconds':10,'timeoutSeconds':2,'failureThreshold':3},'startupProbe':{'httpGet':{'path':'/healthz','port':18086},'periodSeconds':2,'timeoutSeconds':2,'failureThreshold':45},'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'memory':'128Mi'}}})
    return t

class Runner:
    def __init__(self,args):
        validate_probe_pins(args)
        self.args=args;self.owner=str(uuid.uuid4());self.short=self.owner[:8];self.out=Path(args.out);self.out.mkdir(mode=0o700,parents=False,exist_ok=False)
        self.pins=json.loads(Path(args.cluster_pins).read_text());self.ledger_raw=Path(args.issuer_ledger).read_bytes();self.issuer=json.loads(self.ledger_raw)['identity']
        self.report={'schema':'cmtc-exact-registrar-runtime/v1','owner':self.owner,'sourceRevision':REVISION,'probeImage':args.probe_image,'probeConfig':args.probe_config,'probeSource':args.probe_source,'startedAt':datetime.now(timezone.utc).isoformat(),'clusters':{},'events':[],'cleanupErrors':[],'protected':False,'packetProtectionTested':False,'qualified':False}
        self.apis={};self.flush()
    def flush(self):
        tmp=self.out/'report.tmp';tmp.write_text(json.dumps(self.report,indent=2));os.replace(tmp,self.out/'report.json')
    def emit(self,event):self.report['events'].append(dict(event,at=datetime.now(timezone.utc).isoformat()));self.flush()
    def save(self,name,obj):
        data=obj if isinstance(obj,str) else json.dumps(obj,indent=2)
        need('PRIVATE KEY' not in data,'private output refused');(self.out/name).write_text(data)
    def remaining(self,limit):
        end=getattr(self,'_deadline',None)
        if end is None:return limit
        remaining=end-time.monotonic()
        need(remaining>0,'withdrawal global deadline exhausted; no denial evidence')
        return min(limit,remaining)
    @contextmanager
    def deadline(self,seconds):
        old=getattr(self,'_deadline',None)
        end=time.monotonic()+seconds;self._deadline=min(old,end) if old is not None else end
        try:yield
        finally:self._deadline=old
    def pause(self,seconds):
        delay=self.remaining(seconds);time.sleep(delay)
        self.remaining(1)
    def poll(self,fn,*,seconds=90):
        end=time.monotonic()+self.remaining(seconds)
        while True:
            self.remaining(1);value=fn();self.remaining(1)
            if value:return value
            need(time.monotonic()<end,'bounded observation timed out')
            self.pause(min(1,end-time.monotonic()))
    def get(self,c,path):
        if getattr(self,'_deadline',None) is None:return self.apis[c].get(path)
        return json.loads(self.command(c,['get','--raw',path]).stdout)
    def maybe(self,c,path):return pki.maybe(self.apis[c],path)
    def command(self,c,args,*,success=True,timeout=40):
        result=q.bounded(self.apis[c].argv+args,success=success,timeout=self.remaining(timeout))
        self.remaining(1)
        return result
    def create(self,c,collection,obj):
        obj=copy.deepcopy(obj);obj.setdefault('metadata',{}).setdefault('labels',{})[OWNER]=self.owner
        path=collection+'/'+obj['metadata']['name'];need(self.maybe(c,path) is None,'fresh fixture name already exists')
        # Persist intent before API write; a lost create response is never an excuse
        # to delete an unpinned object. Cleanup records an unresolved pending path.
        self.report['clusters'][c]['pendingCreate']=path;self.flush()
        result=self.apis[c].request('POST',collection,obj);m=live(result)
        self.report['clusters'][c]['created'].append({'path':path,'uid':m['uid'],'kind':obj['kind']});self.report['clusters'][c].pop('pendingCreate');self.flush();return result
    def delete_owned(self,c,path,uid):
        obj=self.maybe(c,path)
        if obj is None:return
        body=deletion(obj,self.owner,uid);self.apis[c].request('DELETE',path,body)
        def absent():
            now=self.maybe(c,path)
            if now is None:return True
            need(now['metadata']['uid']==uid,'replacement appeared during delete; never touch replacement');return False
        self.poll(absent,seconds=90)
    def template(self,c,old,new):
        st=self.report['clusters'][c];path=st['serverPath'];obj=self.get(c,path);patch=template_patch(obj,st['serverUID'],old,new)
        # API admission errors are determined before recording a possibly sent write.
        self.command(c,['patch','statefulset','spire-server','-n',NAMESPACE,'--type=json','--dry-run=server','-p',json.dumps(patch),'-o','json'])
        st['pendingTemplatePatch']=True;self.flush()
        result=self.command(c,['patch','statefulset','spire-server','-n',NAMESPACE,'--type=json','-p',json.dumps(patch),'-o','json'])
        applied=json.loads(result.stdout)['spec']['template'];st['installedTemplate']=applied;st.pop('pendingTemplatePatch');self.flush();return applied
    def pods(self,c,namespace):return self.get(c,'/api/v1/namespaces/'+namespace+'/pods')['items']
    def current_pods(self,c,ds):
        owner=live(ds)['uid'];out={}
        for p in self.pods(c,ds['metadata']['namespace']):
            if p['metadata'].get('deletionTimestamp'):continue
            if any(x.get('controller') and x.get('kind')=='DaemonSet' and x.get('uid')==owner for x in p['metadata'].get('ownerReferences',[])):
                node=p['spec'].get('nodeName')
                if not node:continue # A newly created DaemonSet Pod may still await scheduling.
                need(node not in out,'ambiguous daemon Pod incarnation');out[node]=p
        return out
    def ready(self,p):
        ss=p.get('status',{}).get('containerStatuses',[])
        return bool(not p['metadata'].get('deletionTimestamp') and p.get('status',{}).get('phase')=='Running' and ss and len(ss)==len(p['spec']['containers']) and all(s.get('ready') and s.get('containerID') and s.get('state',{}).get('running') for s in ss))
    def wait_daemon(self,c,ds):
        def check():
            ps=self.current_pods(c,ds)
            return ps if set(ps)==set(self.pins[c]['nodes']) and all(self.ready(p) for p in ps.values()) else None
        return self.poll(check,seconds=120)
    def server(self,c,*,old_uid=None,registrar=True):
        st=self.report['clusters'][c]
        def check():
            p=self.maybe(c,'/api/v1/namespaces/cilium-spire/pods/spire-server-0')
            if not p or (old_uid is not None and p['metadata']['uid']==old_uid) or not self.ready(p):return None
            owner=next((x for x in p['metadata'].get('ownerReferences',[]) if x.get('controller')),None)
            need(owner and owner['uid']==st['serverUID'] and owner['kind']=='StatefulSet','foreign server Pod controller')
            names={x['name'] for x in p['spec']['containers']}
            expected={'spire-server','register-agent-node'}|({'cmtc-spire-registrar'} if registrar else set())
            if names!=expected:
                # An exact opposite owned profile is an old Pod waiting for the
                # StatefulSet rollout. Unknown profiles remain fatal.
                proof.pod_identity(p,p['metadata']['uid'],server_image=self.issuer['spireServerImage'],registrar_image=None if registrar else self.args.registrar_image)
                return None
            proof.pod_identity(p,p['metadata']['uid'],server_image=self.issuer['spireServerImage'],registrar_image=self.args.registrar_image if registrar else None)
            return p
        return self.poll(check,seconds=180)
    def cri(self,c,node,image,expected):
        raw=q.bounded(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,'crictl','inspecti','-o','json',image],timeout=30)
        result=json.loads(raw.stdout);need(result['status']['id'].removeprefix('sha256:')==expected,'actual node image config pin mismatch')
        spec=result['info']['imageSpec'];need(spec['architecture']=='arm64' and spec['os']=='linux','actual node image architecture differs')
        revision=REVISION if image==self.args.registrar_image else self.args.probe_source
        need(spec['config']['Labels']['org.opencontainers.image.revision']==revision,'actual node image source differs')
        self.save(c+'-'+node+'-'+('registrar' if expected==REGISTRAR_CONFIG else 'probe')+'-cri.json',result)
        return result['status']['id']
    def rows(self,c):
        result=(q.server_cli(self.apis[c],['entry','show','-socketPath',SOCKET,'-output','json']) if getattr(self,'_deadline',None) is None else json.loads(self.command(c,['exec','-n',NAMESPACE,'spire-server-0','-c','register-agent-node','--','/bin/timeout','-s','KILL','12','/spire-cli/opt/spire/bin/spire-server','entry','show','-socketPath',SOCKET,'-output','json'],timeout=20).stdout))
        # SPIRE's protobuf JSON omits the repeated field for an empty store.
        need(isinstance(result,dict) and set(result)<={'entries','next_page_token'} and result.get('next_page_token','')=='','unexpected or incomplete paginated Entry list schema')
        rows=result.get('entries',[]);need(isinstance(rows,list),'Entry list must be an array');return rows
    def owned_rows(self,c):
        hint='cmtc-registrar/v1/'+self.pins[c]['clusterUID']+'/'+self.report['clusters'][c]['installationID']
        rows=self.rows(c);return {r['id']:r for r in rows if r.get('hint')==hint}
    def expected(self,c):
        st=self.report['clusters'][c];agents=self.current_pods(c,st['agent']);probes=self.current_pods(c,st['delegate']);ns=st['namespace'];options=st['approval'];rows={};targets=[]
        for node_name in self.pins[c]['nodes']:
            node=self.get(c,'/api/v1/nodes/'+node_name);need(live(node)['uid']==self.pins[c]['nodes'][node_name],'node incarnation changed');agent=agents[node_name];probe=probes[node_name]
            for pod,nsuid,role in [(probe,options['delegate']['namespaceUID'],'delegate')]+[(p,n['metadata']['uid'],'workload') for n in (ns,st['controlNamespace']) for p in self.pods(c,n['metadata']['name']) if p['spec']['nodeName']==node_name and not p['metadata'].get('deletionTimestamp')]:
                need(pod['metadata']['labels'].get(OWNER)==self.owner,'foreign fixture workload');a,b=wanted(options,pod,node,agent,nsuid,role);rows[a['entryID']]=a;rows[b['entryID']]=b
                if role=='workload':targets.append((probe,pod,b))
        pair_controls(targets,ns['metadata']['name'],st['controlNamespace']['metadata']['name'])
        return rows,targets
    def wait_rows(self,c,wants):
        def check():
            actual=self.owned_rows(c)
            if set(actual)!=set(wants):return None
            now=time.time()
            for eid,desired in wants.items():
                w.compare_entry(actual[eid],desired)
                need(actual[eid].get('hint')==desired['hint'],'entry ownership hint mismatch')
                expiry=int(actual[eid].get('expires_at',0))
                if not now+15<expiry<=now+95:return None
            return actual
        actual=self.poll(check,seconds=75);self.emit({'cluster':c,'stage':'exact-entry-readback','entryIDs':sorted(actual)});return actual
    def signer(self,c,name,*,registrar):
        p=self.server(c,registrar=registrar)
        result=proof.execute_proof(self.apis[c],cluster=c,cluster_uid=self.pins[c]['clusterUID'],pod_uid=p['metadata']['uid'],approval_uid=self.issuer['approvalPins'][c],root_pin=self.issuer['rootSHA256'],server_image=self.issuer['spireServerImage'],registrar_image=self.args.registrar_image if registrar else None)
        self.save(c+'-'+name+'-signer.json',result);return result
    def pvc(self,c):
        return {x['metadata']['name']:x['metadata']['uid'] for x in self.get(c,'/api/v1/namespaces/cilium-spire/persistentvolumeclaims')['items']}
    def label(self,c,enrolled):
        st=self.report['clusters'][c];path='/api/v1/namespaces/'+st['namespace']['metadata']['name'];o=self.get(c,path);m=assert_owned(o,self.owner,st['namespace']['metadata']['uid']);labels=copy.deepcopy(m.get('labels',{}))
        if enrolled:labels['io.cilium/mtls-enabled']='true'
        else:labels.pop('io.cilium/mtls-enabled',None)
        patch=[{'op':'test','path':'/metadata/uid','value':m['uid']},{'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']},{'op':'test','path':'/metadata/labels','value':m['labels']},{'op':'replace','path':'/metadata/labels','value':labels}]
        self.command(c,['patch','namespace',m['name'],'--type=json','-p',json.dumps(patch)]);self.emit({'cluster':c,'stage':'namespace-enrollment','enrolled':enrolled})
    def assert_registration(self,c,desired):
        matches=[entry for entry in self.rows(c) if entry['id']==desired['entryID']]
        need(len(matches)==1,'one exact live control/positive registration required')
        w.compare_entry(matches[0],desired)
    def positive_fetch(self,c,probe,pod,desired,issuer,phase):
        with self.deadline(60):
            for attempt in range(1,6):
                self.assert_registration(c,desired)
                result=self.native_observation(c,probe,pod,desired,phase+'-positive-'+str(attempt))
                self.assert_registration(c,desired)
                if result.returncode==0:
                    verified=q.verify_public_result(result.stdout,wanted=desired,current_issuer_proof=issuer)
                    self.remaining(1);return verified
                explicit_pending=(result.returncode==1 and not result.stdout.strip() and 'native PID-attested credential fetch' in result.stderr and
                    (('The caller does not have permission' in result.stderr and 'no identity issued' in result.stderr) or
                     'Failed to receive X.509 SVID: empty Workload API response' in result.stderr) and
                    not any(x in result.stderr for x in ('Unavailable','deadline','timed out','Timeout')))
                need(explicit_pending,'positive credential request failed for an unrelated reason')
                need(attempt<5,'positive registration propagation attempts exhausted')
                self.emit({'cluster':c,'stage':'positive-registration-propagation','podUID':desired['podUID'],'attempt':attempt,'diagnostic':result.stderr[:4096]})
                self.pause(min(2**attempt,8))
        raise Refusal('positive registration propagation exhausted')
    def fetch_all(self,c,phase):
        wants,targets=self.expected(c);self.wait_rows(c,wants);issuer=self.signer(c,phase,registrar=True);st=self.report['clusters'][c]
        need(issuer['directIssuerSHA256']==st['beforeSigner']['directIssuerSHA256'],'signer changed across registrar fixture')
        results=[]
        for probe,pod,desired in targets:
            self.cri(c,probe['spec']['nodeName'],self.args.probe_image,self.args.probe_config)
            result=self.positive_fetch(c,probe,pod,desired,issuer,phase)
            results.append(result)
        need(len(results)==4,'one target and control per audited node required');self.save(c+'-'+phase+'-native-svid.json',results);return wants,targets
    def native_observation(self,c,probe,pod,desired,label):
        need(pod['spec']['nodeName']==probe['spec']['nodeName'],'remote PID cannot use a local probe')
        need(desired['podUID']==pod['metadata']['uid'],'desired target incarnation differs')
        need(len(probe['spec']['containers'])==1 and probe['spec']['containers'][0]['image']==self.args.probe_image,'unexpected actual probe image')
        ppath='/api/v1/namespaces/'+pod['metadata']['namespace']+'/pods/'+pod['metadata']['name']
        dpath='/api/v1/namespaces/'+probe['metadata']['namespace']+'/pods/'+probe['metadata']['name']
        q.same_running_pod(pod,self.get(c,ppath));q.same_running_pod(probe,self.get(c,dpath))
        result=self.command(c,['exec','-n',probe['metadata']['namespace'],probe['metadata']['name'],'-c','probe','--',q.BINARY,'fetch',desired['spiffeID'],desired['podUID'],desired['podName']],success=False)
        self.save(c+'-'+label+'-'+desired['podUID']+'.json',{'exitCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        q.same_running_pod(pod,self.get(c,ppath));q.same_running_pod(probe,self.get(c,dpath))
        return result
    def control_fetch(self,c,control,issuer,label):
        self.assert_registration(c,control[2])
        result=self.native_observation(c,*control,label)
        self.assert_registration(c,control[2])
        need(result.returncode==0,'still-enrolled control credential failed; target withdrawal inconclusive')
        verified=q.verify_public_result(result.stdout,wanted=control[2],current_issuer_proof=issuer)
        self.save(c+'-'+label+'-'+control[2]['podUID']+'-verified.json',verified);self.remaining(1)
        return verified
    def deny_withdrawn(self,c,target,control,issuer):
        started=time.monotonic();attempt=0
        self.control_fetch(c,control,issuer,'withdrawal-control-before')
        while True:
            self.remaining(1);attempt+=1
            result=self.native_observation(c,*target,'withdrawal-attempt-'+str(attempt))
            if target_absence(result):
                self.control_fetch(c,control,issuer,'withdrawal-control-after')
                self.remaining(1)
                self.emit({'cluster':c,'stage':'withdrawal-explicit-empty-svid','attempt':attempt,'elapsedSeconds':time.monotonic()-started,'podUID':target[2]['podUID'],'controlPodUID':control[2]['podUID'],'delegateAuthorizedControl':True,'authorizationDenied':False,'withdrawalRemainingSeconds':self.remaining(60),'diagnostic':result.stderr[:4096]})
                self.remaining(1)
                return
            # Successful propagation responses must be real, correctly bound SVIDs.
            q.verify_public_result(result.stdout,wanted=target[2],current_issuer_proof=issuer)
            self.remaining(1)
            self.emit({'cluster':c,'stage':'withdrawal-not-yet-observed','attempt':attempt,'elapsedSeconds':time.monotonic()-started,'podUID':target[2]['podUID']})
            self.pause(2)
    def hold(self,c,name,node,namespace=None):
        st=self.report['clusters'][c];ns=namespace or st['namespace']['metadata']['name']
        return self.create(c,'/api/v1/namespaces/'+ns+'/pods',{'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns},'spec':{'nodeName':node,'serviceAccountName':'api','automountServiceAccountToken':False,'restartPolicy':'Never','terminationGracePeriodSeconds':5,'securityContext':{'runAsUser':65532,'runAsGroup':65532,'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'hold','image':w.r.BUSYBOX_IMAGE,'imagePullPolicy':'Never','command':['/bin/sleep','1800'],'workingDir':'/','securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}})
    def preflight_images(self):
        # Verify local exact binary before any fixture API write. Node config
        # checks below tie that same immutable image content to all four nodes.
        prefix=['podman','--connection',self.args.probe_podman_connection]
        inspect=json.loads(q.bounded(prefix+['image','inspect','sha256:'+self.args.probe_config],timeout=30).stdout)
        need(isinstance(inspect,list) and len(inspect)==1,'one local diagnostic image required')
        image=inspect[0];need(image['Id'].removeprefix('sha256:')==self.args.probe_config and image['Architecture']=='arm64' and image['Os']=='linux','local diagnostic image configuration/platform differs')
        labels=image.get('Labels',image.get('Config',{}).get('Labels',{}))
        need(labels.get('org.opencontainers.image.revision')==self.args.probe_source,'local diagnostic source label differs')
        version=q.bounded(prefix+['run','--rm','--timeout=10','--stop-timeout=1','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1000:0','--workdir=/','--entrypoint='+q.BINARY,'sha256:'+self.args.probe_config,'version'],timeout=30).stdout
        verify_probe_version(version,self.args.probe_source)
        self.save('probe-preflight.json',{'config':self.args.probe_config,'source':self.args.probe_source,'version':version})
        for c in self.apis:
            need(self.get(c,'/api/v1/namespaces/kube-system')['metadata']['uid']==self.pins[c]['clusterUID']==self.issuer['clusterPins'][c],'cluster pin mismatch before mutation')
            nodes=self.get(c,'/api/v1/nodes')['items'];need({n['metadata']['name']:n['metadata']['uid'] for n in nodes}==self.pins[c]['nodes'],'exact node inventory required before mutation')
            for node in self.pins[c]['nodes']:
                self.cri(c,node,self.args.registrar_image,REGISTRAR_CONFIG)
                self.cri(c,node,self.args.probe_image,self.args.probe_config)
    def prepare(self,c):
        st={'created':[],'installationID':str(uuid.uuid4()),'serverPath':'/apis/apps/v1/namespaces/cilium-spire/statefulsets/spire-server'};self.report['clusters'][c]=st;self.flush()
        need(self.get(c,'/api/v1/namespaces/kube-system')['metadata']['uid']==self.pins[c]['clusterUID']==self.issuer['clusterPins'][c],'cluster pin mismatch')
        nodes=self.get(c,'/api/v1/nodes')['items'];need({n['metadata']['name']:n['metadata']['uid'] for n in nodes}==self.pins[c]['nodes'],'exact two-node inventory required')
        for n,uid in self.pins[c]['nodes'].items():need(self.issuer['nodePins'][c+'/'+n]==uid,'issuer ledger node pin mismatch');self.cri(c,n,self.args.registrar_image,REGISTRAR_CONFIG);self.cri(c,n,self.args.probe_image,self.args.probe_config)
        baseline=json.loads((Path(self.args.baselines)/(c+'-server-before.json')).read_text());server=self.get(c,st['serverPath']);need(live(server)['uid']==live(baseline)['uid'] and server['spec']['template']==baseline['spec']['template'],'server baseline drift')
        st.update(serverUID=server['metadata']['uid'],originalTemplate=copy.deepcopy(server['spec']['template']),pvc=self.pvc(c))
        st['beforeSigner']=self.signer(c,'before',registrar=False);st['foreignRows']=self.rows(c);st['meshLabels']=self.get(c,'/api/v1/namespaces/mesh-example')['metadata'].get('labels',{});self.flush()
        namespace=self.create(c,'/api/v1/namespaces',{'apiVersion':'v1','kind':'Namespace','metadata':{'name':'orders-registrar-'+self.short,'labels':{'io.cilium/mtls-enabled':'true'}}});st['namespace']=namespace
        account=self.create(c,'/api/v1/namespaces/'+namespace['metadata']['name']+'/serviceaccounts',{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'api','namespace':namespace['metadata']['name']},'automountServiceAccountToken':False})
        control_ns=self.create(c,'/api/v1/namespaces',{'apiVersion':'v1','kind':'Namespace','metadata':{'name':'control-registrar-'+self.short,'labels':{'io.cilium/mtls-enabled':'true'}}});st['controlNamespace']=control_ns
        control_sa=self.create(c,'/api/v1/namespaces/'+control_ns['metadata']['name']+'/serviceaccounts',{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'api','namespace':control_ns['metadata']['name']},'automountServiceAccountToken':False})
        for i,n in enumerate(self.pins[c]['nodes']):
            self.hold(c,'orders-'+str(i),n)
            self.hold(c,'control-'+str(i),n,namespace=control_ns['metadata']['name'])
        self.poll(lambda:len(self.pods(c,control_ns['metadata']['name']))==2 and all(self.ready(p) for p in self.pods(c,control_ns['metadata']['name'])),seconds=90)
        self.poll(lambda:len(self.pods(c,namespace['metadata']['name']))==2 and all(self.ready(p) for p in self.pods(c,namespace['metadata']['name'])),seconds=90)
        sa_name='registrar-probe-'+self.short;delegate_sa=self.create(c,'/api/v1/namespaces/cilium-spire/serviceaccounts',{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':sa_name,'namespace':NAMESPACE},'automountServiceAccountToken':False})
        node_name=next(iter(self.pins[c]['nodes']));node={'name':node_name,'uid':self.pins[c]['nodes'][node_name]};pod=w.probe_pod(c,node,self.args.probe_image,namespace=NAMESPACE,service_account=sa_name);ps=pod['spec'];ps.pop('nodeName');ps.pop('restartPolicy');ps.pop('activeDeadlineSeconds');ps['restartPolicy']='Always';ps['terminationGracePeriodSeconds']=5;ps['tolerations']=[{'operator':'Exists'}];ps['securityContext']['runAsUser']=self.args.probe_uid;ps['securityContext']['runAsGroup']=self.args.probe_gid;ps['containers'][0]['resources']={'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'128Mi'}}
        ds=self.create(c,'/apis/apps/v1/namespaces/cilium-spire/daemonsets',{'apiVersion':'apps/v1','kind':'DaemonSet','metadata':{'name':sa_name,'namespace':NAMESPACE},'spec':{'selector':{'matchLabels':{'app':sa_name}},'updateStrategy':{'type':'OnDelete'},'template':{'metadata':{'labels':{'app':sa_name,OWNER:self.owner}},'spec':ps}}});st['delegate']=ds;probes=self.wait_daemon(c,ds)
        for node,probe in probes.items():
            version=self.command(c,['exec','-n',NAMESPACE,probe['metadata']['name'],'-c','probe','--',q.BINARY,'version']).stdout
            verify_probe_version(version,self.args.probe_source);self.save(c+'-'+node+'-probe-version.txt',version)
        agent=self.get(c,'/apis/apps/v1/namespaces/cilium-spire/daemonsets/spire-agent');oldagent=json.loads((Path(self.args.baselines)/(c+'-agent-before.json')).read_text());need(live(agent)['uid']==live(oldagent)['uid'],'agent DaemonSet incarnation changed');st['agent']=agent;self.wait_daemon(c,agent)
        ans=self.get(c,'/api/v1/namespaces/cilium-spire');agent_sa=self.get(c,'/api/v1/namespaces/cilium-spire/serviceaccounts/spire-agent')
        options=approval(c,self.pins[c]['clusterUID'],proof.DOMAINS[c],st['installationID'],namespace,account,agent,agent_sa,ds,delegate_sa,ans,extra_namespaces=[(control_ns,control_sa)]);st['approval']=options
        self.rbac(c,options)
        data=canonical(options);config_name='registrar-approval-'+self.short
        self.create(c,'/api/v1/namespaces/cilium-spire/configmaps',{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':config_name,'namespace':NAMESPACE},'immutable':True,'data':{'approval.json':data}})
        self.save(c+'-approval.json',options);self.template(c,st['originalTemplate'],sidecar_template(st['originalTemplate'],self.args.registrar_image,config_name,sha(data.encode())))
        self.server(c,registrar=True);self.flush()
    def rbac(self,c,o):
        suffix='registrar-'+self.short;subject=[{'kind':'ServiceAccount','name':'spire-server','namespace':NAMESPACE}]
        self.create(c,'/apis/rbac.authorization.k8s.io/v1/clusterroles',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':suffix},'rules':[{'apiGroups':[''],'resources':['namespaces'],'resourceNames':sorted({'kube-system',NAMESPACE,*[n['name'] for n in o['namespaces']]}),'verbs':['get']},{'apiGroups':[''],'resources':['nodes'],'resourceNames':sorted(self.pins[c]['nodes']),'verbs':['get']}]})
        self.create(c,'/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding','metadata':{'name':suffix},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':suffix},'subjects':subject})
        for ns in [NAMESPACE,*[n['name'] for n in o['namespaces']]]:
            sas=sorted({o['agent']['serviceAccount'],o['delegate']['serviceAccount']}) if ns==NAMESPACE else sorted(next(n['serviceAccounts'] for n in o['namespaces'] if n['name']==ns))
            rules=[{'apiGroups':[''],'resources':['pods'],'verbs':['get','list']},{'apiGroups':[''],'resources':['serviceaccounts'],'resourceNames':sas,'verbs':['get']}]
            if ns==NAMESPACE:rules.append({'apiGroups':['apps'],'resources':['daemonsets'],'resourceNames':sorted({o['agent']['name'],o['delegate']['name']}),'verbs':['get']})
            self.create(c,'/apis/rbac.authorization.k8s.io/v1/namespaces/'+ns+'/roles',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':suffix,'namespace':ns},'rules':rules})
            self.create(c,'/apis/rbac.authorization.k8s.io/v1/namespaces/'+ns+'/rolebindings',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':suffix,'namespace':ns},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':suffix},'subjects':subject})
    def exercise(self,c):
        st=self.report['clusters'][c];wants,targets=self.fetch_all(c,'initial')
        pairs=pair_controls(targets,st['namespace']['metadata']['name'],st['controlNamespace']['metadata']['name'])
        need(len(wants)==8,'eight exact initial rows required')
        issuer=st['beforeSigner']
        with self.deadline(60):
            self.label(c,False)
            remaining=withdrawal_rows(wants,st['namespace']['metadata']['name'])
            need(len(remaining)==6,'six alias/delegate/control rows required during withdrawal')
            self.wait_rows(c,remaining)
            for target,control in pairs:self.deny_withdrawn(c,target,control,issuer)
        self.label(c,True);self.fetch_all(c,'reenrolled')
        probe,old,oldwanted=pairs[0][0];path='/api/v1/namespaces/'+old['metadata']['namespace']+'/pods/'+old['metadata']['name'];self.delete_owned(c,path,old['metadata']['uid']);replacement=self.hold(c,old['metadata']['name'],old['spec']['nodeName']);need(replacement['metadata']['uid']!=old['metadata']['uid'],'Pod replacement reused UID')
        self.poll(lambda:self.ready(self.get(c,path)),seconds=90);fresh,_=self.fetch_all(c,'pod-replaced');need(oldwanted['entryID'] not in self.owned_rows(c),'old Pod registration survived replacement')
        before=self.server(c,registrar=True);old_uid=before['metadata']['uid'];meta=live(before);self.apis[c].request('DELETE','/api/v1/namespaces/cilium-spire/pods/spire-server-0',{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':old_uid,'resourceVersion':meta['resourceVersion']}})
        after=self.server(c,old_uid=old_uid,registrar=True);need(after['metadata']['uid']!=old_uid,'server restart not observed');need(self.pvc(c)==st['pvc'],'PVC incarnation changed')
        self.fetch_all(c,'server-restarted')
        log=self.command(c,['logs','-n',NAMESPACE,'spire-server-0','-c','cmtc-spire-registrar','--tail=300']).stdout;self.save(c+'-registrar-logs.jsonl',log)
        events=[json.loads(line) for line in log.splitlines() if line.strip().startswith('{')]
        need(any(e.get('stage')=='readback-ack' and isinstance(e.get('attempt'),int) and e['attempt']>=1 and e.get('entries')==8 for e in events),'new registrar lacks fresh startup readback ACK')
        version=self.command(c,['exec','-n',NAMESPACE,'spire-server-0','-c','cmtc-spire-registrar','--','/cmtc-spire-registrar','--version']).stdout.strip();need(version=='cmtc-spire-registrar source='+REVISION,'actual source binary differs');self.save(c+'-registrar-version.txt',version)
        need(self.get(c,'/api/v1/namespaces/mesh-example')['metadata'].get('labels',{})==st['meshLabels'],'foreign application namespace label changed')
    def retire_owned_registrar_pod(self,c,installed):
        """Force a failed StatefulSet revision to roll back after template restore."""
        st=self.report['clusters'][c];server=self.get(c,st['serverPath'])
        need(live(server)['uid']==st['serverUID'] and server['spec']['template']==st['originalTemplate'],'original server template must be restored first')
        path='/api/v1/namespaces/cilium-spire/pods/spire-server-0';pod=self.maybe(c,path)
        if pod is None or pod['metadata'].get('deletionTimestamp'):return
        meta=live(pod);owner=next((x for x in meta.get('ownerReferences',[]) if x.get('controller')),None)
        need(owner and owner['uid']==st['serverUID'] and owner['kind']=='StatefulSet','server Pod controller changed during rollback')
        containers={x['name']:x for x in pod['spec']['containers']}
        if set(containers)=={'spire-server','register-agent-node'}:return
        need(set(containers)=={'spire-server','register-agent-node','cmtc-spire-registrar'},'unknown server rollback profile')
        expected=next(x for x in installed['spec']['containers'] if x['name']=='cmtc-spire-registrar')
        for key in ('image','command','args','securityContext'):
            need(containers['cmtc-spire-registrar'].get(key)==expected[key],'registrar rollback identity differs: '+key)
        log=self.command(c,['logs','-n',NAMESPACE,'spire-server-0','-c','cmtc-spire-registrar','--tail=200'],success=False)
        self.save(c+'-before-rollback-registrar.log',log.stdout+log.stderr)
        self.apis[c].request('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':meta['uid'],'resourceVersion':meta['resourceVersion']}})
        self.emit({'cluster':c,'stage':'exact-owned-revision-rollback','podUID':meta['uid']})
    def cleanup(self):
        for c,st in self.report['clusters'].items():
            try:
                need(not st.get('pendingTemplatePatch'),'ambiguous server template write; preserve dependent fixture for explicit recovery')
                if st.get('installedTemplate') is not None:
                    # Remove the exact fixture delegate first. Its missing pinned
                    # DaemonSet makes the running registrar withdraw all owned
                    # rows while SPIRE still serves the private Admin API. Do not
                    # rely on container shutdown ordering or expiry garbage collection.
                    delegate=st['delegate'];dm=live(delegate)
                    self.delete_owned(c,'/apis/apps/v1/namespaces/cilium-spire/daemonsets/'+dm['name'],dm['uid'])
                    self.poll(lambda:not self.owned_rows(c),seconds=60)
                    installed=st['installedTemplate'];self.template(c,installed,st['originalTemplate']);self.retire_owned_registrar_pod(c,installed);self.server(c,registrar=False)
                    self.poll(lambda:not self.owned_rows(c),seconds=30)
                    after=self.signer(c,'cleanup',registrar=False);need(after['directIssuerSHA256']==st['beforeSigner']['directIssuerSHA256'],'cleanup changed retained signer');need(self.pvc(c)==st['pvc'],'cleanup changed PVC')
                if st.get('foreignRows') is not None:
                    current={e['id']:e for e in self.rows(c)};need(all(current.get(e['id'])==e for e in st['foreignRows']),'foreign registration changed')
                if st.get('pendingCreate'):raise Refusal('ambiguous create response; pending object preserved: '+st['pendingCreate'])
            except Exception as exc:self.report['cleanupErrors'].append({'cluster':c,'stage':'restore-and-withdraw','error':str(exc)});self.flush();continue
            # Reverse order removes read RBAC/config/probe daemon before namespace.
            # A stale same-name object from a prior Pod phase cannot delete the new UID.
            latest={e['path']:e for e in st['created']}
            for e in reversed(list(latest.values())):
                try:self.delete_owned(c,e['path'],e['uid'])
                except Exception as exc:self.report['cleanupErrors'].append({'cluster':c,'stage':'delete-owned','path':e['path'],'error':str(exc)})
            self.flush()
        need(Path(self.args.issuer_ledger).read_bytes()==self.ledger_raw,'issuer producer ledger changed; never reset it')
    def execute(self):
        error=None
        with ExitStack() as stack:
            for c in ('cmtc-a','cmtc-b'):self.apis[c]=stack.enter_context(pki.Proxy(self.args.kubeconfig,'kind-'+c))
            try:
                self.preflight_images()
                for c in self.apis:self.prepare(c)
                for c in self.apis:self.exercise(c)
            except Exception as exc:error=exc;self.report['error']=str(exc)
            finally:
                try:self.cleanup()
                except Exception as exc:self.report['cleanupErrors'].append({'stage':'final','error':str(exc)})
                self.report['qualified']=error is None and not self.report['cleanupErrors'];self.flush()
        if error:raise error
        need(not self.report['cleanupErrors'],'owned cleanup or retained authority audit failed')
        return self.report

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--out',required=True);a.add_argument('--kubeconfig',default='/private/tmp/cmtc-a-b-20261024.kubeconfig');a.add_argument('--cluster-pins',default='/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json');a.add_argument('--issuer-ledger',default=str(Path.home()/'.local/share/cmtc-issuer-profile/live-a-b/ledger.json'));a.add_argument('--baselines',default='/private/tmp/cmtc-exact-registrar-20261025');a.add_argument('--registrar-image',required=True);a.add_argument('--probe-image',required=True);a.add_argument('--probe-config',required=True);a.add_argument('--probe-source',required=True);a.add_argument('--probe-podman-connection',default='cmtc-ubuntu-build');a.add_argument('--probe-uid',type=int,choices=[0,1000],default=1000);a.add_argument('--probe-gid',type=int,choices=[0,1337],default=0)
    args=a.parse_args();validate_probe_pins(args);proof.approved_server_image(args.registrar_image);proof.approved_server_image(args.probe_image)
    Runner(args).execute()
if __name__=='__main__':main()
