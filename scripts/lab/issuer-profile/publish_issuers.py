#!/usr/bin/env python3
"""Persist explicit public issuer approval and enable the existing CMTC producer only.

No native consumer, certificate/key issuance, workload enrollment or datapath changes.
Failure conditionally restores only this tool's exact Deployment template and keeps
all approval/output/permission objects and publication floors for explicit recovery.
"""
import argparse
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

OWNER='security.cmtc.io/live-issuer-owner'
OUTPUT='security.cmtc.io/issuer-profile-output'
INIT='security.cmtc.io/issuer-profile-initialized'
NS='cmtc-system'
DEP='cmtc-controller'
OUT='cmtc-issuer-publication'
ACCESS='cmtc-issuer-profile-access'
ROLLBACK='security.cmtc.io/live-issuer-rollback'
MAX=256*1024
class Refusal(RuntimeError):pass

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def compact(x):
    return json.dumps(x,ensure_ascii=False,separators=(',',':'),allow_nan=False).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e').replace('\u2028','\\u2028').replace('\u2029','\\u2029')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def stamp(t):return t.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
def public(raw):
    if isinstance(raw,str):raw=raw.encode()
    if len(raw)>2*1024*1024 or re.search(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|["\'](?:tls\.key|private_key|privateKey)["\']\s*:',raw):raise Refusal('nonpublic/unbounded material withheld')
    return raw

def meta(o):
    m=o.get('metadata',{})
    if not m.get('uid') or not m.get('resourceVersion') or m.get('deletionTimestamp'):raise Refusal('object is not live UID/RV-bound')
    return m

def owned(o,owner,uid):
    m=meta(o)
    if m['uid']!=uid or m.get('labels',{}).get(OWNER)!=owner or m.get('ownerReferences'):raise Refusal('object ownership/UID mismatch')
    return o

def tests(o):return [{'op':'test','path':'/metadata/uid','value':meta(o)['uid']},{'op':'test','path':'/metadata/resourceVersion','value':meta(o)['resourceVersion']}]

class State:
    """Held private directory, exclusive owner lock, atomic fsynced PUBLIC ledger.

    No unknown UID is adopted, including a create acknowledged by the API but lost
    before its UID was persisted. Such ambiguity needs explicit admin recovery.
    """
    def __init__(self,path,pki):self.path=path;self.pki=pki;self.fd=None;self.lock=None;self.data=None;self.poison=False;self.inode=None;self.lock_inode=None
    def __enter__(self):
        self.fd=self.pki.open_directory(self.path)
        try:
            self.lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.fd)
            st=os.fstat(self.lock)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:raise Refusal('unsafe ledger lock')
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.lock_inode=(st.st_dev,st.st_ino)
            entries=set(os.listdir(self.fd))
            if entries-{'lock','ledger.json'}:raise Refusal('unknown/partial ledger state; explicit recovery required')
            if 'ledger.json' in entries:
                self.data=self.pki.strict_json(public(self.pki.private_file(self.fd,'ledger.json',MAX)))
                st=os.stat('ledger.json',dir_fd=self.fd,follow_symlinks=False);self.inode=(st.st_dev,st.st_ino)
            return self
        except BaseException:self.__exit__(None,None,None);raise
    def save(self):
        if self.poison:raise Refusal('ledger commit is ambiguous; reopen only after explicit inspection')
        raw=public(compact(self.data).encode());name='pending-'+uuid.uuid4().hex
        if len(raw)>MAX:raise Refusal('public ownership ledger exceeds256KiB; preserve state')
        lock_stat=os.stat('lock',dir_fd=self.fd,follow_symlinks=False)
        if (lock_stat.st_dev,lock_stat.st_ino)!=self.lock_inode:raise Refusal('owner lock replaced')
        try:
            old=os.stat('ledger.json',dir_fd=self.fd,follow_symlinks=False)
            if (old.st_dev,old.st_ino)!=self.inode:raise Refusal('ledger inode replaced')
        except FileNotFoundError:
            if self.inode is not None:raise Refusal('recorded ledger disappeared')
        try:
            self.pki.write_private(self.fd,name,raw)
            os.rename(name,'ledger.json',src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
            st=os.stat('ledger.json',dir_fd=self.fd,follow_symlinks=False);self.inode=(st.st_dev,st.st_ino)
        except BaseException:self.poison=True;raise
    def __exit__(self,*_):
        if self.lock is not None:os.close(self.lock);self.lock=None
        if self.fd is not None:os.close(self.fd);self.fd=None

def build_approval(proofs,parents,q,generation,now,horizon):
    if type(generation)is not int or not 1<=generation<2**64 or not 120<=horizon<=86400:raise Refusal('invalid administered generation/horizon')
    if set(proofs)!={'cmtc-a','cmtc-b'} or set(parents)!=set(proofs):raise Refusal('both exact clusters required')
    roots={};clusters=[];keys=set();rolekeys=set()
    expiry=now+dt.timedelta(seconds=horizon)
    for cluster in sorted(proofs):
        p=proofs[cluster];parent,root=parents[cluster]
        if p['cluster']!=cluster or p['domain']!=q.DOMAINS[cluster] or p['protected'] is not False or p['workloadAttestation'] is not False or p['source']!='authenticated-kubernetes-exec-local-SPIRE-admin-API-nonce-mint':raise Refusal('wrong public proof source/binding')
        observed=dt.datetime.fromisoformat(p['observedAt'])
        if not -2<=(now-observed).total_seconds()<=90:raise Refusal('active proof is not fresh')
        signer_chain=q.certs(p['directIssuerPEM'])
        if len(signer_chain)!=1:raise Refusal('proof direct issuer must be exactly one certificate')
        signer=signer_chain[0]
        from cryptography import x509
        if list(q.ext(signer,x509.SubjectAlternativeName).value)!=[x509.UniformResourceIdentifier('spiffe://'+q.DOMAINS[cluster])]:raise Refusal('proof signer domain mismatch')
        if q.sha(q.der(signer))!=p['directIssuerSHA256'] or p['parentPEM']!=q.pem(parent) or p['rootSHA256']!=q.sha(q.der(root)):raise Refusal('public proof material/pins differ')
        q.ca(root,2,now);q.ca(parent,1,now);q.ca(signer,'signer',now,True);q.issued(signer,parent);q.issued(parent,root);q.issued(root,root)
        k=q.sha(q.spki(signer));pk=q.sha(q.spki(parent));rk=q.sha(q.spki(root))
        if k in keys or k in rolekeys or pk in keys or pk in rolekeys or rk in keys or len({k,pk,rk})!=3:raise Refusal('cross-cluster issuer/parent key reuse')
        keys.add(k);rolekeys.add(pk);rolekeys.add(rk)
        pin=q.sha(q.der(root));roots[pin]={'certificatePEM':q.pem(root),'sha256':pin}
        expiry=min(expiry,signer.not_valid_after_utc,parent.not_valid_after_utc,root.not_valid_after_utc)
        clusters.append({'clusterID':cluster,'trustDomain':q.DOMAINS[cluster],'issuers':[{'certificatePEM':q.pem(signer),'chainPEM':q.pem(parent),'spkiSHA256':k,'rootSHA256':pin}]})
    if len(roots)!=1 or (expiry-now).total_seconds()<120:raise Refusal('one common approved root and at least120seconds remaining required')
    approval={'schemaVersion':1,'generation':generation,'expiresAt':stamp(expiry),'roots':list(roots.values()),'clusters':clusters}
    if len(compact(approval).encode())>65536:raise Refusal('approval size bound')
    return approval

def same_material(a,b):
    return {k:a[k] for k in ('schemaVersion','generation','roots','clusters')}=={k:b[k] for k in ('schemaVersion','generation','roots','clusters')}

def enabled_template(baseline,owner,cluster,source,source_uid,output_uid,root_pin,generation):
    t=copy.deepcopy(baseline);spec=t.get('spec',{});cs=spec.get('containers',[])
    if spec.get('serviceAccountName')!='cmtc-controller' or len(cs)!=1 or cs[0].get('name')!='controller' or '--cluster-name='+cluster not in cs[0].get('args',[]):raise Refusal('unexpected controller topology/cluster')
    if any(x.startswith('--issuer-profile') for x in cs[0].get('args',[])) or OWNER in t.get('metadata',{}).get('annotations',{}):raise Refusal('baseline already configures an issuer producer/owner')
    t.setdefault('metadata',{}).setdefault('annotations',{})[OWNER]=owner
    cs[0]['args']=list(cs[0].get('args',[]))+['--issuer-profile-producer=true','--issuer-profile-namespace='+NS,'--issuer-profile-source='+source,'--issuer-profile-output='+OUT,'--issuer-profile-source-uid='+source_uid,'--issuer-profile-output-uid='+output_uid,'--issuer-profile-root-sha256='+root_pin,'--issuer-profile-minimum-generation='+str(generation)]
    return t

def template_patch(deployment,uid,expected,desired):
    if meta(deployment)['uid']!=uid or deployment['spec']['template']!=expected:raise Refusal('Deployment identity/template drift; no takeover')
    return tests(deployment)+[{'op':'test','path':'/spec/template','value':expected},{'op':'replace','path':'/spec/template','value':desired}]

def check_floor(current,previous):
    if previous is None:return
    if current['sequence']<previous['sequence'] or current['acceptedGeneration']<previous['acceptedGeneration']:raise Refusal('recorded publication floor rollback')
    if current['sequence']==previous['sequence'] and current['digest']!=previous['digest']:raise Refusal('same-sequence publication changed')
    if current['acceptedGeneration']==previous['acceptedGeneration'] and any(current.get(k)!=previous.get(k) for k in ('acceptedSourceUID','acceptedApprovalDigest')):raise Refusal('same-generation accepted identity changed')

class Publisher:
    def __init__(self,args,pki,q,publication,state,apis):
        self.a=args;self.pki=pki;self.q=q;self.decode_publication=publication;self.s=state;self.apis=apis;self.started=time.time();self.command_attempt=0
    def command(self,argv,timeout=25):
        self.command_attempt+=1;started=time.monotonic()
        try:p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        except subprocess.TimeoutExpired as e:raise Refusal('bounded public command timed out') from e
        public(p.stdout);public(p.stderr)
        if p.returncode:
            diagnostic=p.stderr.decode(errors='replace')[-1000:]
            raise Refusal('public command failed ('+str(p.returncode)+'): '+diagnostic)
        return p.stdout
    def cm_path(self,name):return '/api/v1/namespaces/'+NS+'/configmaps/'+name
    def get_optional(self,api,path):
        try:return api.get(path)
        except self.pki.APIError as e:
            if e.status==404:return None
            raise
    def owned_object(self,cluster,kind,name,body):
        c=self.s.data['clusters'][cluster];api=self.apis[cluster]
        prefix='/api/v1' if kind=='ConfigMap' else '/apis/rbac.authorization.k8s.io/v1'
        plural={'ConfigMap':'configmaps','Role':'roles','RoleBinding':'rolebindings'}[kind]
        collection=prefix+'/namespaces/'+NS+'/'+plural;path=collection+'/'+name
        record=kind+'/'+name;uid=c['uids'].get(record)
        current=self.get_optional(api,path)
        if uid:
            if current is None:raise Refusal('recorded public object missing; never recreate '+record)
            owned(current,self.s.data['owner'],uid)
            if current.get('kind')!=kind or current['metadata'].get('name')!=name or current['metadata'].get('namespace')!=NS:raise Refusal('owned public API object identity differs '+record)
            if kind=='ConfigMap' and current.get('binaryData'):raise Refusal('unexpected binary ConfigMap data '+record)
            if kind=='ConfigMap' and name==OUT:
                if current.get('immutable') is True or current.get('binaryData') or current.get('metadata',{}).get('labels',{}).get(OUTPUT)!='true' or set(current.get('data',{}))-{'profile.json'}:raise Refusal('foreign output shape')
                raw=current.get('data',{}).get('profile.json')
                if raw:
                    # An expired lease is persisted antirollback history, never an active grant.
                    parsed=self.pki.strict_json(raw)
                    checkpoint_time=dt.datetime.fromisoformat(parsed['publishedAt'].replace('Z','+00:00')).timestamp()+0.001
                    stored=self.decode_publication(raw,cluster,uid,now=checkpoint_time)
                    check_floor(stored,c.get('lastPublication'))
                elif current['metadata'].get('annotations',{}).get(INIT)=='true':raise Refusal('initialized output cleared; explicit repair required')
            else:
                for field in ('data','immutable','rules','roleRef','subjects'):
                    if current.get(field)!=body.get(field):raise Refusal('owned public object content drift '+record)
            return current
        if current is not None:raise Refusal('preexisting or unrecorded object; refuse adoption '+record)
        obj=copy.deepcopy(body);obj.update(apiVersion='v1' if kind=='ConfigMap' else 'rbac.authorization.k8s.io/v1',kind=kind)
        obj['metadata']={'name':name,'namespace':NS,'labels':{**body.get('metadata',{}).get('labels',{}),OWNER:self.s.data['owner']}}
        # Record the intended object BEFORE create. Unknown outcomes still never adopt.
        c['pendingCreate']=record;self.s.save()
        made=api.request('POST',collection,obj);uid=meta(made)['uid'];owned(made,self.s.data['owner'],uid)
        c['uids'][record]=uid;c.pop('pendingCreate',None);self.s.save()
        # Admission/defaulting or a concurrent write may differ from the POST body.
        # Re-read and verify the exact acknowledged UID and intended shape before use.
        return self.owned_object(cluster,kind,name,body)
    def inspect_image(self,cluster,node):
        api=self.apis[cluster]
        if meta(api.get('/api/v1/nodes/'+node))['uid']!=self.a.node_pins[cluster+'/'+node]:raise Refusal('node identity changed before exact image inspection')
        raw=self.command(['colima','ssh','--profile',self.a.colima_profile,'--','docker','exec',node,'crictl','inspecti',self.a.image])
        image=json.loads(raw);spec=image.get('info',{}).get('imageSpec',{});cri=image['status']
        if cri.get('id')!=self.a.image_config or spec.get('architecture')!='arm64' or spec.get('config',{}).get('Labels',{}).get('org.opencontainers.image.revision')!=self.a.source_sha:raise Refusal('actual image config/source/architecture differs')
        return cri
    def preflight(self,cluster):
        api=self.apis[cluster];c=self.s.data['clusters'][cluster]
        if meta(api.get('/api/v1/namespaces/kube-system'))['uid']!=self.a.cluster_pins[cluster]:raise Refusal('cluster UID mismatch')
        for node in (cluster+'-worker',cluster+'-control-plane'):self.inspect_image(cluster,node)
        d=api.get('/apis/apps/v1/namespaces/'+NS+'/deployments/'+DEP)
        if meta(d)['uid']!=self.a.deployment_pins[cluster] or d['spec'].get('replicas',1)!=1:raise Refusal('controller Deployment UID/topology mismatch')
        sa=api.get('/api/v1/namespaces/'+NS+'/serviceaccounts/cmtc-controller');uid=meta(sa)['uid']
        if c.get('saUID') not in (None,uid):raise Refusal('controller SA replaced')
        c['saUID']=uid
        if 'baseline' not in c:
            baseline=copy.deepcopy(d['spec']['template']);container=baseline['spec']['containers'][0]
            if container.get('image')!=self.a.image:raise Refusal('existing controller image differs; this helper never changes images')
            enabled_template(baseline,self.s.data['owner'],cluster,'preflight','a','b',self.a.root_sha256,self.a.generation)
            c.update(baseline=baseline,deploymentUID=meta(d)['uid']);self.s.save()
        if d['spec']['template'] not in (c['baseline'],c.get('active')):raise Refusal('unowned Deployment template')
        return d
    def fresh_proofs(self):
        server_image=self.q.approved_server_image(getattr(self.a,'spire_server_image',self.q.SERVER_IMAGE))
        proofs={};parents={}
        for cluster in sorted(self.apis):
            api=self.apis[cluster];self.preflight(cluster)
            pod=api.get('/api/v1/namespaces/cilium-spire/pods/spire-server-0')
            proofs[cluster]=self.q.execute_proof(api,cluster=cluster,cluster_uid=self.a.cluster_pins[cluster],pod_uid=meta(pod)['uid'],approval_uid=self.a.approval_pins[cluster],root_pin=self.a.root_sha256,server_image=server_image)
            if proofs[cluster].get('approvedServerImage')!=server_image:raise Refusal('proof did not retain the independent approved server image pin')
            approval=api.get('/api/v1/namespaces/cert-manager/configmaps/cmtc-spire-cluster-ca-approval')
            parents[cluster]=self.q.approved_parent(approval,uid=self.a.approval_pins[cluster],cluster=cluster,root_pin=self.a.root_sha256,now=dt.datetime.now(dt.timezone.utc))
        approval=build_approval(proofs,parents,self.q,self.a.generation,dt.datetime.now(dt.timezone.utc),self.a.horizon)
        old=self.s.data.get('approval')
        if old:
            if not same_material(old,approval) or dt.datetime.fromisoformat(old['expiresAt'].replace('Z','+00:00'))<=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=120):raise Refusal('recorded approval expired/material changed; explicit higher-generation workflow required')
        else:self.s.data['approval']=approval
        self.s.data['freshProofs']=proofs;self.s.save()
    def rbac(self,cluster,source):
        body={'rules':[{'apiGroups':[''],'resources':['configmaps'],'resourceNames':[source],'verbs':['get']},{'apiGroups':[''],'resources':['configmaps'],'resourceNames':[OUT],'verbs':['get','update']}]}
        self.owned_object(cluster,'Role',ACCESS,body)
        self.owned_object(cluster,'RoleBinding',ACCESS,{'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':ACCESS},'subjects':[{'kind':'ServiceAccount','name':'cmtc-controller','namespace':NS}]})
        api=self.apis[cluster];checks=[('get','configmap/'+source,True),('get','configmap/'+OUT,True),('update','configmap/'+OUT,True),('update','configmap/'+source,False),('update','configmap/cmtc-live-issuer-foreign',False),('list','configmaps',False),('watch','configmaps',False),('create','configmaps',False),('delete','configmap/'+OUT,False),('patch','configmap/'+source,False),('patch','configmap/'+OUT,False),('patch','configmap/cmtc-live-issuer-foreign',False),('deletecollection','configmaps',False),('get','secret/cmtc-live-issuer-never-created',False),('list','secrets',False),('watch','secrets',False),('create','secrets',False),('update','secret/cmtc-live-issuer-never-created',False),('patch','secret/cmtc-live-issuer-never-created',False),('delete','secret/cmtc-live-issuer-never-created',False),('deletecollection','secrets',False)]
        results=[]
        for verb,res,want in checks:
            argv=api.argv+['-n',NS,'auth','can-i',verb,res,'--as=system:serviceaccount:'+NS+':cmtc-controller','--as-group=system:serviceaccounts','--as-group=system:serviceaccounts:'+NS,'--as-group=system:authenticated','--request-timeout=12s']
            p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
            if p.stdout.strip()!=(b'yes' if want else b'no') or p.returncode not in (0,1):raise Refusal('effective SA permission differs from exact contract: '+verb+' '+res)
            results.append({'verb':verb,'resource':res,'allowed':want})
        self.s.data['clusters'][cluster]['rbac']=results;self.s.save()
    def patch_template(self,cluster,expected,desired):
        api=self.apis[cluster];c=self.s.data['clusters'][cluster];path='/apis/apps/v1/namespaces/'+NS+'/deployments/'+DEP
        d=api.get(path);ops=template_patch(d,c['deploymentUID'],expected,desired)
        self.command(api.argv+['-n',NS,'patch','deployment',DEP,'--type=json','-p',compact(ops),'--request-timeout=12s'])
        again=api.get(path)
        if meta(again)['uid']!=c['deploymentUID'] or again['spec']['template']!=desired:raise Refusal('Deployment patch acknowledgment differs')
    def runtime(self,cluster,template):
        api=self.apis[cluster];c=self.s.data['clusters'][cluster];deadline=time.monotonic()+150
        while time.monotonic()<deadline:
            d=api.get('/apis/apps/v1/namespaces/'+NS+'/deployments/'+DEP)
            if meta(d)['uid']!=c['deploymentUID'] or d['spec']['template']!=template:raise Refusal('controller template changed during rollout')
            pods=api.get('/api/v1/namespaces/'+NS+'/pods?'+urllib.parse.urlencode({'labelSelector':'app.kubernetes.io/name=cmtc-controller'}))['items']
            found=[]
            for p in pods:
                if p.get('metadata',{}).get('deletionTimestamp'):continue
                refs=p.get('metadata',{}).get('ownerReferences',[])
                if len(refs)!=1 or refs[0].get('kind')!='ReplicaSet':continue
                rs=api.get('/apis/apps/v1/namespaces/'+NS+'/replicasets/'+refs[0]['name'])
                if meta(rs)['uid']!=refs[0]['uid'] or not any(r.get('kind')=='Deployment' and r.get('uid')==c['deploymentUID'] for r in rs['metadata'].get('ownerReferences',[])):continue
                if p.get('metadata',{}).get('annotations',{}).get(OWNER)!=self.s.data['owner'] and template!=c['baseline']:continue
                cs=p.get('status',{}).get('containerStatuses',[])
                if len(cs)==1 and cs[0].get('ready') and p.get('status',{}).get('podIP') and p['spec']['containers'][0]['image']==self.a.image and p['spec']['containers'][0].get('args',[])==template['spec']['containers'][0].get('args',[]):found.append(p)
            status=d.get('status',{})
            if len(found)==1 and status.get('observedGeneration',0)>=d['metadata'].get('generation',0) and status.get('updatedReplicas')==1 and status.get('readyReplicas')==1 and status.get('replicas')==1:
                p=found[0];node=p['spec']['nodeName'];nodeuid=meta(api.get('/api/v1/nodes/'+node))['uid']
                if self.a.node_pins.get(cluster+'/'+node)!=nodeuid:raise Refusal('controller node UID differs from independent pin')
                raw=self.command(['colima','ssh','--profile',self.a.colima_profile,'--','docker','exec',node,'crictl','inspecti',self.a.image])
                image=json.loads(raw);spec=image.get('info',{}).get('imageSpec',{});cri=image['status']
                if cri.get('id')!=self.a.image_config or spec.get('architecture')!='arm64' or spec.get('config',{}).get('Labels',{}).get('org.opencontainers.image.revision')!=self.a.source_sha:raise Refusal('actual running image config/source/architecture differs')
                running=p['status']['containerStatuses'][0]['imageID'].split('://',1)[-1].rsplit('@',1)[-1]
                if running not in {x.rsplit('@',1)[-1] for x in cri.get('repoDigests',[])} or not re.fullmatch('sha256:[0-9a-f]{64}',running):raise Refusal('runtime imageID is not a manifest of exact CRI image')
                c['runtime']={'podUID':meta(p)['uid'],'podName':p['metadata']['name'],'podIP':p['status']['podIP'],'containerID':p['status']['containerStatuses'][0]['containerID'],'imageID':p['status']['containerStatuses'][0]['imageID'],'imageConfig':cri['id'],'sourceRevision':self.a.source_sha,'nodeUID':nodeuid};self.s.save();return p
            time.sleep(1)
        raise Refusal('exact existing controller rollout timed out')
    def read_publication(self,cluster,source):
        api=self.apis[cluster];c=self.s.data['clusters'][cluster]
        out=owned(api.get(self.cm_path(OUT)),self.s.data['owner'],c['uids']['ConfigMap/'+OUT])
        raw=out.get('data',{}).get('profile.json')
        if not raw:
            if out['metadata'].get('annotations',{}).get(INIT)=='true' or c.get('lastPublication'):raise Refusal('initialized publication erased')
            return None
        p=self.decode_publication(raw,cluster,meta(out)['uid'])
        src=owned(api.get(self.cm_path(source)),self.s.data['owner'],c['uids']['ConfigMap/'+source])
        wanted={'namespace':NS,'name':source,'uid':meta(src)['uid'],'resourceVersion':meta(src)['resourceVersion'],'generation':self.a.generation}
        if p['state']!='published' or p.get('reason')!='Validated' or p.get('source')!=wanted or p.get('expectedSourceUID')!=meta(src)['uid'] or p.get('acceptedGeneration')!=self.a.generation or p.get('approval')!=self.s.data['approval']:raise Refusal('publication is not exact current approved source/generation')
        previous=c.get('lastPublication')
        check_floor(p,previous)
        again=api.get(self.cm_path(OUT))
        if meta(again)['uid']!=meta(out)['uid']:raise Refusal('output UID replacement')
        if meta(again)['resourceVersion']!=meta(out)['resourceVersion']:return None
        c['lastPublication']=p;c['lastOutputRV']=meta(out)['resourceVersion'];self.s.save();return p
    def publications(self,cluster,source):
        deadline=time.monotonic()+70;first=None
        while time.monotonic()<deadline:
            p=self.read_publication(cluster,source)
            if p:
                if first is None:first=p
                elif p['sequence']>first['sequence'] and p['validUntil']>first['validUntil']:
                    if any(p.get(k)!=first.get(k) for k in ('approvalDigest','acceptedGeneration','acceptedSourceUID','acceptedApprovalDigest')):raise Refusal('renewal changed approval identity')
                    c=self.s.data['clusters'][cluster];c['renewal']={'firstSequence':first['sequence'],'renewedSequence':p['sequence'],'firstValidUntil':first['validUntil'],'renewedValidUntil':p['validUntil']};self.s.save();return
            time.sleep(1)
        raise Refusal('current publication/renewal timed out')
    def metrics_logs(self,cluster):
        c=self.s.data['clusters'][cluster];pod=c['runtime'];api=self.apis[cluster]
        names=['cmtc_issuer_profile_validation_attempts_total','cmtc_issuer_profile_publication_writes_total','cmtc_issuer_profile_source_checked_timestamp_seconds','cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds','cmtc_enforcement_available']
        base=self.a.prometheus[cluster].rstrip('/');selector='{job="cmtc",component="cmtc-controller",cluster="'+cluster+'",instance="'+pod['podIP']+':8080"}'
        evidence=[];deadline=time.monotonic()+50
        while time.monotonic()<deadline:
            evidence=[];good=True
            for name in names:
                query=name+selector
                with urllib.request.urlopen(base+'/api/v1/query?'+urllib.parse.urlencode({'query':query}),timeout=10) as r:obj=json.loads(r.read(MAX+1))
                if obj.get('status')!='success' or obj.get('data',{}).get('resultType')!='vector':raise Refusal('Prometheus query failure')
                rows=obj['data']['result'];evidence.append({'query':query,'response':obj})
                if not rows:good=False;continue
                vals=[float(x['value'][1]) for x in rows]
                if name=='cmtc_enforcement_available' and any(v!=0 for v in vals):raise Refusal('Observe enforcement changed')
                if name.endswith('attempts_total') and not any(x['metric'].get('result')=='accepted' and float(x['value'][1])>0 for x in rows):good=False
                if name.endswith('writes_total') and not any(x['metric'].get('state')=='published' and x['metric'].get('result')=='acknowledged' and float(x['value'][1])>=2 for x in rows):good=False
                if name.endswith('source_checked_timestamp_seconds') and any(not 0<=time.time()-v<20 for v in vals):good=False
                if name.endswith('valid_until_timestamp_seconds') and any(not time.time()<v<=time.time()+31 for v in vals):good=False
            if good:break
            time.sleep(1)
        if not good:raise Refusal('actual producer metrics not fresh/nonzero on exact current controller instance')
        logs=public(self.command(api.argv+['-n',NS,'logs',pod['podName'],'-c','controller','--tail=1000','--limit-bytes=524288','--request-timeout=12s'])).decode()
        records=[]
        for line in logs.splitlines():
            try:o=json.loads(line)
            except ValueError:continue
            if o.get('component')=='issuer-profile-producer':records.append(o)
        if not any(r.get('stage')=='publish' and r.get('state')=='published' and r.get('reason')=='Validated' and 'attempt'in r and 'elapsed'in r and 'deadline'in r for r in records):raise Refusal('actual structured publication boundary log absent')
        live=api.get('/api/v1/namespaces/'+NS+'/pods/'+pod['podName'])
        cs=live.get('status',{}).get('containerStatuses',[])
        if meta(live)['uid']!=pod['podUID'] or len(cs)!=1 or cs[0].get('containerID')!=pod['containerID'] or not cs[0].get('ready'):raise Refusal('controller process changed during evidence collection')
        c['metrics']=evidence;c['producerLogs']=records[-16:];self.s.save()
    def enable(self,cluster):
        api=self.apis[cluster];c=self.s.data['clusters'][cluster];source='cmtc-issuer-approval-g'+str(self.a.generation)
        src=self.owned_object(cluster,'ConfigMap',source,{'immutable':True,'data':{'approval.json':compact(self.s.data['approval'])}})
        out=self.owned_object(cluster,'ConfigMap',OUT,{'metadata':{'labels':{OUTPUT:'true'}},'data':{}})
        self.rbac(cluster,source)
        # Image/RBAC/rollout steps can outlast the original challenge window.
        # Reconfirm BOTH exact approved current signers immediately before enabling.
        self.fresh_proofs()
        desired=enabled_template(c['baseline'],self.s.data['owner'],cluster,source,meta(src)['uid'],meta(out)['uid'],self.a.root_sha256,self.a.generation)
        # Save desired intent BEFORE patch so an unknown patch acknowledgment can be recovered.
        c['active']=desired;c['phase']='enable-intended';self.s.save()
        d=self.preflight(cluster)
        if d['spec']['template']==c['baseline']:self.patch_template(cluster,c['baseline'],desired)
        self.runtime(cluster,desired);self.publications(cluster,source);self.metrics_logs(cluster)
        c['phase']='publication-qualified-no-consumer';self.s.save()
    def disable_owned(self,cluster):
        c=self.s.data['clusters'][cluster]
        if not c.get('active'):return
        api=self.apis[cluster];d=api.get('/apis/apps/v1/namespaces/'+NS+'/deployments/'+DEP)
        if meta(d)['uid']!=c['deploymentUID']:raise Refusal('cannot disable replaced Deployment')
        current=d['spec']['template']
        if current not in (c['baseline'],c['active'],c.get('rollbackTemplate')):raise Refusal('cannot disable foreign Deployment template')
        # Always make a real resourceVersion-changing write, even if the API GET
        # sees baseline. A timed-out original enable PATCH can still commit later
        # against its old RV unless a distinct successful CAS fences it first.
        fence=copy.deepcopy(c['baseline'])
        fence.setdefault('metadata',{}).setdefault('annotations',{}).update({OWNER:self.s.data['owner'],ROLLBACK:uuid.uuid4().hex})
        c['rollbackTemplate']=fence;c['phase']='disable-intended'
        ledger_error=None
        if not self.s.poison:
            try:self.s.save()
            except Exception as error:ledger_error=type(error).__name__
        self.patch_template(cluster,current,fence)
        self.patch_template(cluster,fence,c['baseline'])
        self.runtime(cluster,c['baseline'])
        # No object deletion/output reset. Existing leases naturally expire within30s.
        c.pop('rollbackTemplate',None);c['phase']='disabled-after-failure'
        if not self.s.poison:self.s.save()
        if ledger_error:raise Refusal('controller disabled but rollback ledger commit failed: '+ledger_error)
    def run(self):
        try:
            self.s.data['success']=False
            # Finish only an already-recorded owned rollback before fresh activation.
            for cluster in sorted(self.apis):
                if self.s.data['clusters'][cluster].get('rollbackTemplate'):self.disable_owned(cluster)
            self.fresh_proofs()
            for cluster in sorted(self.apis):self.enable(cluster)
            self.fresh_proofs()
            self.s.data.update(success=True,scope='public issuer mapping publication only; native consumer disabled; no TLS/Protected');self.s.save()
        except BaseException as error:
            self.s.data['success']=False
            cleanup=[]
            for cluster in sorted(self.apis):
                try:self.disable_owned(cluster)
                except Exception as failure:cleanup.append({'cluster':cluster,'failure':type(failure).__name__})
            if not self.s.poison:
                try:
                    self.s.data.update(failure=type(error).__name__,conditionalDisableFailures=cleanup);self.s.save()
                except Exception as failure:cleanup.append({'stage':'failure-ledger','failure':type(failure).__name__})
            if cleanup:error.add_note('Conditional recovery failures: '+compact(cleanup))
            raise

def pairs(values,expected):
    result={}
    for value in values:
        k,sep,v=value.partition('=')
        if not sep or not v or k in result:raise Refusal('duplicate/invalid explicit pin')
        result[k]=v
    if set(result)!=set(expected):raise Refusal('exact pin set required')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig','state-dir','root-sha256','image','image-config','source-sha','pki-module','proof-module','publication-module'):p.add_argument('--'+name,required=True)
    for name in ('cluster-pin','approval-pin','deployment-pin','node-pin'):p.add_argument('--'+name,action='append',required=True)
    p.add_argument('--server-image',dest='spire_server_image',default=None,help='Independent approved digest-qualified SPIRE server/CLI image; first verify source/config and all-node CRI imports')
    p.add_argument('--generation',type=int,required=True);p.add_argument('--horizon',type=int,default=3600)
    p.add_argument('--colima-profile',default='cmtc-cilium');p.add_argument('--prometheus-a',default='http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom');p.add_argument('--prometheus-b',default='http://127.0.0.1:19091')
    a=p.parse_args();clusters=['cmtc-a','cmtc-b']
    a.cluster_pins=pairs(a.cluster_pin,clusters);a.approval_pins=pairs(a.approval_pin,clusters);a.deployment_pins=pairs(a.deployment_pin,clusters)
    a.node_pins=pairs(a.node_pin,[c+'/'+c+'-'+n for c in clusters for n in ('worker','control-plane')]);a.prometheus={'cmtc-a':a.prometheus_a,'cmtc-b':a.prometheus_b}
    if not re.fullmatch('[0-9a-f]{64}',a.root_sha256) or not re.fullmatch('sha256:[0-9a-f]{64}',a.image_config) or not re.fullmatch('[0-9a-f]{40}',a.source_sha):p.error('exact root/config/source pins required')
    pki=load(a.pki_module,'accepted_pki');q=load(a.proof_module,'accepted_public_proof');lab=load(a.publication_module,'accepted_publication_parser')
    a.spire_server_image=q.approved_server_image(a.spire_server_image if a.spire_server_image is not None else q.SERVER_IMAGE)
    identity={'spireServerImage':a.spire_server_image,'schemaVersion':1,'rootSHA256':a.root_sha256,'generation':a.generation,'clusterPins':a.cluster_pins,'approvalPins':a.approval_pins,'deploymentPins':a.deployment_pins,'nodePins':a.node_pins,'image':a.image,'imageConfig':a.image_config,'sourceRevision':a.source_sha}
    with State(a.state_dir,pki) as state,contextlib.ExitStack() as stack:
        if state.data is None:state.data={'identity':identity,'owner':uuid.uuid4().hex,'clusters':{c:{'uids':{}} for c in clusters}};state.save()
        elif state.data.get('identity')!=identity:raise Refusal('ledger identity differs; no automatic rotation/reassignment')
        apis={c:stack.enter_context(pki.Proxy(a.kubeconfig,'kind-'+c)) for c in clusters}
        Publisher(a,pki,q,lab.publication,state,apis).run()
    print(json.dumps({'success':True,'ledger':str(Path(a.state_dir)/'ledger.json'),'scope':'public mapping publication only; consumer remains disabled'},indent=2))
if __name__=='__main__':main()
