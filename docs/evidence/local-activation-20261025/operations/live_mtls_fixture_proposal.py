#!/usr/bin/env python3
"""UNRUN operational test proposal. No action without --execute. No product source edits."""
import argparse, json, subprocess, time, uuid, re, socket, urllib.request, base64
from pathlib import Path
from datetime import datetime, timezone
K='/private/tmp/cmtc-a-b-20261024.kubeconfig'
NS='cmtc-live-mtls'; NEG=NS+'-unauth'; OWNER='cmtc-primary-live-mtls-20261025'
PINS={'cmtc-a':'bb7182c7-de95-4e70-816a-a1400d755794','cmtc-b':'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
PORTS=(80,8080,31337)
def require(x,msg):
 if not x: raise RuntimeError(msg)
def now(): return datetime.now(timezone.utc).isoformat()
class Lab:
 def __init__(self,a):
  self.a=a; self.run=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'); self.out=Path(a.out); self.out.mkdir(parents=True,exist_ok=True)
 def k(self,c,*args,body=None,check=True):
  r=subprocess.run(['kubectl','--kubeconfig',K,'--context','kind-'+c,*args],input=body,text=True,capture_output=True,timeout=180)
  require('PRIVATE KEY' not in r.stdout+r.stderr,'Unsafe private material suppressed')
  if check: require(r.returncode==0,'kubectl '+str(args[:4])+': '+r.stderr[:3000])
  return r
 def get(self,c,*args):return json.loads(self.k(c,*args,'-o','json').stdout)
 def save(self,name,obj):
  p=self.out/name;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_text(obj if isinstance(obj,str) else json.dumps(obj,indent=2)+'\n')
 def check(self,c):
  require(self.get(c,'get','ns','kube-system')['metadata']['uid']==PINS[c],'Cluster UID mismatch')
 def owned(self,c,ns):
  n=self.get(c,'get','ns',ns);require(n['metadata'].get('labels',{}).get('security.cmtc.io/test-owner')==OWNER,'Foreign namespace')
  pin=self.out/(c+'-'+ns+'-uid')
  require(pin.exists() and pin.read_text().strip()==n['metadata']['uid'],'Namespace incarnation mismatch')
  return n
 def create(self,c):
  self.check(c)
  for ns in [NS,NEG]:
   old=self.k(c,'get','ns',ns,'-o','name',check=False)
   require(old.returncode!=0,'Namespace already exists; use existing run ledger, do not take over')
   self.k(c,'create','-f','-',body=json.dumps({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns,'labels':{'security.cmtc.io/test-owner':OWNER}}}))
   n=self.get(c,'get','ns',ns);self.save(c+'-'+ns+'-uid',n['metadata']['uid'])
  d=self.get(c,'-n','mesh-example','get','deploy','rebel-base')['spec']['template']['spec']
  require(len(d['containers'])==1 and d['containers'][0]['image']=='nginx:1.27-alpine','Unexpected app image')
  require({v['name'] for v in d['volumes']}=={'html','nginx-conf'} and all('configMap'in v for v in d['volumes']),'Only public app ConfigMaps permitted')
  objs=[]
  for v in d['volumes']:
   cm=self.get(c,'-n','mesh-example','get','cm',v['configMap']['name'])
   objs.append({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':cm['metadata']['name'],'namespace':NS},'data':cm.get('data',{})})
  for sa in ['rebel-base','mesh-client']:
   objs.append({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':sa,'namespace':NS},'automountServiceAccountToken':False})
  objs.append({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'unregistered','namespace':NEG},'automountServiceAccountToken':False})
  for suffix in ['worker','control-plane']:
   node=c+'-'+suffix
   for role in ['server','client']:
    ct=json.loads(json.dumps(d['containers'][0])) if role=='server' else {'name':'client','image':'curlimages/curl:8.14.1','imagePullPolicy':'IfNotPresent','command':['sh','-c','sleep 86400']}
    sp={'nodeName':node,'serviceAccountName':'rebel-base' if role=='server' else 'mesh-client','automountServiceAccountToken':False,'containers':[ct],'terminationGracePeriodSeconds':5}
    if role=='server':sp['volumes']=d['volumes']
    objs.append({'apiVersion':'v1','kind':'Pod','metadata':{'name':role+'-'+suffix,'namespace':NS,'labels':{'security.cmtc.io/test-owner':OWNER,'test-role':role,'serving-cluster':c}},'spec':sp})
   objs.append({'apiVersion':'v1','kind':'Pod','metadata':{'name':'unregistered-'+suffix,'namespace':NEG,'labels':{'security.cmtc.io/test-owner':OWNER}},'spec':{'nodeName':node,'serviceAccountName':'unregistered','automountServiceAccountToken':False,'containers':[{'name':'client','image':'curlimages/curl:8.14.1','imagePullPolicy':'IfNotPresent','command':['sh','-c','sleep 86400']}]}})
  # Global services exist on BOTH clusters; each selects one explicitly named serving cluster.
  for dest in PINS:
   objs.append({'apiVersion':'v1','kind':'Service','metadata':{'name':'server-'+dest,'namespace':NS,'annotations':{'service.cilium.io/global':'true'}},'spec':{'selector':{'test-role':'server','serving-cluster':dest},'ports':[{'name':'tcp-'+str(p),'port':p,'targetPort':p} for p in PORTS]}})
  self.save(c+'-fixture-manifest.json',{'apiVersion':'v1','kind':'List','items':objs})
  self.k(c,'create','-f','-',body=json.dumps({'apiVersion':'v1','kind':'List','items':objs}))
  for ns in [NS,NEG]:self.k(c,'-n',ns,'wait','--for=condition=Ready','pod','--all','--timeout=120s')
  self.save(c+'-pods-created.json',self.get(c,'-n',NS,'get','pods'))
 def server(self,c,*args,check=True):
  return self.k(c,'-n','cilium-spire','exec','spire-server-0','-c','register-agent-node','--','/bin/timeout','-s','KILL','12','/spire-cli/opt/spire/bin/spire-server',*args,'-socketPath','/tmp/spire-server/private/api.sock',check=check)
 def register(self,c):
  ns=self.owned(c,NS);entries=[]
  for p in self.get(c,'-n',NS,'get','pods')['items']:
   m,s=p['metadata'],p['spec'];require(s.get('nodeName') in [c+'-worker',c+'-control-plane'],'Unexpected node')
   sels=[f'k8s:ns:{NS}',f'k8s:sa:{s["serviceAccountName"]}',f'k8s:pod-uid:{m["uid"]}',f'k8s:node-name:{s["nodeName"]}']
   e={'id':str(uuid.uuid5(uuid.NAMESPACE_URL,OWNER+':'+PINS[c]+':'+ns['metadata']['uid']+':'+m['uid'])),'spiffeID':f'spiffe://{c}.mesh.example/ns/{NS}/sa/{s["serviceAccountName"]}','parentID':f'spiffe://{c}.mesh.example/ns/cilium-spire/sa/spire-agent','selectors':sels,'pod':m['name'],'podUID':m['uid'],'node':s['nodeName']}
   entries.append(e)
  ledger=self.out/(c+'-entries.json');require(not ledger.exists(),'Registration ledger exists; do not duplicate registration stage')
  self.save(c+'-entries.json',entries) # write intended exact IDs BEFORE mutation for failure cleanup
  for e in entries:
   args=['entry','create','-entryID',e['id'],'-spiffeID',e['spiffeID'],'-parentID',e['parentID'],'-x509SVIDTTL','120']
   for s in e['selectors']:args+=['-selector',s]
   self.server(c,*args)
   got=json.loads(self.server(c,'entry','show','-entryID',e['id'],'-output','json').stdout)['entries']
   require(len(got)==1,'Entry readback count')
   actual=got[0]
   identity=actual.get('spiffe_id',{});parent=actual.get('parent_id',{})
   require('spiffe://'+identity.get('trust_domain','')+identity.get('path','')==e['spiffeID'],'Exact SPIFFE identity readback mismatch')
   require('spiffe://'+parent.get('trust_domain','')+parent.get('path','')==e['parentID'],'Exact parent readback mismatch')
   require(actual.get('id')==e['id'] and actual.get('x509_svid_ttl')==120,'Exact entry ID/TTL readback mismatch')
   require(sorted(x['type']+':'+x['value']for x in got[0]['selectors'])==sorted(e['selectors']),'Selector readback mismatch')
   self.save(c+'-entry-'+e['pod']+'.json',got)
 def enroll(self,c):
  n=self.owned(c,NS);require(n['metadata'].get('labels',{}).get('io.cilium/mtls-enabled')!='true','Already enrolled')
  entries=json.loads((self.out/(c+'-entries.json')).read_text())
  require({e['podUID']for e in entries}=={p['metadata']['uid']for p in self.get(c,'-n',NS,'get','pods')['items']},'Pod incarnations changed; registrations stale')
  # resourceVersion/UID tested atomically; no label-based ownership takeover.
  patch=[{'op':'test','path':'/metadata/uid','value':n['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':n['metadata']['resourceVersion']},{'op':'add','path':'/metadata/labels/io.cilium~1mtls-enabled','value':'true'}]
  self.k(c,'patch','ns',NS,'--type=json','-p',json.dumps(patch))
 def curl(self,c,ns,pod,url,expected):
  # Only constructed Pod-IP/service URLs. Never shell-interpolate URL.
  require(re.fullmatch(r'http://[A-Za-z0-9.:-]+/(?:\?cmtc=[0-9]+)?',url),'Unsafe URL')
  cmd='curl -sS -i --connect-timeout 3 --max-time 6 "$1"; r=$?; printf "\\nCMTC_CURL_RC=%s\\n" "$r"; exit 0'
  r=self.k(c,'-n',ns,'exec',pod,'--','sh','-c',cmd,'sh',url,check=False)
  require(r.returncode==0,'Exec failed; cannot count as traffic rejection: '+r.stderr)
  m=re.search(r'CMTC_CURL_RC=(\d+)',r.stdout);require(m,'Missing curl completion marker')
  rc=int(m[1]);ok=rc==0 and bool(re.search(r'^HTTP/\S+ 200 ',r.stdout,re.M))
  if expected is not None:ok=ok and f'"cluster": "{expected}"' in r.stdout
  return {'at':now(),'context':'kind-'+c,'namespace':ns,'client':pod,'url':url,'curlRC':rc,'http200':bool(re.search(r'^HTTP/\S+ 200 ',r.stdout,re.M)),'expectedCluster':expected,'positiveMatch':ok,'stdout':r.stdout,'stderr':r.stderr}
 def probe(self,c,scope,expect,repeat):
  self.owned(c,NS);local=self.get(c,'-n',NS,'get','pods')['items'];lp={p['metadata']['name']:p for p in local}
  require(all(p['status'].get('podIP')for p in local),'PodIP missing')
  targets=[]
  for sn in ['worker','control-plane']:
   if scope=='first' and sn!='worker':continue
   client='client-'+sn;ns=NS
   if scope=='negative':client='unregistered-'+sn;ns=NEG;self.owned(c,NEG)
   if scope in ['first','same','negative','all']:
    targets.append((ns,client,lp['server-'+sn]['status']['podIP'],c))
   if scope in ['crossnode','all']:
    other='control-plane' if sn=='worker'else'worker';targets.append((ns,client,lp['server-'+other]['status']['podIP'],c))
   if scope in ['crosscluster','all']:
    peer='cmtc-b'if c=='cmtc-a'else'cmtc-a';self.check(peer);self.owned(peer,NS)
    for p in self.get(peer,'-n',NS,'get','pods','-l','test-role=server')['items']:targets.append((ns,client,p['status']['podIP'],peer))
   if scope in ['global','remote-global','all']:
    for dest in PINS:
     if scope=='remote-global' and dest==c:continue
     targets.append((ns,client,'server-'+dest+'.'+NS+'.svc.cluster.local',dest))
  rows=[]
  for n in range(repeat):
   for ns,client,target,dest in targets:
    for port in PORTS:
     row=self.curl(c,ns,client,f'http://{target}:{port}/?cmtc={time.time_ns()}',dest if expect=='allow'else None)
     row.update(scope=scope,expect=expect,repetition=n);rows.append(row)
     self.save(c+'-'+self.run+'-probe-'+scope+'-'+expect+'.json',rows)
     require(row['positiveMatch'] if expect=='allow'else not row['http200'],'Unexpected traffic verdict: '+json.dumps(row))
  print(json.dumps({'context':c,'scope':scope,'expect':expect,'selected':len(rows),'trafficChecksPassed':len(rows),'securityReasonVerified':False,'evidenceRequired':'peer certs, authenticated identities, policy verdict,packet/metrics correlation'}))
 def evidence(self,c):
  self.owned(c,NS);stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
  self.save(c+'-'+stamp+'-pods.json',self.get(c,'-n',NS,'get','pods'))
  self.save(c+'-'+stamp+'-ceps.json',self.get(c,'-n',NS,'get','ciliumendpoints'))
  for app,sel,ports in [('ztunnel','app=ztunnel-cilium',[(15000,'/config_dump'),(15020,'/metrics')]),('cilium','k8s-app=cilium',[(9962,'/metrics')])]:
   for p in self.get(c,'-n','kube-system','get','pods','-l',sel)['items']:
    name=p['metadata']['name'];node=p['spec']['nodeName'];base=c+'-'+stamp+'-'+node+'-'+app
    self.save(base+'-log.txt',self.k(c,'-n','kube-system','logs',name,'-c','istio-proxy' if app=='ztunnel' else 'cilium-agent','--since=10m','--timestamps','--tail=3000').stdout)
    for port,path in ports:
     with socket.socket()as s:s.bind(('127.0.0.1',0));local=s.getsockname()[1]
     pf=subprocess.Popen(['kubectl','--kubeconfig',K,'--context','kind-'+c,'-n','kube-system','port-forward','--address','127.0.0.1','pod/'+name,f'{local}:{port}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
     try:
      body=None
      for _ in range(60):
       require(pf.poll()is None,'Task port-forward exited')
       try:body=urllib.request.urlopen(f'http://127.0.0.1:{local}{path}',timeout=2).read();break
       except OSError:time.sleep(.25)
      require(body is not None,'Read endpoint unavailable');require(b'PRIVATE KEY'not in body,'Unsafe private material suppressed')
      self.save(base+'-'+str(port)+('.json'if path=='/config_dump'else'.prom'),body.decode())
      if path=='/config_dump':
       dump=json.loads(body)
       for i,cert in enumerate(dump.get('certificates',[])):
        # CertDump.pem is BASE64-encoded public PEM, not literal PEM and never a key.
        for j,part in enumerate(cert.get('certChain',[])):
         public=base64.b64decode(part['pem']);require(b'BEGIN CERTIFICATE'in public and b'PRIVATE KEY'not in public,'Unexpected public certificate format')
         self.save(base+f'-cert-{i}-{j}.pem',public.decode())
     finally:
      pf.terminate()
      try:pf.wait(timeout=5)
      except subprocess.TimeoutExpired:pf.kill();pf.wait()
 def withdraw(self,c,pod):
  self.owned(c,NS);es=json.loads((self.out/(c+'-entries.json')).read_text());es=[e for e in es if e['pod']==pod];require(len(es)==1,'Exact owned entry missing')
  self.server(c,'entry','delete','-entryID',es[0]['id']);self.save(c+'-'+self.run+'-withdraw-'+pod+'.json',{'at':now(),'entry':es[0]})
 def recover(self,c,pod):
  self.owned(c,NS);es=json.loads((self.out/(c+'-entries.json')).read_text());e=next(e for e in es if e['pod']==pod)
  p=self.get(c,'-n',NS,'get','pod',pod);require(p['metadata']['uid']==e['podUID'],'Pod changed; old entry must not be reused')
  args=['entry','create','-entryID',e['id'],'-spiffeID',e['spiffeID'],'-parentID',e['parentID'],'-x509SVIDTTL','120']
  for s in e['selectors']:args+=['-selector',s]
  self.server(c,*args);self.save(c+'-'+self.run+'-recover-'+pod+'.json',{'at':now(),'entry':e})
def main():
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('stage',choices=['create','register','enroll','probe','evidence','withdraw','recover']);a.add_argument('--cluster',choices=list(PINS),required=True);a.add_argument('--out',required=True);a.add_argument('--scope',choices=['first','same','crossnode','crosscluster','global','remote-global','negative','all'],default='first');a.add_argument('--expect',choices=['allow','deny'],default='allow');a.add_argument('--repeat',type=int,default=1);a.add_argument('--pod',default='client-worker');a.add_argument('--execute',action='store_true');x=a.parse_args()
 require(x.execute,'UNRUN proposal: review first, then pass --execute to authorize this operational stage');require(1<=x.repeat<=100,'Bounded load repetitions required')
 l=Lab(x);l.check(x.cluster)
 if x.stage=='probe':l.probe(x.cluster,x.scope,x.expect,x.repeat)
 elif x.stage in ['withdraw','recover']:getattr(l,x.stage)(x.cluster,x.pod)
 else:getattr(l,x.stage)(x.cluster)
if __name__=='__main__':main()
