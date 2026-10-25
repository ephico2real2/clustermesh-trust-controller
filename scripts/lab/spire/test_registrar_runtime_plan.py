"""Pure plan/ownership regressions. No API, subprocess or filesystem changes."""
import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

spec=importlib.util.spec_from_file_location('registrar_runtime',Path(__file__).with_name('qualify_registrar.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

POD='512e6e77-05c4-49fb-ac0c-eb864f2a1177'
NS='90ab564a-91a1-4949-9729-c7d2e053264a'
NODE='a629ba06-f2c6-4b34-a3a2-e4931a4b9e66'
AGENT='6d9e8b85-17c8-4d15-be54-45dc84c13f56'
CLUSTER='a47cc926-2715-41f6-9fab-e76cd4bfa1ed'
INSTALL='79c74c4e-3d5b-4dd7-bb16-40b2d4fb3306'
OWNER='11119cde-2de0-4a9b-93a7-cf368bb6a82a'

def obj(uid,name='orders',namespace='orders-reg'):
    return {'metadata':{'name':name,'namespace':namespace,'uid':uid,'resourceVersion':'12','labels':{r.OWNER:OWNER}},'spec':{'nodeName':'node-a','serviceAccountName':'api'}}

class Plan(unittest.TestCase):
    def test_actual_protobuf_json_empty_entry_store(self):
        h=r.Runner.__new__(r.Runner);h.apis={'cmtc-a':object()}
        for result in [{},{'entries':[]},{'entries':[],'next_page_token':''}]:
            with patch.object(r.q,'server_cli',return_value=result):self.assertEqual(h.rows('cmtc-a'),[])
        for result in [[],{'unknown':[]},{'entries':None},{'entries':[],'unknown':1},{'entries':[],'next_page_token':'unread-page'}]:
            with patch.object(r.q,'server_cli',return_value=result),self.assertRaises(r.Refusal):h.rows('cmtc-a')
    def test_daemon_observation_waits_for_scheduling_and_rejects_ambiguity(self):
        h=r.Runner.__new__(r.Runner)
        daemon=obj(AGENT,'probe','cilium-spire')
        pending=obj(POD,'probe-pending','cilium-spire');pending['spec'].pop('nodeName')
        pending['metadata']['ownerReferences']=[{'kind':'DaemonSet','uid':AGENT,'controller':True}]
        h.pods=lambda *args:[pending]
        self.assertEqual(h.current_pods('cmtc-a',daemon),{})
        pending['spec']['nodeName']='node-a'
        self.assertEqual(set(h.current_pods('cmtc-a',daemon)),{'node-a'})
        h.pods=lambda *args:[pending,copy.deepcopy(pending)]
        with self.assertRaises(r.Refusal):h.current_pods('cmtc-a',daemon)
    def test_go_equivalent_binding_bytes_and_exact_selectors(self):
        options={'installationID':INSTALL,'clusterUID':CLUSTER,'clusterName':'cmtc-a','trustDomain':'cmtc-a.mesh.example','agent':{'namespaceUID':NS,'namespace':'cilium-spire','serviceAccount':'spire-agent'}}
        a,b=r.wanted(options,obj(POD),obj(NODE,'node-a'),obj(AGENT,'agent'),NS,'workload')
        raw=('['+','.join('"'+x+'"' for x in [INSTALL,CLUSTER,NS,NODE,AGENT,POD,'workload'])+']').encode()
        h=bytearray(hashlib.sha1(uuid.NAMESPACE_URL.bytes+raw).digest()[:16]);h[6]=(h[6]&15)|80;h[8]=(h[8]&63)|128
        self.assertEqual(b['entryID'],str(uuid.UUID(bytes=bytes(h))))
        self.assertEqual(b['parentID'],'spiffe://cmtc-a.mesh.example/cmtc/agents/'+NODE+'/'+AGENT)
        self.assertEqual(b['selectors'],['k8s:ns:orders-reg','k8s:sa:api','k8s:pod-uid:'+POD,'k8s:node-name:node-a'])
        self.assertEqual(a['parentID'],'spiffe://cmtc-a.mesh.example/spire/server')
        self.assertIn('k8s_psat:agent_node_uid:'+NODE,a['selectors'])
        _,replacement=r.wanted(options,obj(str(uuid.uuid4())),obj(NODE,'node-a'),obj(AGENT,'agent'),NS,'workload')
        self.assertNotEqual(b['entryID'],replacement['entryID'])
    def test_delete_preconditions_and_foreign_replacement_refusal(self):
        o=obj(POD);body=r.deletion(o,OWNER,POD)
        self.assertEqual(body['preconditions'],{'uid':POD,'resourceVersion':'12'})
        for modify in [lambda x:x['metadata'].update(uid=str(uuid.uuid4())),lambda x:x['metadata']['labels'].update({r.OWNER:'foreign'}),lambda x:x['metadata'].update(deletionTimestamp='now')]:
            n=copy.deepcopy(o);modify(n)
            with self.assertRaises(r.Refusal):r.deletion(n,OWNER,POD)
    def test_template_write_requires_old_template_and_current_uid_rv(self):
        o={'metadata':{'uid':POD,'resourceVersion':'12'},'spec':{'template':{'spec':{'x':1}}}}
        patch=r.template_patch(o,POD,{'spec':{'x':1}},{'spec':{'x':2}})
        self.assertEqual(patch[1],{'op':'test','path':'/metadata/resourceVersion','value':'12'})
        with self.assertRaises(r.Refusal):r.template_patch(o,POD,{'spec':{'x':0}},{})
        with self.assertRaises(r.Refusal):r.template_patch(o,str(uuid.uuid4()),o['spec']['template'],{})
    def test_sidecar_changes_only_private_server_profile(self):
        old={'spec':{'serviceAccountName':'spire-server','securityContext':{'runAsUser':1000,'runAsGroup':1000},'containers':[{'name':'spire-server','image':'server'},{'name':'register-agent-node','image':'busybox'}],'volumes':[{'name':'spire-server-socket','emptyDir':{}}]}}
        frozen=copy.deepcopy(old);result=r.sidecar_template(old,r.REGISTRAR_IMAGE,'config','a'*64)
        self.assertEqual(old,frozen);self.assertEqual(result['spec']['containers'][:2],old['spec']['containers'])
        side=result['spec']['containers'][-1];self.assertEqual(side['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertEqual({m['name'] for m in side['volumeMounts']},{'spire-server-socket','cmtc-registrar-config'})
        self.assertFalse(any('hostPath' in v for v in result['spec']['volumes']))
        init=result['spec']['initContainers'];self.assertEqual(len(init),1)
        self.assertEqual(init[0]['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertEqual(init[0]['securityContext']['runAsUser'],0)
        self.assertEqual(init[0]['volumeMounts'],[{'name':'spire-server-socket','mountPath':'/tmp/spire-server/private'}])
        self.assertNotIn('spire-data',str(init))
        self.assertIn('chmod 00770',init[0]['command'][-1])
        self.assertIn('--config-sha256='+'a'*64,side['args'])
        self.assertTrue(all(len(p['name'])<=15 for p in side['ports']))
        foreign=copy.deepcopy(old);foreign['spec']['containers'].append({'name':'foreign'})
        with self.assertRaises(r.Refusal):r.sidecar_template(foreign,r.REGISTRAR_IMAGE,'config','a'*64)
    def test_execute_keeps_cleanup_on_prepare_or_exercise_failure(self):
        for failing in ['prepare','exercise']:
            events=[]
            class API:
                def __init__(self,*args):pass
                def __enter__(self):return self
                def __exit__(self,*args):events.append('api-closed')
            class Harness(r.Runner):
                def preflight_images(self):events.append("preflight")
                def prepare(self,c):
                    events.append('prepare-'+c)
                    if failing=='prepare':raise r.Refusal('expected')
                def exercise(self,c):events.append('exercise-'+c);raise r.Refusal('expected')
                def cleanup(self):events.append('cleanup')
                def flush(self):pass
            h=Harness.__new__(Harness);h.args=SimpleNamespace(kubeconfig='unused');h.apis={};h.report={'clusters':{},'cleanupErrors':[]}
            with patch.object(r.pki,'Proxy',API),self.assertRaises(r.Refusal):h.execute()
            self.assertEqual(events.count('cleanup'),1);self.assertEqual(events[-2:],['api-closed','api-closed']);self.assertFalse(h.report['qualified'])
    def test_ambiguous_template_write_preserves_dependent_objects(self):
        h=r.Runner.__new__(r.Runner);h.report={'clusters':{'cmtc-a':{'pendingTemplatePatch':True,'created':[{'path':'/must-not-delete','uid':POD}]}},'cleanupErrors':[]};h.args=SimpleNamespace(issuer_ledger='unused');h.ledger_raw=b'x';h.flush=lambda:None
        h.delete_owned=lambda *args:(_ for _ in ()).throw(AssertionError('must preserve ambiguous dependencies'))
        with patch.object(Path,'read_bytes',return_value=b'x'):h.cleanup()
        self.assertEqual(len(h.report['cleanupErrors']),1)
        self.assertIn('ambiguous server template write',h.report['cleanupErrors'][0]['error'])
    def test_template_admission_failure_never_marks_ambiguous_write(self):
        h=r.Runner.__new__(r.Runner)
        h.report={'clusters':{'cmtc-a':{'serverPath':'/server','serverUID':POD}}}
        h.get=lambda *args:{'metadata':{'uid':POD,'resourceVersion':'7'},'spec':{'template':{'original':True}}}
        commands=[]
        def reject(c,args):
            commands.append(args)
            raise r.Refusal('actual API admission rejected')
        h.command=reject;h.flush=lambda:None
        with self.assertRaises(r.Refusal):h.template('cmtc-a',{'original':True},{'next':True})
        self.assertEqual(len(commands),1);self.assertIn('--dry-run=server',commands[0])
        self.assertNotIn('pendingTemplatePatch',h.report['clusters']['cmtc-a'])
    def test_rollback_deletes_only_exact_owned_registrar_revision(self):
        side={'name':'cmtc-spire-registrar','image':r.REGISTRAR_IMAGE,'command':['/cmtc-spire-registrar'],'args':['--config=owned'],'securityContext':{'runAsUser':1000}}
        installed={'spec':{'containers':[side]}}
        for variant in ['owned','other-controller','other-image','unknown-container','already-original']:
            h=r.Runner.__new__(r.Runner);h.report={'clusters':{'cmtc-a':{'serverPath':'/server','serverUID':POD,'originalTemplate':{'original':True}}}}
            h.get=lambda *args:{'metadata':{'uid':POD,'resourceVersion':'7'},'spec':{'template':{'original':True}}}
            pod=obj(AGENT,'spire-server-0','cilium-spire');pod['metadata']['ownerReferences']=[{'controller':True,'kind':'StatefulSet','uid':POD}]
            pod['spec']['containers']=[{'name':'spire-server'},{'name':'register-agent-node'},copy.deepcopy(side)]
            if variant=='other-controller':pod['metadata']['ownerReferences'][0]['uid']=NODE
            if variant=='other-image':pod['spec']['containers'][-1]['image']='foreign'
            if variant=='unknown-container':pod['spec']['containers'].append({'name':'foreign'})
            if variant=='already-original':pod['spec']['containers'].pop()
            h.maybe=lambda *args:pod;writes=[]
            h.apis={'cmtc-a':SimpleNamespace(request=lambda *args:writes.append(args))}
            h.command=lambda *args,**kwargs:SimpleNamespace(stdout='public log',stderr='')
            h.save=lambda *args:None;h.emit=lambda *args:None
            if variant in ['owned','already-original']:h.retire_owned_registrar_pod('cmtc-a',installed)
            else:
                with self.assertRaises(r.Refusal):h.retire_owned_registrar_pod('cmtc-a',installed)
            self.assertEqual(len(writes),int(variant=='owned'))
            if writes:self.assertEqual(writes[0][2]['preconditions'],{'uid':AGENT,'resourceVersion':'12'})
    def test_cleanup_withdraws_delegate_before_stopping_registrar(self):
        events=[]
        delegate=obj(POD,'owned-probe','cilium-spire')
        state={'installedTemplate':{'active':True},'originalTemplate':{'active':False},'delegate':delegate,'beforeSigner':{'directIssuerSHA256':'signer'},'pvc':{'data':'pvc'},'created':[]}
        class Harness(r.Runner):
            def delete_owned(self,*args):events.append('delegate-deleted')
            def owned_rows(self,c):
                return {} if 'delegate-deleted' in events else {'still-present':{}}
            def poll(self,fn,**kwargs):
                if not fn():raise AssertionError('withdrawal must finish while registrar is running')
            def template(self,*args):
                self.assert_withdrawn();events.append('template-restored')
            def assert_withdrawn(self):
                if self.owned_rows('cmtc-a'):raise AssertionError('registrar stopped before withdrawal')
            def retire_owned_registrar_pod(self,*args):events.append('rollback-checked')
            def server(self,*args,**kwargs):events.append('server-restored')
            def signer(self,*args,**kwargs):return {'directIssuerSHA256':'signer'}
            def pvc(self,*args):return {'data':'pvc'}
            def flush(self):pass
        h=Harness.__new__(Harness);h.report={'clusters':{'cmtc-a':state},'cleanupErrors':[]};h.args=SimpleNamespace(issuer_ledger='unused');h.ledger_raw=b'x'
        with patch.object(Path,'read_bytes',return_value=b'x'):h.cleanup()
        self.assertEqual(h.report['cleanupErrors'],[])
        self.assertEqual(events,['delegate-deleted','template-restored','rollback-checked','server-restored'])




class ControlWithdrawal(unittest.TestCase):
    def response(self,code=0,error='',stdout=None):
        return SimpleNamespace(returncode=code,stderr=error,stdout=('public cert' if code==0 else '') if stdout is None else stdout)
    def empty(self):
        return self.response(1,'Error: native PID-attested credential fetch\nCaused by: failed to fetch certificate for workload: Failed to receive X.509 SVID: empty Workload API response')
    def fake(self,responses):
        h=r.Runner.__new__(r.Runner);h.args=SimpleNamespace(probe_image='probe');h.events=[];h.calls=[];h.now=0.;h._deadline=None
        target=(obj(POD,'probe'),obj(AGENT,'target'),{'podUID':AGENT,'namespace':'target-ns'})
        control=(target[0],obj(NODE,'control'),{'podUID':NODE,'namespace':'control-ns'})
        iterator=iter(responses)
        def native(c,probe,pod,wanted,label):
            h.remaining(1);h.calls.append((pod['metadata']['name'],label));return next(iterator)
        h.native_observation=native;h.save=lambda *args:None;h.emit=h.events.append;h.assert_registration=lambda *args:None
        return h,target,control
    def test_alias_metadata_never_removes_node_or_delegate_entitlement(self):
        rows={
            'alias':{'spiffeID':'spiffe://cluster.mesh/cmtc/agents/node/agent','namespace':'target-ns'},
            'delegate':{'spiffeID':'spiffe://cluster.mesh/ztunnel-proxy','namespace':'cilium-spire'},
            'target':{'spiffeID':'spiffe://cluster.mesh/ns/target-ns/sa/api','namespace':'target-ns'},
            'control':{'spiffeID':'spiffe://cluster.mesh/ns/control-ns/sa/api','namespace':'control-ns'},
        }
        self.assertEqual(set(r.withdrawal_rows(rows,'target-ns')),{'alias','delegate','control'})

    def test_classifier_rejects_delegate_outage_deadline_and_payload(self):
        for text in ['The caller does not have permission: no identity issued','PermissionDenied: no identity issued','Unavailable','SPIRE credential deadline exceeded','Timeout while waiting for SVID stream','invalid certificate','No SVIDs received in stream']:
            with self.subTest(text=text),self.assertRaises(r.Refusal):r.target_absence(self.response(1,'native PID-attested credential fetch '+text))
        with self.assertRaises(r.Refusal):r.target_absence(self.response(1,self.empty().stderr,'unexpected stdout'))
        with self.assertRaises(r.Refusal):r.target_absence(self.response(1,self.empty().stderr+' Unavailable'))
        abnormal=self.empty();abnormal.returncode=137
        with self.assertRaises(r.Refusal):r.target_absence(abnormal)
        self.assertTrue(r.target_absence(self.empty()))
        self.assertFalse(r.target_absence(self.response()))
    def test_control_success_brackets_explicit_empty(self):
        h,target,control=self.fake([self.response(),self.empty(),self.response()])
        with patch.object(r.q,'verify_public_result',return_value={'verified':True}) as verify:
            with h.deadline(60):h.deny_withdrawn('cmtc-a',target,control,{'issuer':'pin'})
        self.assertEqual([x[0] for x in h.calls],['control','target','control'])
        self.assertEqual(verify.call_count,2)
        self.assertEqual(h.events[-1]['stage'],'withdrawal-explicit-empty-svid')
        self.assertFalse(h.events[-1]['authorizationDenied'])
    def test_control_failure_before_or_after_is_never_withdrawal(self):
        for responses in [[self.response(1,'PermissionDenied')],[self.response(),self.empty(),self.response(1,'Unavailable')]]:
            h,target,control=self.fake(responses)
            with patch.object(r.q,'verify_public_result',return_value={}):
                with h.deadline(60),self.assertRaises(r.Refusal):h.deny_withdrawn('cmtc-a',target,control,{})
            self.assertFalse(any(e['stage']=='withdrawal-explicit-empty-svid' for e in h.events))
    def test_target_permission_denied_or_timeout_is_inconclusive(self):
        for error in ['The caller does not have permission: no identity issued','Unavailable','SPIRE credential deadline exceeded']:
            h,target,control=self.fake([self.response(),self.response(1,'native PID-attested credential fetch '+error)])
            with patch.object(r.q,'verify_public_result',return_value={}):
                with h.deadline(60),self.assertRaises(r.Refusal):h.deny_withdrawn('cmtc-a',target,control,{})
            self.assertEqual(len(h.calls),2)
            self.assertFalse(h.events)
    def test_cached_success_requires_verification_then_empty_recovers(self):
        h,target,control=self.fake([self.response(),self.response(),self.empty(),self.response()]);sleeps=[]
        h.pause=lambda seconds:sleeps.append(seconds)
        with patch.object(r.q,'verify_public_result',return_value={}) as verify:
            with h.deadline(60):h.deny_withdrawn('cmtc-a',target,control,{})
        self.assertEqual(verify.call_count,3);self.assertEqual(sleeps,[2])
        self.assertEqual(h.events[-1]['attempt'],2)
    def test_bad_cached_certificate_is_fatal(self):
        h,target,control=self.fake([self.response(),self.response()])
        with patch.object(r.q,'verify_public_result',side_effect=[{},ValueError('wrong signer')]):
            with h.deadline(60),self.assertRaises(ValueError):h.deny_withdrawn('cmtc-a',target,control,{})
        self.assertFalse(any(e.get('stage')=='withdrawal-explicit-empty-svid' for e in h.events))
    def test_deadline_bounds_command_sleep_and_no_late_success(self):
        h=r.Runner.__new__(r.Runner);h.apis={'cmtc-a':SimpleNamespace(argv=['kubectl'])};clock=[0.];timeouts=[]
        def bounded(argv,**kwargs):
            timeouts.append(kwargs['timeout']);clock[0]+=kwargs['timeout'];return self.response()
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]):
            with h.deadline(3):
                with patch.object(r.q,'bounded',side_effect=bounded),self.assertRaises(r.Refusal):h.command('cmtc-a',['get','pods'],timeout=40)
                self.assertEqual(timeouts,[3])
                with self.assertRaises(r.Refusal):h.command('cmtc-a',['get','pods'])
            clock[0]=0.
            with h.deadline(1):
                def sleep(seconds):self.assertEqual(seconds,1);clock[0]+=seconds
                with patch.object(r.time,'sleep',side_effect=sleep),self.assertRaises(r.Refusal):h.pause(2)
            self.assertIsNone(h._deadline)
    def test_global_deadline_includes_both_nodes_and_controls(self):
        h,target,control=self.fake([self.response(),self.empty(),self.response()]);clock=[0.]
        original=h.native_observation
        def delayed(*args):
            result=original(*args);clock[0]+=3;return result
        h.native_observation=delayed
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]),patch.object(r.q,'verify_public_result',return_value={}):
            with h.deadline(8),self.assertRaises(r.Refusal):h.deny_withdrawn('cmtc-a',target,control,{})
        self.assertFalse(any(e.get('stage')=='withdrawal-explicit-empty-svid' for e in h.events))
    def test_positive_empty_retries_and_fresh_valid_request_recovers(self):
        h,target,control=self.fake([self.empty(),self.response()]);h.pause=lambda seconds:None
        with patch.object(r.q,'verify_public_result',return_value={'recovered':True}):
            result=h.positive_fetch('cmtc-a',*target,{},'recovery')
        self.assertEqual(result,{'recovered':True});self.assertEqual(len(h.calls),2)
    def test_pair_controls_rejects_cross_node_duplicate_or_replaced_probe(self):
        fixtures=[]
        for i,node in enumerate(['node-a','node-b']):
            probe=obj(str(uuid.uuid4()),'probe-'+str(i),'cilium-spire');probe['spec']['nodeName']=node
            for ns in ['target','control']:
                pod=obj(str(uuid.uuid4()),ns+'-'+str(i),ns);pod['spec']['nodeName']=node
                fixtures.append((copy.deepcopy(probe),pod,{'namespace':ns,'podUID':pod['metadata']['uid']}))
        self.assertEqual(len(r.pair_controls(fixtures,'target','control')),2)
        for modify in [lambda x:x.pop(),lambda x:x[1][0]['spec'].update(nodeName='other'),lambda x:x[1][0]['metadata'].update(uid=str(uuid.uuid4())),lambda x:x.append(copy.deepcopy(x[0]))]:
            broken=copy.deepcopy(fixtures);modify(broken)
            with self.assertRaises(r.Refusal):r.pair_controls(broken,'target','control')
    def test_pin_parser_rejects_old_permission_profile_and_bad_values(self):
        good=SimpleNamespace(probe_config='a'*64,probe_source='b'*40,probe_image=r.REGISTRAR_IMAGE,probe_uid=1000,probe_gid=0)
        r.validate_probe_pins(good)
        for key,value in [('probe_config','tag'),('probe_source','short'),('probe_uid',0),('probe_gid',1337),('probe_image','latest')]:
            bad=copy.copy(good);setattr(bad,key,value)
            with self.assertRaises(Exception):r.validate_probe_pins(bad)
        valid='version.BuildInfo{GitRevision:"'+'b'*40+'", BuildStatus:"Clean"}'
        self.assertEqual(r.verify_probe_version(valid,'b'*40),valid)
        for raw in [valid.replace('Clean','Modified'),valid.replace('b'*40,'c'*40),'not a version']:
            with self.assertRaises(r.Refusal):r.verify_probe_version(raw,'b'*40)
    def test_preflight_failure_prevents_all_fixture_prepares_and_cleans(self):
        events=[]
        class API:
            def __init__(self,*args):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
        class Harness(r.Runner):
            def preflight_images(self):events.append('preflight');raise r.Refusal('wrong binary')
            def prepare(self,c):events.append('MUTATION')
            def cleanup(self):events.append('cleanup')
            def flush(self):pass
        h=Harness.__new__(Harness);h.args=SimpleNamespace(kubeconfig='unused');h.apis={};h.report={'clusters':{},'cleanupErrors':[]}
        with patch.object(r.pki,'Proxy',API),self.assertRaises(r.Refusal):h.execute()
        self.assertEqual(events,['preflight','cleanup']);self.assertFalse(h.report['qualified'])
    def test_control_namespace_is_in_approval_and_scoped_rbac(self):
        namespace=obj(NS,'target','');account=obj(POD,'api','target');control=obj(NODE,'control','');control_sa=obj(AGENT,'api','control')
        daemon=obj(INSTALL,'agent','cilium-spire');daemon['spec']['template']={'spec':{'containers':[{'name':'spire-agent','image':r.REGISTRAR_IMAGE},{'name':'probe','image':r.REGISTRAR_IMAGE}]}}
        spire_ns=obj(CLUSTER,'cilium-spire','')
        options=r.approval('cmtc-a',CLUSTER,'cmtc-a.mesh.example',INSTALL,namespace,account,daemon,account,daemon,account,spire_ns,extra_namespaces=[(control,control_sa)])
        self.assertEqual({n['name'] for n in options['namespaces']},{'target','control'})
        h=r.Runner.__new__(r.Runner);h.short='test';h.pins={'cmtc-a':{'nodes':{'node-a':NODE,'node-b':POD}}};writes=[]
        h.create=lambda c,path,body:writes.append((path,body))
        r.Runner.rbac(h,'cmtc-a',options)
        role=writes[0][1];self.assertEqual(role['rules'][0]['resourceNames'],['cilium-spire','control','kube-system','target'])
        self.assertFalse(any('*' in str(body['rules']) for _,body in writes if 'rules' in body))
        self.assertEqual({body['metadata'].get('namespace') for _,body in writes if body['kind']=='Role'},{'target','control','cilium-spire'})

    def test_expected_eight_rows_retains_six_control_alias_delegate_rows(self):
        h=r.Runner.__new__(r.Runner);h.owner=OWNER
        node_ids={'node-a':NODE,'node-b':str(uuid.uuid4())}
        agents={};probes={};pods={'target':[],'control':[]}
        for node in node_ids:
            agents[node]=obj(str(uuid.uuid4()),'agent-'+node,'cilium-spire')
            probes[node]=obj(str(uuid.uuid4()),'probe-'+node,'cilium-spire')
            agents[node]['spec']['nodeName']=node;probes[node]['spec']['nodeName']=node
            for ns in pods:
                pod=obj(str(uuid.uuid4()),ns+'-'+node,ns);pod['spec']['nodeName']=node;pods[ns].append(pod)
        options={'installationID':INSTALL,'clusterUID':CLUSTER,'clusterName':'cmtc-a','trustDomain':'cmtc-a.mesh.example','agent':{'namespaceUID':NS,'namespace':'cilium-spire','serviceAccount':'spire-agent'},'delegate':{'namespaceUID':NS}}
        h.report={'clusters':{'cmtc-a':{'agent':'agent-ds','delegate':'probe-ds','namespace':obj(NS,'target'),'controlNamespace':obj(POD,'control'),'approval':options}}}
        h.pins={'cmtc-a':{'nodes':node_ids}};h.current_pods=lambda c,ds:agents if ds=='agent-ds' else probes
        h.pods=lambda c,ns:pods[ns];h.get=lambda c,path:obj(node_ids[path.split('/')[-1]],path.split('/')[-1])
        rows,targets=h.expected('cmtc-a');self.assertEqual(len(rows),8);self.assertEqual(len(targets),4)
        keep={k:v for k,v in rows.items() if v['namespace']!='target'}
        self.assertEqual(len(keep),6)
        self.assertEqual(sum(v['spiffeID'].endswith('/ztunnel-proxy') for v in keep.values()),2)
        self.assertEqual(sum('/ns/control/sa/api' in v['spiffeID'] for v in keep.values()),2)
    def test_persistent_cached_svid_exhausts_global_budget(self):
        h,target,control=self.fake([self.response() for _ in range(10)]);clock=[0.]
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]),patch.object(r.time,'sleep',side_effect=lambda seconds:clock.__setitem__(0,clock[0]+seconds)),patch.object(r.q,'verify_public_result',return_value={}):
            with h.deadline(5),self.assertRaises(r.Refusal):h.deny_withdrawn('cmtc-a',target,control,{})
        self.assertEqual(clock[0],5)
        self.assertTrue(h.events);self.assertTrue(all(e['stage']=='withdrawal-not-yet-observed' for e in h.events))
    def test_real_preflight_checks_binary_and_all_node_configs_before_prepare(self):
        for failure in ['none','local-config','binary-source','node-config']:
            h=r.Runner.__new__(r.Runner);h.args=SimpleNamespace(probe_config='a'*64,probe_source='b'*40,probe_image='probe',registrar_image=r.REGISTRAR_IMAGE,probe_podman_connection='owned-builder')
            h.apis={'cmtc-a':object(),'cmtc-b':object()};h.pins={c:{'clusterUID':CLUSTER,'nodes':{'node-a':NODE,'node-b':POD}} for c in h.apis}
            h.issuer={'clusterPins':{c:CLUSTER for c in h.apis}};h.save=lambda *args:None;calls=[]
            h.get=lambda c,path:({'metadata':{'uid':CLUSTER}} if path.endswith('kube-system') else {'items':[obj(NODE,'node-a'),obj(POD,'node-b')]})
            def cri(c,node,image,expected):
                calls.append((c,node,image,expected))
                if failure=='node-config' and c=='cmtc-b' and node=='node-b':raise r.Refusal('wrong final node config')
            h.cri=cri
            inspected={'Id':'sha256:'+'a'*64,'Architecture':'arm64','Os':'linux','Labels':{'org.opencontainers.image.revision':'b'*40}}
            if failure=='local-config':inspected['Id']='sha256:'+'c'*64
            source='c'*40 if failure=='binary-source' else 'b'*40
            version='version.BuildInfo{GitRevision:"'+source+'", BuildStatus:"Clean"}'
            outputs=[self.response(stdout=r.json.dumps([inspected])),self.response(stdout=version)]
            with patch.object(r.q,'bounded',side_effect=outputs) as commands:
                if failure=='none':h.preflight_images();self.assertEqual(len(calls),8)
                else:
                    with self.assertRaises(r.Refusal):h.preflight_images()
                self.assertTrue(all(call.kwargs['timeout']<=30 for call in commands.call_args_list))
                self.assertTrue(all(call.args[0][:3]==['podman','--connection','owned-builder'] for call in commands.call_args_list))
                if len(commands.call_args_list)>1:
                    argv=commands.call_args_list[1].args[0]
                    self.assertIn('--network=none',argv);self.assertIn('--pull=never',argv);self.assertIn('--timeout=10',argv)

if __name__=='__main__':unittest.main()
