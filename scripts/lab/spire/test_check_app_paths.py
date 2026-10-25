import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec=importlib.util.spec_from_file_location('app_paths',Path(__file__).with_name('check_app_paths.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
OWNER='f1aa1bd2-9521-43c4-abf9-02f0e4ca0850'
UID='93e40292-8005-4527-9a38-de7483a888b3'

def backend(cluster,node,index):
    return {'metadata':{'name':'backend-'+node,'namespace':'mesh-example','uid':UID+str(index),'resourceVersion':'1','labels':{'name':'rebel-base','mesh.cmtc.io/cluster':cluster}},'spec':{'nodeName':node,'containers':[{'name':'app','image':'fixture'}]},'status':{'phase':'Running','podIP':'10.'+('1' if cluster=='cmtc-a' else '2')+'.0.'+str(index+1),'containerStatuses':[{'name':'app','ready':True,'containerID':'containerd://'+node,'imageID':'sha256:'+'1'*64,'restartCount':0,'state':{'running':{'startedAt':'2026-10-25T01:00:00Z'}}}]}}

def inventories():
    return {c:a.backend_inventory([backend(c,c+'-control-plane',0),backend(c,c+'-worker',1)],c,{c+'-control-plane':'uid1',c+'-worker':'uid2'}) for c in a.CLUSTERS}

def owned():
    o=a.client_plan(OWNER,'cmtc-a-worker');o['metadata'].update(uid=UID,resourceVersion='37');return o

class PurePlan(unittest.TestCase):
    def test_exact_least_privilege_two_client_template(self):
        p=a.client_plan(OWNER,'cmtc-a-worker');s=p['spec'];self.assertEqual(p['metadata']['namespace'],'mesh-example');self.assertNotEqual(p['metadata']['name'],'mesh-client');self.assertEqual(s['containers'][0]['image'],'curlimages/curl:8.14.1');self.assertEqual((s['securityContext']['runAsUser'],s['securityContext']['runAsGroup']),(65532,65532));self.assertFalse(s['automountServiceAccountToken']);self.assertFalse(s['hostPID']);self.assertFalse(s['hostNetwork']);self.assertEqual(s['activeDeadlineSeconds'],900);self.assertFalse(s.get('volumes'));self.assertEqual(s['containers'][0]['securityContext']['capabilities'],{'drop':['ALL']});self.assertTrue(s['containers'][0]['securityContext']['readOnlyRootFilesystem'])
    def test_actual_api_omits_false_host_flags_but_true_is_still_refused(self):
        plan=a.client_plan(OWNER,'cmtc-a-worker');pod=owned()
        pod['spec'].pop('hostNetwork');pod['spec'].pop('hostPID')
        a.assert_client_profile(pod,plan)
        for key in ('hostNetwork','hostPID'):
            actual=copy.deepcopy(pod);actual['spec'][key]=True
            with self.subTest(key=key),self.assertRaises(a.Refusal):a.assert_client_profile(actual,plan)
    def test_unknown_worker_and_owner_rejected(self):
        for owner,node in [(OWNER,'foreign-worker'),('00000000-0000-0000-0000-000000000000','cmtc-a-worker'),(OWNER.upper(),'cmtc-a-worker')]:
            with self.subTest(owner=owner,node=node),self.assertRaises((a.Refusal,ValueError)):a.client_plan(owner,node)
    def test_actual_client_admission_cannot_widen_profile(self):
        plan=a.client_plan(OWNER,'cmtc-a-worker');p=owned();a.assert_client_profile(p,plan)
        changes=[lambda p:p['spec'].update(automountServiceAccountToken=True),lambda p:p['spec'].update(hostPID=True),lambda p:p['spec'].update(volumes=[{'hostPath':{'path':'/'}}]),lambda p:p['spec']['containers'][0].update(env=[{'name':'TOKEN','value':'test'}]),lambda p:p['spec']['containers'][0]['securityContext']['capabilities'].update(add=['NET_ADMIN']),lambda p:p['spec']['containers'][0].update(image='foreign')]
        for change in changes:
            p=owned();change(p)
            with self.subTest(change=change),self.assertRaises(a.Refusal):a.assert_client_profile(p,plan)
    def test_matrix_has_twelve_service_and_twenty_four_direct_paths(self):
        cases=a.path_matrix(inventories());self.assertEqual(len(cases),36);self.assertEqual(sum(x['kind']=='service' for x in cases),12);self.assertEqual(sum(x['kind']=='pod-ip' for x in cases),24)
        for source in a.CLUSTERS:
            for destination in a.CLUSTERS:
                pair=[x for x in cases if x['source']==source and x['destination']==destination];self.assertEqual(len(pair),9);self.assertEqual({x['port'] for x in pair},set(a.PORTS));self.assertEqual(len({x.get('expectedPod') for x in pair if x['kind']=='pod-ip'}),2)
    def test_backend_placement_missing_readiness_and_address_reuse_refused(self):
        cluster='cmtc-a';nodes={cluster+'-control-plane':'1',cluster+'-worker':'2'};pods=[backend(cluster,n,i) for i,n in enumerate(nodes)]
        for mutate in [lambda x:x.pop(),lambda x:x[1]['spec'].update(nodeName=x[0]['spec']['nodeName']),lambda x:x[0]['status']['containerStatuses'][0].update(ready=False),lambda x:x[1]['status'].update(podIP=x[0]['status']['podIP'])]:
            current=copy.deepcopy(pods);mutate(current)
            with self.subTest(mutate=mutate),self.assertRaises(a.Refusal):a.backend_inventory(current,cluster,nodes)
    def test_response_requires_exact_cluster_and_pod_on_real_http200(self):
        case=a.path_matrix(inventories())[3];pod=case['expectedPod'];body='{"cluster":"'+case['destination']+'","message":"okay"}';headers='HTTP/1.0 200 OK\r\nX-CMTC-Pod: '+pod+'\r\n\r\n';self.assertEqual(a.validate_response(case,body,headers)['actualPod'],pod)
        failures=[(body.replace(case['destination'],'foreign'),headers),(body,headers.replace(pod,'wrong-pod')),(body,headers.replace('200 OK','301 Redirect')),(body,headers+'X-CMTC-Pod: '+pod+'\n'),('{"cluster":"'+case['destination']+'","cluster":"'+case['destination']+'"}',headers),('{"cluster":"'+case['destination']+'","x":NaN}',headers)]
        for b,h in failures:
            with self.subTest(body=b,headers=h),self.assertRaises(a.Refusal):a.validate_response(case,b,h)
    def test_service_response_must_name_one_of_current_exact_backends(self):
        case=a.path_matrix(inventories())[0]
        for pod in case['allowedPods']:a.validate_response(case,'{"cluster":"'+case['destination']+'"}','HTTP/1.1 200 OK\nX-CMTC-Pod: '+pod+'\n\n')
        with self.assertRaises(a.Refusal):a.validate_response(case,'{"cluster":"'+case['destination']+'"}','HTTP/1.1 200 OK\n\n')
    def test_delete_requires_exact_uid_owner_name_namespace_and_current_rv(self):
        p=owned();self.assertEqual(a.delete_options(p,OWNER,UID)['preconditions'],{'uid':UID,'resourceVersion':'37'})
        for mutate in [lambda p:p['metadata'].update(uid='replacement'),lambda p:p['metadata']['labels'].update({a.OWNER:'foreign'}),lambda p:p['metadata'].update(name='mesh-client'),lambda p:p['metadata'].update(namespace='foreign')]:
            o=owned();mutate(o)
            with self.subTest(mutate=mutate),self.assertRaises(a.Refusal):a.delete_options(o,OWNER,UID)
    def test_cleanup_attempts_second_owned_client_after_first_replacement(self):
        h=a.Audit.__new__(a.Audit);h.owner=OWNER;h.report={'clusters':{},'cleanupErrors':[]};h.flush=lambda:None;h.apis={};calls=[]
        class API:
            def request(self,method,path,body):calls.append((method,path,body));return {}
        for c in a.CLUSTERS:h.report['clusters'][c]={'created':{'path':'/'+c,'uid':UID,'name':'owned'}};h.apis[c]=API()
        def maybe(c,path):
            if c=='cmtc-a':o=owned();o['metadata']['uid']='replacement';return o
            if calls:return None
            return owned()
        h.maybe=maybe;h.poll=lambda fn:fn();h.cleanup();self.assertEqual(len(h.report['cleanupErrors']),1);self.assertEqual([x[1] for x in calls],['/cmtc-b']);self.assertEqual(calls[0][2]['preconditions']['uid'],UID)
    def test_ambiguous_create_is_preserved_and_never_deleted(self):
        h=a.Audit.__new__(a.Audit);h.owner=OWNER;h.report={'clusters':{'cmtc-a':{'pendingCreate':'/unknown'}},'cleanupErrors':[]};h.flush=lambda:None
        h.maybe=lambda *args:(_ for _ in ()).throw(AssertionError('cannot adopt unknown UID'));h.cleanup();self.assertEqual(len(h.report['cleanupErrors']),1);self.assertIn('preserved',h.report['cleanupErrors'][0]['error'])
if __name__=='__main__':unittest.main()
