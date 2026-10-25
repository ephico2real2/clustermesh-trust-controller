"""Fake-command structural tests; no kube/Colima/BPF qualification claim."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

LIB = Path(__file__).resolve().parent
ROOT = LIB.parents[1]
spec = importlib.util.spec_from_file_location('fanout_candidate', LIB/'test-fence-fanout.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def result(code=0, stdout=''):
    return subprocess.CompletedProcess([],code,stdout,'')


def route(cluster='cmtc-a', node='cmtc-a-control-plane'):
    h=m.NodeHarness.__new__(m.NodeHarness)
    h.cluster=cluster; h.physical_node=node; h.run_id='testrun'; h.ns='own-ns'; h.parents={}
    h.report={'clusters': {},'cleanupErrors': []}; h.flush=lambda: None
    h.args=SimpleNamespace(image='localhost/fence:test',image_id='sha256:'+'1'*64,client_image='curlimages/curl:8.14.1')
    return h


class Structural(unittest.TestCase):
    def setUp(self):
        self.no_exec=patch('subprocess.run',side_effect=AssertionError('real subprocess forbidden'))
        self.no_exec.start()
    def tearDown(self): self.no_exec.stop()

    def test_uncached_or_invalid_client_configuration_fails_without_waiting(self):
        h=m.lab.FenceHarness.__new__(m.lab.FenceHarness)
        for reason in ('ErrImageNeverPull', 'CreateContainerConfigError'):
            h.own_pod=lambda c,reason=reason:{'status':{'containerStatuses':[{'ready':False,'state':{'waiting':{'reason':reason}}}]}}
            with self.subTest(reason=reason), self.assertRaisesRegex(AssertionError,'client prerequisite rejected'):
                h._ready_client('cmtc-a')
        h.own_pod=lambda c:{'status':{'containerStatuses':[{'ready':False,'state':{'waiting':{'reason':'ContainerCreating'}}}]}}
        self.assertFalse(h._ready_client('cmtc-a'))
        ready={'status':{'containerStatuses':[{'ready':True}]}}
        h.own_pod=lambda c:ready
        self.assertIs(h._ready_client('cmtc-a'),ready)

    def test_physical_node_route_never_aliases_cluster(self):
        h=route(); calls=[]
        h.command=lambda argv,**kw: calls.append(argv) or result()
        h.node('cmtc-a','true')
        self.assertEqual(calls[0][-2:],['cmtc-a-control-plane','true'])
        self.assertEqual(h.node_name('cmtc-a'),'cmtc-a-control-plane')
        with self.assertRaisesRegex(AssertionError,'crossed actual cluster'): h.node('cmtc-b','true')
        self.assertEqual(len(calls),1)

    def test_prepare_owns_only_actual_cluster_and_separate_backend_catalogue(self):
        h=route(); backends={'cmtc-a': {'name':'a','uid':'a1','ip':'1.1.1.1'},'cmtc-b': {'name':'b','uid':'b1','ip':'2.2.2.2'}}
        def get(cluster,kind,name=None,*args,**kw):
            self.assertEqual(cluster,'cmtc-a')
            if kind=='node': return {'metadata': {'uid':'node1','labels': {}}}
            if kind=='namespace': return None if kw.get('absent') else {'metadata': {'uid':'ns1'}}
            raise AssertionError(kind)
        h.get=get; h.kubectl=lambda *a,**kw: result(stdout=json.dumps({'items':[{'metadata':{'name':'agent','uid':'ag1'},'status':{'containerStatuses':[{'ready':True}]}}]}))
        h.tc=lambda c: []; h.create=lambda *a: None; h.prepare_roots=lambda c: None
        h.node=lambda c,*a,**kw: result(stdout=json.dumps({'status':{'id':h.args.image_id},'info':{'imageSpec':{'architecture':'arm64'}}})) if a[0]=='crictl' else result()
        h.new_client=lambda c: {'metadata':{'uid':'pod1'}}
        def audit(c,p,d):
            phase={'config':{'ifIndex':11},'direction':d}; h.state()['phases'].append(phase); return phase
        h.audit=audit; h.chain_for=lambda *a: []; h.traffic=lambda *a: None
        h.prepare(backends)
        self.assertEqual(set(h.report['clusters']),{'cmtc-a'})
        self.assertEqual(h.backend('cmtc-b')['uid'],'b1')
        backends['cmtc-b']['uid']='changed'
        self.assertEqual(h.backend('cmtc-b')['uid'],'b1')
        self.assertEqual(h.state()['namespaceUID'],'ns1')
        self.assertFalse(h.phase()['nativeEgressQualified'])

    def fanout(self):
        f=m.Fanout.__new__(m.Fanout); f.run_id='testrun'; f.report={'errors':[]}; f.flush=lambda: None
        a,b=route(),route(node='cmtc-a-worker')
        for h in (a,b):
            cfg={'node':h.physical_node,'cluster':h.cluster,'namespaceUID':h.physical_node+'-ns','podUID':h.physical_node+'-pod'}
            h.report['clusters'][h.cluster]={'phases':[{'config':cfg}]}
            h.parents={'pinRoot':{'path':'/sys/fs/bpf/cmtc-fence-testrun','stat':'directory|0|700|1|2'},'lockRoot':{'path':'/run/cmtc-fence-testrun','stat':'directory|0|700|3|4'}}
        f.routes={(h.cluster,h.physical_node):h for h in(a,b)}
        return f,a,b

    def test_immutable_node_config_keys_and_swapped_negative(self):
        f,a,b=self.fanout(); captured=[]; a.create=lambda c,body: captured.append((c,body))
        f.create_config('cmtc-a'); f.create_config('cmtc-a',swapped=True)
        good,bad=[body for c,body in captured]
        self.assertTrue(good['immutable']); self.assertEqual(set(good['data']),{a.physical_node+'.json',b.physical_node+'.json'})
        for node in (a.physical_node,b.physical_node):
            self.assertEqual(json.loads(good['data'][node+'.json'])['node'],node)
            self.assertNotEqual(json.loads(bad['data'][node+'.json'])['node'],node)
            self.assertEqual(json.loads(bad['data'][node+'.json'])['cluster'],'cmtc-a')

    def test_fanout_manifest_contract_and_narrow_rendering(self):
        from fence_manifest_contract import validate_fence_template
        f,a,b=self.fanout(); template=json.loads((ROOT/'config/experimental/datapath-fence-fanout.yaml').read_text())
        a.template=validate_fence_template(template,fanout=True)
        f.args=SimpleNamespace(image='localhost/fence:exact'); captured=[]; a.create=lambda c,body: captured.append(body)
        f.create_ds('cmtc-a','immutable-cm')
        spec=captured[0]['spec']['template']['spec']
        self.assertEqual(spec['nodeSelector'],{m.lab.OPTIN:'true',m.RUN_SELECTOR:'testrun'})
        self.assertEqual(captured[0]['spec']['updateStrategy'],{'type':'OnDelete'})
        self.assertEqual(spec['containers'][0]['imagePullPolicy'],'Never')
        mounts={v['name']:v for v in spec['containers'][0]['volumeMounts']}
        for name,path in (('pins','/cmtc-pins'),('locks','/cmtc-locks')):
            self.assertEqual(mounts[name]['mountPath'],path); self.assertEqual(mounts[name]['subPathExpr'],'$(NODE_NAME)')
        self.assertIn({'name':'CMTC_FENCE_POD_UID','valueFrom':{'fieldRef':{'fieldPath':'metadata.uid'}}},spec['containers'][0]['env'])
        self.assertNotIn(m.RUN_SELECTOR,template['spec']['template']['spec']['nodeSelector'])

    def parent_fixture(self,shared=False,changed=False,absent=False):
        f,a,b=self.fanout(); calls=[]
        # Keep one path for concise per-physical-node cleanup assertions.
        for h in (a,b): h.parents={'pinRoot':h.parents['pinRoot']}
        common={'exists':not absent}; local=[{'exists':not absent},{'exists':not absent}]
        for i,h in enumerate((a,b)):
            state=common if shared else local[i]
            def node(cluster,*argv,_h=h,_state=state,**kw):
                self.assertEqual(cluster,_h.cluster); calls.append((_h.physical_node,argv))
                if argv[0]=='stat': return result(0,('changed' if changed else _h.parents['pinRoot']['stat'])+'\n') if _state['exists'] else result(1)
                if argv[0]=='rmdir': self.assertTrue(_state['exists']); _state['exists']=False; return result()
                if argv[0]=='sh': return result(0 if not _state['exists'] else 1)
                raise AssertionError(argv)
            h.node=node
        return f,calls

    def test_identical_tokens_on_distinct_nodes_are_both_checked_and_removed(self):
        f,calls=self.parent_fixture(); f.remove_parents()
        self.assertEqual(f.report['errors'],[])
        self.assertEqual([n for n,a in calls if a[0]=='rmdir'],['cmtc-a-control-plane','cmtc-a-worker'])
        self.assertEqual(len([1 for n,a in calls if a[0]=='stat']),2)

    def test_shared_parent_absence_is_confirmed_on_second_actual_node(self):
        f,calls=self.parent_fixture(shared=True); f.remove_parents()
        self.assertEqual(f.report['errors'],[])
        self.assertEqual(len([1 for n,a in calls if a[0]=='rmdir']),1)
        self.assertEqual(len([1 for n,a in calls if a[0]=='stat']),2)
        self.assertTrue(any(n=='cmtc-a-worker' and a[0]=='sh' for n,a in calls))

    def test_unknown_absence_retains_error(self):
        f,calls=self.parent_fixture(absent=True); f.remove_parents()
        self.assertEqual(len(f.report['errors']),2)
        self.assertFalse(any(a[0]=='rmdir' for n,a in calls))

    def test_changed_parent_incarnation_refuses_deletion(self):
        f,calls=self.parent_fixture(changed=True); f.remove_parents()
        self.assertEqual(len(f.report['errors']),2)
        self.assertFalse(any(a[0]=='rmdir' for n,a in calls))

if __name__=='__main__': unittest.main()
