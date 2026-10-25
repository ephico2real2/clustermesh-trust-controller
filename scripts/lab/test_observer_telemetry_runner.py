"""Pure code/lifecycle checks, no imports that invoke runtime APIs."""
import ast
import datetime
import json
from pathlib import Path
from types import SimpleNamespace
import traceback
import unittest

HERE=Path(__file__).resolve().parent
proposed=ast.parse((HERE/'test-observer.py').read_text())
new=next(n for n in proposed.body if isinstance(n,ast.ClassDef) and n.name=='Harness')
ns={'ObserverLogCaptureMixin':object,'traceback':traceback,'datetime':datetime}
exec(compile(ast.Module(body=[new],type_ignores=[]),'candidate-observer','exec'),ns)
Harness=ns['Harness']

class Flow(Harness):
    def __init__(self,fail=False):self.report={'status':'running','cleanupErrors':[]};self.events=[];self.active=set();self.fail=fail
    def preflight(self):self.events.append('preflight')
    def prepare_cluster(self,c):self.events.append(('prepare',c));self.active.add(c)
    def exercise_cluster(self,c):self.events.append(('exercise',c));self.active.remove(c)
    def after_all_installed(self):
        self.events.append(('installed',set(self.active)));assert self.active=={'cmtc-a','cmtc-b'}
        if self.fail:raise AssertionError('hook failed')
    def after_all_removed(self):self.events.append(('removed',set(self.active)));assert not self.active
    def cleanup(self):self.events.append('cleanup');self.active.clear()
    def flush(self):pass

runner=ast.parse((HERE/'test-observer-telemetry.py').read_text())
parts=[n for n in runner.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ('one','sum_percpu','ObserverTelemetryHarness')]
def require(v,m):
    if not v:raise AssertionError(m)
rns={'require':require,'observer':SimpleNamespace(Harness=object),'CLUSTERS':('cmtc-a','cmtc-b')}
exec(compile(ast.Module(body=parts,type_ignores=[]),'candidate-telemetry','exec'),rns)

class Proposal(unittest.TestCase):
    def test_both_installed_before_hook_and_original_exercises(self):
        f=Flow();self.assertEqual(f.execute(),0)
        self.assertEqual(f.events,['preflight',('prepare','cmtc-a'),('prepare','cmtc-b'),('installed',{'cmtc-a','cmtc-b'}),('exercise','cmtc-a'),('exercise','cmtc-b'),('removed',set()),'cleanup'])
    def test_hook_error_cleans_both_and_skips_exercises(self):
        f=Flow(True);self.assertEqual(f.execute(),1);self.assertEqual(f.events[-1],'cleanup');self.assertFalse(f.active)
        self.assertFalse(any(isinstance(e,tuple) and e[0]=='exercise' for e in f.events))
    def test_btf_percpu_sum(self):
        self.assertEqual(rns['sum_percpu']([{'values':[{'value':{'packets':2,'bytes':100}},{'value':{'packets':3,'bytes':200}}]}]),{'packets':5,'bytes':300})
    def test_raw_u64_percpu_sum(self):
        raw=(7).to_bytes(8,'little')+(900).to_bytes(8,'little')
        self.assertEqual(rns['sum_percpu']([{'values':[{'value':[hex(b) for b in raw]}]}]),{'packets':7,'bytes':900})
    def test_unknown_map_layout_refused(self):
        for value in ([],[{'values':[]}],[{'values':[{'value':[0]}]}],[{'values':[{'value':{'packets':1,'other':2}}]}]):
            with self.assertRaises(AssertionError):rns['sum_percpu'](value)
    def test_counter_map_reset_inside_load_is_rejected(self):
        cls=rns['ObserverTelemetryHarness'];before={'x':{'programID':1,'mapID':2,'chain':[3],'podUID':'p','imageID':'i','revision':'r'}}
        cls.same_bindings(before,before)
        after=json.loads(json.dumps(before));after['x']['mapID']=4
        with self.assertRaises(AssertionError):cls.same_bindings(before,after)
    def test_snapshot_selects_observer_profile(self):
        cls=rns['ObserverTelemetryHarness'];h=cls.__new__(cls);h.expected={('cmtc-a','n','ingress')};h.target_urls={'cmtc-a':'local'};h.args=SimpleNamespace(prometheus='central');calls=[]
        h.telemetry=SimpleNamespace(snapshot=lambda *a,**kw:calls.append(kw) or kw['report']);h.retain=lambda *a:None
        rns['time']=SimpleNamespace(monotonic=lambda:0)
        self.assertTrue(h.snapshot('test')['passed']);self.assertEqual(calls[0]['profile'],'observer')
        self.assertEqual(calls[0]['target_bases'],{'cmtc-a':'local'})

if __name__=='__main__':unittest.main()
