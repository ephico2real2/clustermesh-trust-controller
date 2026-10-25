"""Pure proposal checks. No runner import, subprocess or runtime access."""
import ast
import json
from pathlib import Path
import re
from types import SimpleNamespace
import tempfile
import unittest

p=Path(__file__).with_name('test-fence-telemetry.py'); tree=ast.parse(p.read_text())
parts=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in ('targets','TelemetryFanout')]
def require(value,message):
    if not value: raise AssertionError(message)
ns={'fanout':SimpleNamespace(Fanout=object),'require':require,'re':re,'json':json}
exec(compile(ast.Module(body=parts,type_ignores=[]),str(p),'exec'),ns)
Runner=ns['TelemetryFanout']; targets=ns['targets']

class Pure(unittest.TestCase):
    def test_targets_explicit_actual_contexts(self):
        self.assertEqual(targets(['cmtc-a=http://127.0.0.1:13000/api/proxy','cmtc-b=http://127.0.0.1:19091'],['cmtc-a','cmtc-b'])['cmtc-b'],'http://127.0.0.1:19091')
        for items in (['cmtc-a=http://x'],['cmtc-a=http://x','cmtc-a=http://y'],['cmtc-a=file:///x','cmtc-b=http://y']):
            with self.assertRaises(AssertionError): targets(items,['cmtc-a','cmtc-b'])
    def test_binding_map_replacement_detected(self):
        first={'c/n/ingress':{'mapID':1,'chain':[2,3],'namespaceUID':'ns','podUID':'pod','imageID':'image','revision':'rev'}}
        Runner.same_bindings(first,first)
        for field in first['c/n/ingress']:
            other=json.loads(json.dumps(first)); other['c/n/ingress'][field]='changed'
            with self.assertRaises(AssertionError): Runner.same_bindings(first,other)
    def test_retention_never_overwrites_retried_phase(self):
        with tempfile.TemporaryDirectory() as d:
            r=Runner.__new__(Runner); r.telemetry_out=Path(d)
            a=r.retain('idle-kernel-a',{'n':1}); b=r.retain('idle-kernel-a',{'n':2})
            self.assertNotEqual(a,b); self.assertEqual(json.loads(Path(a).read_text()),{'n':1})
    def test_snapshot_failure_retains_partial_before_success(self):
        with tempfile.TemporaryDirectory() as d:
            r=Runner.__new__(Runner); r.telemetry_out=Path(d);r.telemetry_sequence=0
            r.args=SimpleNamespace(prometheus='http://central');r.expected={('c','n','ingress')};r.target_urls={'c':'http://local'}
            calls=[]
            def snapshot(base,expected,**kwargs):
                report=kwargs['report']; report['targets']={'c':'partial-local-proof'};calls.append(1)
                if len(calls)==1: raise AssertionError('first scrape pending')
                return report
            r.telemetry=SimpleNamespace(snapshot=snapshot)
            ns['time']=SimpleNamespace(monotonic=lambda:1,sleep=lambda n:None)
            report=r.snapshot('installed')
            self.assertTrue(report['passed']); files=sorted(Path(d).glob('*.json'));self.assertEqual(len(files),2)
            failure=json.loads(files[0].read_text());self.assertFalse(failure['passed']);self.assertEqual(failure['targets'],{'c':'partial-local-proof'})
    def test_snapshot_timeout_keeps_failure_and_propagates(self):
        with tempfile.TemporaryDirectory() as d:
            r=Runner.__new__(Runner);r.telemetry_out=Path(d);r.telemetry_sequence=0;r.args=SimpleNamespace(prometheus='http://central');r.expected=set();r.target_urls={}
            r.telemetry=SimpleNamespace(snapshot=lambda *a,**kw:(_ for _ in ()).throw(AssertionError('missing series')))
            times=iter([0,100]);ns['time']=SimpleNamespace(monotonic=lambda:next(times),sleep=lambda n:None)
            with self.assertRaisesRegex(AssertionError,'missing series'):r.snapshot('absent',absent=True,timeout=90)
            self.assertEqual(len(list(Path(d).glob('*.json'))),1)

if __name__=='__main__':unittest.main()
