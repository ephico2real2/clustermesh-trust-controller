"""Structural lifecycle tests of the actual proposed Fanout.execute method.
No subprocess, Kubernetes, images or kernel operations are invoked.
"""
import ast
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import traceback
import unittest

candidate=Path(__file__).with_name('test-fence-fanout.py')
module=ast.parse(candidate.read_text(),filename=str(candidate))
class_node=next(n for n in module.body if isinstance(n,ast.ClassDef) and n.name=='Fanout')
ns={'json':json,'traceback':traceback}
exec(compile(ast.Module(body=[class_node],type_ignores=[]),str(candidate),'exec'),ns)
Fanout=ns['Fanout']


class Flow(Fanout):
    def __init__(self, fail=None):
        self.args=SimpleNamespace(clusters=['cmtc-a','cmtc-b'])
        self.report={'status':'running','errors':[]}; self.events=[]; self.active=set(); self.fail=fail
        self.routes={}
        for cluster in self.args.clusters:
            for suffix in ('control-plane','worker'):
                node=cluster+'-'+suffix
                self.routes[(cluster,node)]=SimpleNamespace(physical_node=node,out=Path('/nonexistent')/node,
                    prepare=lambda backends,node=node:self.events.append(('prepare',node)),
                    select=lambda enabled,node=node:self.events.append(('select',node,enabled)))
    def backends(self): return {'actual':'backend catalogue'}
    def continuity(self,label): self.events.append(('continuity',label))
    def flush(self): pass
    def install_cluster(self,cluster):
        self.events.append(('install',cluster))
        if self.fail=='install' and cluster=='cmtc-b': raise RuntimeError('install failed')
        self.active.update(node for (c,node) in self.routes if c==cluster)
    def after_all_installed(self):
        self.events.append(('installed-hook',tuple(sorted(self.active))))
        assert self.active=={node for c,node in self.routes},'hook lacks all four nodes'
        if self.fail=='installed-hook': raise RuntimeError('installed hook failed')
    def exercise_cluster(self,cluster):
        self.events.append(('exercise',cluster))
        assert {node for (c,node) in self.routes if c==cluster}<=self.active
        if self.fail=='exercise': raise RuntimeError('exercise failed')
        self.active.difference_update(node for (c,node) in self.routes if c==cluster)
    def after_all_removed(self):
        self.events.append(('removed-hook',tuple(sorted(self.active))))
        assert not self.active,'absent hook still has active DS'
        if self.fail=='removed-hook': raise RuntimeError('removed hook failed')
    def cleanup(self): self.events.append(('cleanup',tuple(sorted(self.active)))); self.active.clear()


class Lifecycle(unittest.TestCase):
    def run_flow(self,fail=None):
        f=Flow(fail)
        with contextlib.redirect_stdout(io.StringIO()): code=f.execute()
        return f,code
    def test_both_clusters_four_nodes_installed_before_hook_before_recovery(self):
        f,code=self.run_flow(); self.assertEqual(code,0)
        lifecycle=[e[0] for e in f.events if e[0] in ('install','installed-hook','exercise','removed-hook','cleanup')]
        self.assertEqual(lifecycle,['install','install','installed-hook','exercise','exercise','removed-hook','cleanup'])
        self.assertEqual(len(next(e[1] for e in f.events if e[0]=='installed-hook')),4)
        self.assertEqual(next(e[1] for e in f.events if e[0]=='removed-hook'),())
        self.assertEqual([e[1] for e in f.events if e[0]=='install'],['cmtc-a','cmtc-b'])
        self.assertEqual([e[1] for e in f.events if e[0]=='exercise'],['cmtc-a','cmtc-b'])
    def test_installed_hook_failure_still_cleans_all_four_nodes(self):
        f,code=self.run_flow('installed-hook'); self.assertEqual(code,1)
        self.assertNotIn('exercise',[e[0] for e in f.events])
        self.assertEqual(len(f.events[-1][1]),4); self.assertEqual(f.events[-1][0],'cleanup'); self.assertFalse(f.active)
    def test_install_failure_skips_hooks_and_cleans_partial(self):
        f,code=self.run_flow('install'); self.assertEqual(code,1)
        self.assertFalse(any(e[0].endswith('hook') for e in f.events))
        self.assertEqual(len(f.events[-1][1]),2); self.assertFalse(f.active)
    def test_exercise_failure_skips_absent_hook_and_cleans(self):
        f,code=self.run_flow('exercise'); self.assertEqual(code,1)
        self.assertNotIn('removed-hook',[e[0] for e in f.events]); self.assertEqual(f.events[-1][0],'cleanup'); self.assertFalse(f.active)
    def test_removed_hook_failure_still_cleans_and_fails(self):
        f,code=self.run_flow('removed-hook'); self.assertEqual(code,1)
        self.assertEqual(f.events[-1][0],'cleanup'); self.assertEqual(f.report['status'],'failed')
    def test_default_hooks_are_noops(self):
        f=Fanout.__new__(Fanout)
        self.assertIsNone(f.after_all_installed()); self.assertIsNone(f.after_all_removed())

if __name__=='__main__': unittest.main()
