"""Pure missing-panel regression checks; no network/commands."""
import ast
import copy
import importlib.util
from pathlib import Path
import unittest
p=Path(__file__).with_name('datapath_capture.py')
spec=importlib.util.spec_from_file_location('capture_candidate',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def evidence(profile='observer'):
    ids=(42,43,44,45) if profile=='observer' else (32,33,34,35,36)
    selections=[{'clusterSelection':c,'queries':[{'panelId':i,'panel':str(i),'response':{'data':{'result':[{'value':[1,'2']}]}}} for i in ids]} for c in ('cmtc-a|cmtc-b','cmtc-a','cmtc-b')]
    return {'selections':selections+[{'plannedSecurityPanels':[]} ]}

class Gate(unittest.TestCase):
    def test_both_profiles_complete_with_planned_metadata(self):
        for profile in ('fence','observer'):m.qualify_datapath_queries(evidence(profile),profile)
    def test_old_dashboard_with_no_observer_panels_rejected(self):
        with self.assertRaisesRegex(AssertionError,'missing observer panel'):m.qualify_datapath_queries(evidence('fence'),'observer')
    def test_empty_or_missing_selections_rejected(self):
        for data in ({},{'selections':[]},{'selections':[{'plannedSecurityPanels':[]}]}):
            with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
    def test_each_selection_must_include_every_expected_panel(self):
        for selected in range(3):
            for missing in range(4):
                data=evidence();data['selections'][selected]['queries'].pop(missing)
                with self.assertRaisesRegex(AssertionError,'missing observer panel'):m.qualify_datapath_queries(data,'observer')
    def test_missing_cluster_duplicate_and_unknown_selection_rejected(self):
        data=evidence();data['selections'].pop(1)
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
        data=evidence();data['selections'].append(copy.deepcopy(data['selections'][0]))
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
        data=evidence();data['selections'][0]['clusterSelection']='wrong'
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
    def test_empty_live_panel_or_zero_load_rate_rejected(self):
        data=evidence();data['selections'][0]['queries'][0]['response']['data']['result']=[]
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
        data=evidence();data['selections'][1]['queries'][1]['response']['data']['result'][0]['value'][1]='0'
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
    def test_unnamed_queries_rejected(self):
        data=evidence();data['selections'].append({'queries':[]})
        with self.assertRaises(AssertionError):m.qualify_datapath_queries(data,'observer')
    def test_freshness_hook_after_provision_before_browser_command(self):
        tree=ast.parse(p.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='capture_datapath')
        calls=[n for n in ast.walk(fn) if isinstance(n,ast.Call)]
        fresh=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='snapshot')
        verify=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='poll')
        browser=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='command' and any(k.arg=='label' and isinstance(k.value,ast.Constant) and k.value.value=='both-theme-grafana-capture' for k in n.keywords))
        self.assertLess(verify.lineno,fresh.lineno);self.assertLess(fresh.lineno,browser.lineno)

if __name__=='__main__':unittest.main()
