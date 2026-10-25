import re
import unittest
import build


class DatapathPanelTests(unittest.TestCase):
    def test_both_sources_keep_separate_meanings_and_existing_pages(self):
        dashboards=build.dashboards()
        self.assertEqual(set(dashboards),{'operations.json','workload-security.json'})
        panels={p['id']:p for p in build.all_panels(dashboards['operations.json'])}
        self.assertIn('Inventory/controller',panels[14]['title'])
        self.assertEqual({p['id'] for p in panels.values() if p['id']<100 and p['type']!='row'},set(range(1,23))-{2,7,13,21}|{31,32,33,34,35,36,41,42,43,44,45})
        for id in (32,33,34,35,36):
            for target in panels[id].get('targets',[]):self.assertIn('component="cmtc-bpf-fence"',target['expr'])
        for id in (42,43,44,45):
            for target in panels[id].get('targets',[]):self.assertIn('component="cmtc-bpf-observer"',target['expr'])
        self.assertIn('NEXT',panels[41]['options']['content'])
        for id in (32,33,34,35,36,42,43,44,45):
            for t in panels[id]['targets']:self.assertNotIn('vector(0)',t['expr'])
        self.assertFalse(any(p['type']=='piechart' for id,p in panels.items() if 30<=id<=45))
        for id in (33,35,43,44):
            p=panels[id]
            self.assertEqual(p['options']['legend']['placement'],'bottom')
            self.assertEqual(p['fieldConfig']['defaults']['custom']['lineWidth'],1)
            self.assertEqual(p['fieldConfig']['defaults']['custom']['fillOpacity'],10)
            self.assertEqual(p['fieldConfig']['defaults']['min'],0)
            self.assertEqual(set(re.findall(r'#[a-fA-F0-9]{6}',str(p['fieldConfig']))),{build.BLUE,build.RED})
            self.assertIn('rate(',p['targets'][0]['expr'])


if __name__=='__main__':unittest.main()
