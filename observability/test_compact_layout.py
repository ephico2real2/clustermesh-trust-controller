import copy
import unittest
import build
import validate

class CompactLayoutTests(unittest.TestCase):
    def test_planned_and_optional_panels_remain_query_validated(self):
        dashboards=build.dashboards()
        for dashboard in dashboards.values():
            top=dashboard['panels'];all_panels=list(build.all_panels(dashboard))
            self.assertGreater(len(all_panels),len(top))
            self.assertFalse(any('· planned' in p['title'] for p in top if p['type']!='row'))
            self.assertTrue(any('· planned' in p['title'] and p['collapsed'] and p['panels'] for p in top if p['type']=='row'))
        operations,security=dashboards.values()
        validate.check_dashboards(operations,security)
        validate.domain_coverage(operations,security)
        broken=copy.deepcopy(operations)
        planned=next(p for p in build.all_panels(broken) if p['type']!='row' and p['id']>=100)
        planned['targets'][0]['expr']='vector(0)'
        with self.assertRaises(AssertionError):validate.check_dashboards(broken,security)
    def test_security_shows_coverage_and_live_producer_before_native_details(self):
        security=build.security()
        expanded=[p['id'] for p in security['panels'] if p['type']=='row' and not p['collapsed']]
        self.assertEqual(expanded,[2,23])
        covered={p['id'] for p in build.all_panels(security)}
        self.assertTrue({7,8,9,18,21}<=covered)
        self.assertIn('None reporting',str(next(p for p in security['panels'] if p['id']==3)))
        self.assertEqual(next(v for v in security['templating']['list'] if v['name']=='namespace')['allValue'],'.*')
    def test_top_level_rows_do_not_overlap_after_collapse(self):
        for dashboard in build.dashboards().values():
            rectangles=[p['gridPos'] for p in dashboard['panels']]
            for i,a in enumerate(rectangles):
                for b in rectangles[i+1:]:
                    overlap=a['x']<b['x']+b['w'] and b['x']<a['x']+a['w'] and a['y']<b['y']+b['h'] and b['y']<a['y']+a['h']
                    self.assertFalse(overlap,(a,b))

if __name__=='__main__':unittest.main()
