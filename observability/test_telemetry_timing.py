import datetime
import unittest
from fence_telemetry import FAMILIES, expected_nodes, snapshot


class ScrapeTimingTests(unittest.TestCase):
    def test_scrape_after_query_anchor_is_fresh_at_actual_target_read(self):
        anchor=1800000000
        def api(base,path,params):
            if path.endswith('targets'):
                return {'status':'success','data':{'activeTargets':[{'labels':{'job':'cmtc','component':'cmtc-bpf-fence','cluster':'cmtc-a','node':'cmtc-a-worker'},'health':'up','lastError':'','lastScrape':datetime.datetime.fromtimestamp(anchor+1,datetime.timezone.utc).isoformat()}]}}
            return {'status':'success','data':{'result':[{'metric':{'cluster':'cmtc-a','node':'cmtc-a-worker','direction':'ingress'},'value':[anchor,str(anchor-1) if params['query'].startswith('timestamp(') else '1']}]}}
        report=snapshot('local',expected_nodes(['cmtc-a/cmtc-a-worker/ingress']),now=anchor,clock=lambda:anchor+2,api=api)
        self.assertEqual(report['observedAt'],anchor)
        self.assertEqual(report['targetCheckedAt']['cmtc-a'],anchor+2)
        self.assertEqual(set(report['queries']),set(FAMILIES))


if __name__=='__main__':unittest.main()
