"""Pure adapter controls; real observer proof still requires actual local APIs."""
from copy import deepcopy
import datetime
import unittest
from fence_telemetry import OBSERVER_FAMILIES, compare, expected_nodes, snapshot


class ObserverTelemetryTests(unittest.TestCase):
    def test_observer_profile_preserves_actual_labels_and_families(self):
        expected=expected_nodes(['cmtc-a/cmtc-a-worker/ingress']);now=1800000000
        labels={'cluster':'cmtc-a','node':'cmtc-a-worker','component':'cmtc-bpf-observer','job':'cmtc','direction':'ingress'}
        def api(base,path,params):
            if path.endswith('targets'):
                return {'status':'success','data':{'activeTargets':[{'labels':labels,'health':'up','lastError':'','lastScrape':datetime.datetime.fromtimestamp(now-1,datetime.timezone.utc).isoformat()}]}}
            self.assertIn('component="cmtc-bpf-observer"',params['query'])
            family=params['query'].removeprefix('timestamp(').split('{')[0];self.assertIn(family,OBSERVER_FAMILIES)
            return {'status':'success','data':{'result':[{'metric':labels,'value':[now,str(now-1) if params['query'].startswith('timestamp(') else '1']} ]}}
        first=snapshot('local',expected,api=api,now=now,clock=lambda:now,profile='observer')
        self.assertEqual(first['families'],list(OBSERVER_FAMILIES))
        target=first['targets']['cmtc-a']['data']['activeTargets'][0]
        self.assertEqual(target['labels']['component'],'cmtc-bpf-observer')
        later=deepcopy(first);later['observedAt']+=15
        compare(first,later,idle=True)
        for family in OBSERVER_FAMILIES[1:]:later['values'][family]['cmtc-a/cmtc-a-worker/ingress']+=7
        compare(first,later)
        later['values'][OBSERVER_FAMILIES[1]]['cmtc-a/cmtc-a-worker/ingress']=0
        with self.assertRaises(AssertionError):compare(first,later)


if __name__=='__main__':unittest.main()
