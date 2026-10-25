"""Pure negative/control tests for real-API evidence validation; no cluster IO."""
from copy import deepcopy
import datetime
import unittest
from fence_telemetry import FAMILIES, compare, expected_nodes, snapshot


class FenceTelemetryTests(unittest.TestCase):
    def fixture(self):
        expected = expected_nodes(["cmtc-a/a-worker/ingress", "cmtc-b/b-worker/ingress"])
        now = 1800000000
        rows = [{"metric": {"cluster":c,"node":n,"direction":d,"exported_cluster":c,"exported_node":n}, "value":[now,"1"]} for c,n,d in sorted(expected)]
        targets = {c: {"status":"success","data":{"activeTargets":[{"labels":{"cluster":c,"node":n,"component":"cmtc-bpf-fence","job":"cmtc"},"health":"up","lastError":"","lastScrape":datetime.datetime.fromtimestamp(now-1,datetime.timezone.utc).isoformat()} for ec,n,_ in expected if ec==c]}} for c,_,_ in expected}
        bodies = {name:{"status":"success","data":{"result":deepcopy(rows)}} for name in FAMILIES}
        def api(base,path,params):
            if path.endswith("targets"): return targets[base]
            query=params["query"]
            body=bodies[query.removeprefix("timestamp(").split("{")[0]]
            if query.startswith("timestamp("):
                body=deepcopy(body)
                for row in body["data"]["result"]: row["value"][1]=str(now-1)
            return body
        return expected, now, targets, bodies, api

    def test_real_targets_and_series_contract(self):
        expected,now,_,_,api=self.fixture()
        report=snapshot("central",expected,target_bases={"cmtc-a":"cmtc-a","cmtc-b":"cmtc-b"},api=api,now=now,clock=lambda:now)
        self.assertEqual(len(report["values"][FAMILIES[1]]),2)
        self.assertEqual(set(report["targets"]),{"cmtc-a","cmtc-b"})

    def test_receiver_targets_are_not_remote_scrape_evidence(self):
        expected,now,_,_,api=self.fixture()
        with self.assertRaises(AssertionError):snapshot("central",expected,api=api,now=now,clock=lambda:now)

    def test_wrong_down_missing_duplicate_stale_sources_refused(self):
        for mode in ("missingTarget","duplicateTarget","down","stale","targetCluster","missingMetric","duplicateMetric","unverified","nonfinite","exportedCluster","uidLabel"):
            with self.subTest(mode=mode):
                expected,now,targets,bodies,api=self.fixture()
                target=targets["cmtc-a"]["data"]["activeTargets"][0]
                if mode=="missingTarget": targets["cmtc-a"]["data"]["activeTargets"].clear()
                if mode=="duplicateTarget":targets["cmtc-a"]["data"]["activeTargets"].append(deepcopy(target))
                if mode=="down":target["health"]="down"
                if mode=="stale":target["lastScrape"]="2020-01-01T00:00:00Z"
                if mode=="targetCluster":target["labels"]["cluster"]="wrong"
                if mode=="missingMetric":bodies[FAMILIES[1]]["data"]["result"].pop()
                if mode=="duplicateMetric":bodies[FAMILIES[1]]["data"]["result"].append(deepcopy(bodies[FAMILIES[1]]["data"]["result"][0]))
                if mode=="unverified":bodies[FAMILIES[0]]["data"]["result"][0]["value"][1]="0"
                if mode=="nonfinite":bodies[FAMILIES[1]]["data"]["result"][0]["value"][1]="NaN"
                if mode=="exportedCluster":bodies[FAMILIES[1]]["data"]["result"][0]["metric"]["exported_cluster"]="wrong"
                if mode=="uidLabel":bodies[FAMILIES[1]]["data"]["result"][0]["metric"]["pod_uid"]="unbounded"
                evidence={}
                with self.assertRaises(AssertionError):snapshot("central",expected,target_bases={"cmtc-a":"cmtc-a","cmtc-b":"cmtc-b"},api=api,now=now,clock=lambda:now,report=evidence)
                self.assertIn("targets",evidence)

    def test_old_remote_write_sample_refused_despite_current_target(self):
        expected,now,_,_,original=self.fixture()
        for mode in ('stale','missing','duplicate','future'):
            with self.subTest(mode=mode):
                def api(base,path,params):
                    body=deepcopy(original(base,path,params))
                    if params.get('query','').startswith('timestamp('):
                        rows=body['data']['result']
                        if mode=='stale': rows[0]['value'][1]=str(now-60)
                        if mode=='future': rows[0]['value'][1]=str(now+1)
                        if mode=='missing': rows.pop()
                        if mode=='duplicate': rows.append(deepcopy(rows[0]))
                    return body
                with self.assertRaises(AssertionError):
                    snapshot('central',expected,target_bases={'cmtc-a':'cmtc-a','cmtc-b':'cmtc-b'},api=api,now=now,clock=lambda:now)

    def test_absent_is_empty_not_zero(self):
        expected,now,targets,bodies,api=self.fixture()
        for body in targets.values():body["data"]["activeTargets"].clear()
        for body in bodies.values():body["data"]["result"].clear()
        report=snapshot("central",expected,absent=True,target_bases={"cmtc-a":"cmtc-a","cmtc-b":"cmtc-b"},api=api,now=now,clock=lambda:now)
        self.assertTrue(report["absent"])
        bodies[FAMILIES[1]]["data"]["result"]=[{"metric":{},"value":[now,"0"]}]
        with self.assertRaises(AssertionError):snapshot("central",expected,absent=True,target_bases={"cmtc-a":"cmtc-a","cmtc-b":"cmtc-b"},api=api,now=now,clock=lambda:now)

    def test_idle_load_reset_and_scope_changes(self):
        expected,now,_,_,api=self.fixture()
        before=snapshot("central",expected,target_bases={"cmtc-a":"cmtc-a","cmtc-b":"cmtc-b"},api=api,now=now,clock=lambda:now)
        after=deepcopy(before);after["observedAt"]+=15
        compare(before,after,idle=True)
        with self.assertRaises(AssertionError):compare(before,after)
        for family in FAMILIES[1:]:
            for key in after["values"][family]:after["values"][family][key]+=7
        compare(before,after)
        with self.assertRaises(AssertionError):compare(before,after,idle=True)
        family=FAMILIES[1];after["values"][family][after["expected"][0]]=0
        with self.assertRaises(AssertionError):compare(before,after)
        after["expected"].pop()
        with self.assertRaises(AssertionError):compare(before,after)


if __name__=="__main__":unittest.main()
