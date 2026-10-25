import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("issuer_lab", Path(__file__).with_name("test-issuer-profile.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def pub():
    now=int(time.time())
    stamp=lambda t:time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(t))
    return {"schemaVersion":1,"sequence":1,"state":"withdrawn","reason":"SourceDeleted","producerCluster":"cmtc-a","outputUID":"output-uid","expectedSourceUID":"source-uid","source":{"namespace":"cmtc-system","name":"approval","uid":"source-uid","resourceVersion":"","generation":0},"acceptedGeneration":0,"publishedAt":stamp(now),"validUntil":stamp(now)}
def encode(p):
    p=copy.deepcopy(p);p["digest"]=m.sha(m.compact(p));return m.compact(p)
def obj():return {"metadata":{"uid":"u1","resourceVersion":"22","labels":{m.OWNER:"run1"}},"data":{}}

class TestPublication(unittest.TestCase):
    def test_tombstone_digest(self):self.assertEqual(m.publication(encode(pub()),"cmtc-a","output-uid")["state"],"withdrawn")
    def test_wrong_cluster_uid_or_digest(self):
        for cluster,uid,raw in [("cmtc-b","output-uid",encode(pub())),("cmtc-a","foreign",encode(pub())),("cmtc-a","output-uid",encode(pub()).replace("SourceDeleted","SourceChanged"))]:
            with self.subTest(cluster=cluster,uid=uid),self.assertRaises(m.Refusal):m.publication(raw,cluster,uid)
    def test_duplicate_key_and_unknown_key(self):
        with self.assertRaises(m.Refusal):m.publication('{"schemaVersion":1,"schemaVersion":1}',"cmtc-a","output-uid")
        p=pub();p["unknown"]=1
        with self.assertRaises(m.Refusal):m.publication(encode(p),"cmtc-a","output-uid")
    def test_tombstone_cannot_carry_approval(self):
        p=pub();p["approval"]={}
        with self.assertRaises(m.Refusal):m.publication(encode(p),"cmtc-a","output-uid")
    def test_published_expired_or_unbounded(self):
        p=pub();p.update(state="published",reason="Validated",acceptedSourceUID="source-uid",acceptedGeneration=1,approval={"generation":1})
        p["approvalDigest"]=p["acceptedApprovalDigest"]=m.sha(m.compact(p["approval"]))
        now=time.time()
        for until in [now-1,now+40]:
            p["validUntil"]=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(until))
            with self.subTest(until=until),self.assertRaises(m.Refusal):m.publication(encode(p),"cmtc-a","output-uid",now)
    def test_go_html_escaping(self):self.assertEqual(m.compact({"value":"<>&"}),'{"value":"\\u003c\\u003e\\u0026"}')

class TestOwnership(unittest.TestCase):
    def test_uid_rv_owner_and_deleting(self):
        self.assertIs(m.owned(obj(),"run1","u1")["data"].__class__,dict)
        for mutate in [lambda o:o["metadata"].update(uid="replacement"),lambda o:o["metadata"].pop("resourceVersion"),lambda o:o["metadata"]["labels"].update({m.OWNER:"foreign"}),lambda o:o["metadata"].update(deletionTimestamp="now")]:
            o=obj();mutate(o)
            with self.subTest(o=o),self.assertRaises(m.Refusal):m.owned(o,"run1","u1")
    def test_uid_and_rv_are_atomic_patch_tests(self):
        self.assertEqual(m.tests_for(obj()),[{"op":"test","path":"/metadata/uid","value":"u1"},{"op":"test","path":"/metadata/resourceVersion","value":"22"}])
    def test_source_immutable_exact_data(self):
        o=obj();o.update(immutable=True,data={"approval.json":"{}"});m.check_source(o,"run1","u1")
        for key,value in [("immutable",False),("data",{"other":"{}"}),("binaryData",{"private":"x"})]:
            bad=copy.deepcopy(o);bad[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.check_source(bad,"run1","u1")
    def test_delete_refuses_replaced_uid_before_any_command(self):
        lab=m.Lab.__new__(m.Lab);lab.runid="run1";lab.owned={("ConfigMap","output"):"u1"};replacement=obj();replacement["metadata"]["uid"]="u2";lab.get=lambda *a,**k:replacement
        lab.k=lambda *a,**k:self.fail("attempted mutation")
        with self.assertRaises(m.Refusal):lab.delete_owned("ConfigMap","output")
    def test_patch_refuses_owner_change_before_command(self):
        lab=m.Lab.__new__(m.Lab);lab.runid="run1";lab.owned={("ConfigMap","output"):"u1"};replacement=obj();replacement["metadata"]["labels"][m.OWNER]="foreign";lab.get=lambda *a:replacement;lab.k=lambda *a,**k:self.fail("attempted mutation")
        with self.assertRaises(m.Refusal):lab.patch_owned("ConfigMap","output",[])
    def test_rollout_refuses_foreign_template_drift(self):
        lab=m.Lab.__new__(m.Lab);lab.snapshot={"metadata":{"uid":"dep"}};lab.expected_template={"a":1};lab.get=lambda *a:{"metadata":{"uid":"dep"},"spec":{"template":{"a":2}}};lab.k=lambda *a,**k:self.fail("attempted mutation")
        with self.assertRaises(m.Refusal):lab.rollout()
    def test_failed_restore_retains_authority(self):
        lab=m.Lab.__new__(m.Lab);lab.snapshot=None;lab.fatal=None;lab.owned={("ConfigMap","output"):"u1"};lab.events=[]
        class R:
            def stop(self):pass
        lab.r=R();lab.save=lambda:None;lab.event=lambda *a,**k:lab.events.append((a,k))
        def preflight():lab.snapshot={"metadata":{"uid":"dep"}}
        lab.preflight=preflight
        def rollout(*a,**k):raise m.Refusal("foreign Deployment drift")
        lab.rollout=rollout;lab.delete_owned=lambda *a:self.fail("authority deleted despite failed restoration")
        with self.assertRaises(m.Refusal):lab.execute()
        self.assertTrue(any(k.get("retainedAuthority") for a,k in lab.events))

class TestImageIdentity(unittest.TestCase):
    def test_wrong_revision_config_architecture_refused(self):
        from types import SimpleNamespace
        base={"status":{"id":"sha256:"+"a"*64},"info":{"imageSpec":{"architecture":"arm64","config":{"Labels":{"org.opencontainers.image.revision":"b"*40}}}}}
        for path in ["revision","id","arch"]:
            img=copy.deepcopy(base)
            if path=="revision":img["info"]["imageSpec"]["config"]["Labels"]["org.opencontainers.image.revision"]="c"*40
            if path=="id":img["status"]["id"]="sha256:"+"d"*64
            if path=="arch":img["info"]["imageSpec"]["architecture"]="amd64"
            lab=m.Lab.__new__(m.Lab);lab.a=SimpleNamespace(image="localhost/cmtc:test",image_id="sha256:"+"a"*64,source_sha="b"*40);lab.node=lambda *a:(0,json.dumps(img),"");lab.event=lambda *a,**k:None
            with self.subTest(path=path),self.assertRaises(m.Refusal):lab.inspect_image("node")
    def test_cli_limits_cluster_selection(self):
        args=m.parser().parse_args(["--image","localhost/cmtc:test","--image-id","sha256:"+"a"*64,"--source-sha","b"*40,"--binary-sha256","c"*64,"--fixtures","f","--out","o"])
        self.assertEqual(args.cluster,"both")




class TestManifestIdentity(unittest.TestCase):
    def test_import_alias_uses_same_manifest_digest(self):
        digest = "sha256:" + "a" * 64
        self.assertEqual(m.require_running_manifest("docker://docker.io/library/import-date@" + digest, ["localhost/cmtc:test@" + digest]), digest)
    def test_config_id_does_not_replace_manifest_membership(self):
        with self.assertRaises(m.Refusal):
            m.require_running_manifest("sha256:" + "b" * 64, ["localhost/cmtc:test@sha256:" + "a" * 64])
    def test_unresolved_tag_refused(self):
        with self.assertRaises(m.Refusal): m.require_running_manifest("localhost/cmtc:test", [])

class TestPublicationClock(unittest.TestCase):
    def test_future_publication_is_not_current(self):
        now = int(time.time())
        stamp = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        p=pub();p.update(state="published",reason="Validated",acceptedSourceUID="source-uid",acceptedGeneration=1,approval={"generation":1})
        p["approvalDigest"]=p["acceptedApprovalDigest"]=m.sha(m.compact(p["approval"]))
        p["publishedAt"]=stamp(now + 5);p["validUntil"]=stamp(now + 20)
        with self.assertRaises(m.Refusal): m.publication(encode(p), "cmtc-a", "output-uid", now)

class TestDisabledScrape(unittest.TestCase):
    def test_new_pod_requires_positive_fresh_observe_scrape(self):
        lab=m.Lab.__new__(m.Lab);lab.selector=lambda:'{instance="new-pod:8080"}';lab.event=lambda *a,**k:None
        calls=[];phase=[0]
        def query(q):
            calls.append(q)
            if q.startswith('timestamp('):return [{"value":[0,str(time.time() if phase[0]>1 else time.time()-60)]}]
            if q.startswith('cmtc_enforcement_available'):return [] if phase[0]==0 else [{"value":[0,"0"]}]
            return []
        lab.prom_query=query
        def wait(fn,label,timeout):
            self.assertFalse(fn(),"An unscripted new Pod cannot prove disabled telemetry")
            phase[0]=1;self.assertFalse(fn(),"A stale scrape cannot prove current Observe state")
            phase[0]=2;self.assertTrue(fn())
        lab.wait=wait;lab.metrics(active=False)
        self.assertTrue(any(q.startswith('timestamp(') for q in calls))

    def test_advertised_enforcement_is_rejected(self):
        lab=m.Lab.__new__(m.Lab);lab.selector=lambda:'{}';lab.prom_query=lambda q:[{"value":[0,"1"]}]
        lab.wait=lambda fn,*a,**k:fn()
        with self.assertRaises(m.Refusal):lab.metrics(active=False)

if __name__=="__main__":unittest.main()
