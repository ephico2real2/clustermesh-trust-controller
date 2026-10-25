import contextlib
import copy
import io
import sys
import unittest
from unittest.mock import patch
import public_proof as q
import render_spire as r
from test_public_proof import Fixture,FakeAPI,NOW

FORK='localhost/cmtc-spire-server:journal-qualified@sha256:'+'b'*64
OTHER='ghcr.io/ephico2real2/spire-server:next@sha256:'+'c'*64
POD='/api/v1/namespaces/cilium-spire/pods/spire-server-0'

def fork_pod(api,pin=FORK):
    obj=api.objects[POD]
    next(c for c in obj['spec']['containers'] if c['name']=='spire-server')['image']=pin
    obj['spec']['volumes'][0]['image']['reference']=pin
    next(c for c in obj['status']['containerStatuses'] if c['name']=='spire-server')['imageID']=pin.rsplit(':',1)[0]+':'+pin.rsplit(':',1)[1]

class ServerImagePinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fx=Fixture()
    def test_full_stock_and_independently_approved_registry_pins(self):
        for pin in [q.SERVER_IMAGE,FORK,OTHER,'localhost:5000/team/spire-server@sha256:'+'1'*64,'registry.example.test:443/team/spire_server:V1@sha256:'+'2'*64]:
            for module in [q,r]:
                with self.subTest(module=module.__name__,pin=pin):self.assertEqual(pin,module.approved_server_image(pin))
    def test_tag_only_unqualified_alias_bad_digest_port_host_and_nonstring_refused(self):
        invalid=[None,True,3,'spire-server@sha256:'+'a'*64,'owner/server@sha256:'+'a'*64,'localhost/server:latest','ghcr.io/team/server:latest',FORK.replace('sha256:','sha512:'),FORK[:-1],FORK.upper(),FORK+'\n','https://'+FORK,FORK.replace('localhost','bad..example'),FORK.replace('localhost','localhost:99999'),FORK.replace('localhost','localhost:00'),FORK.replace('/cmtc','//cmtc'),FORK.replace('/cmtc','/../cmtc')]
        for module in [q,r]:
            for pin in invalid:
                with self.subTest(module=module.__name__,pin=pin),self.assertRaises(module.Refusal):module.approved_server_image(pin)
    def invoke(self,api,server_image=FORK,mutate=None):
        f=self.fx
        def command(argv,uri):
            if mutate:mutate(api)
            return b'CMTC_AUTHORITY_BEFORE\n'+f.authority()+b'\nCMTC_CHAIN\n'+f.chain(f.leaf(uri))+b'CMTC_AUTHORITY_AFTER\n'+f.authority()+b'\nCMTC_END\n'
        return q.execute_proof(api,cluster='cmtc-a',cluster_uid='cluster-uid',pod_uid='pod-uid',approval_uid='approval-uid',root_pin=q.sha(q.der(f.root)),server_image=server_image,invoke=command,clock=lambda:NOW)
    def test_explicit_fork_pin_passes_actual_nonce_and_records_independent_approval(self):
        api=FakeAPI(self.fx);fork_pod(api)
        result=self.invoke(api)
        self.assertEqual(FORK,result['approvedServerImage']);self.assertFalse(result['protected']);self.assertFalse(result['workloadAttestation'])
    def test_stock_default_still_passes_and_never_infers_approval_from_fork_pod(self):
        result=self.invoke(FakeAPI(self.fx),server_image=q.SERVER_IMAGE);self.assertEqual(q.SERVER_IMAGE,result['approvedServerImage'])
        api=FakeAPI(self.fx);fork_pod(api)
        with self.assertRaises(q.Refusal):self.invoke(api,server_image=q.SERVER_IMAGE)
    def test_explicit_pin_must_match_both_pod_container_and_cli_image_volume(self):
        for where in ['container','cli']:
            api=FakeAPI(self.fx);fork_pod(api)
            if where=='container':api.objects[POD]['spec']['containers'][0]['image']=OTHER
            else:api.objects[POD]['spec']['volumes'][0]['image']['reference']=OTHER
            with self.subTest(where=where),self.assertRaises(q.Refusal):self.invoke(api)
    def test_invalid_explicit_pin_fails_before_any_authenticated_api_read(self):
        api=FakeAPI(self.fx)
        with self.assertRaises(q.Refusal):self.invoke(api,server_image='localhost/server:latest')
        self.assertEqual([],api.calls)
    def test_post_nonce_server_or_cli_image_mutation_refused(self):
        for where in ['container','cli']:
            api=FakeAPI(self.fx);fork_pod(api)
            def mutate(a):
                if where=='container':a.objects[POD]['spec']['containers'][0]['image']=OTHER
                else:a.objects[POD]['spec']['volumes'][0]['image']['reference']=OTHER
            with self.subTest(where=where),self.assertRaises(q.Refusal):self.invoke(api,mutate=mutate)
    def test_renderer_changes_only_explicit_server_and_cli_pins(self):
        for cluster in r.CLUSTERS:
            stock=r.render(cluster);fork=r.render(cluster,server_image=FORK)
            sts=next(o for o in fork if o['kind']=='StatefulSet' and o['metadata']['name']=='spire-server')
            spec=sts['spec']['template']['spec'];server=next(c for c in spec['containers'] if c['name']=='spire-server');volume=next(v for v in spec['volumes'] if v['name']=='spire-server-cli')
            self.assertEqual(FORK,server['image']);self.assertEqual(FORK,volume['image']['reference'])
            server['image']=r.SERVER_IMAGE;volume['image']['reference']=r.SERVER_IMAGE
            self.assertEqual(stock,fork)
    def test_image_map_cannot_sneak_in_a_server_override_without_explicit_approval(self):
        images=dict(r.PINNED_IMAGES,server=FORK)
        with self.assertRaises(r.Refusal):r.render('cmtc-a',images=images)
        r.render('cmtc-a',images=images,server_image=FORK)
        images['agent']=OTHER
        with self.assertRaises(r.Refusal):r.render('cmtc-a',images=images,server_image=FORK)
    def test_cli_rejects_invalid_pin_before_loading_transport_or_emitting_objects(self):
        stdout=io.StringIO();stderr=io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):self.assertEqual(2,r.main(['cmtc-a','--server-image','localhost/server:latest']))
        self.assertEqual('',stdout.getvalue())
        argv=['public_proof.py','--kubeconfig','not-used','--cluster','cmtc-a','--cluster-uid','c','--pod-uid','p','--approval-uid','a','--root-sha256','0'*64,'--pki-module','/must-not-be-opened','--server-image','localhost/server:latest']
        with patch.object(sys,'argv',argv),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as e:q.main()
        self.assertEqual(2,e.exception.code)
if __name__=='__main__':unittest.main()
