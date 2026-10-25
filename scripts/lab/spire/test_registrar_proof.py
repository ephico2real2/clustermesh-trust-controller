"""Place alongside existing scripts/lab/spire/test_public_proof.py for tests."""
import copy
import unittest
import public_proof as p
from test_public_proof import Fixture,FakeAPI,NOW

IMAGE='localhost/cmtc-spire-registrar@sha256:'+'a'*64
PATH='/api/v1/namespaces/cilium-spire/pods/spire-server-0'

class RegistrarProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fx=Fixture()
    def api(self):
        api=FakeAPI(self.fx);pod=api.objects[PATH]
        pod['spec']['containers'].append({'name':'cmtc-spire-registrar','image':IMAGE})
        pod['status']['containerStatuses'].append({'name':'cmtc-spire-registrar','ready':True,'containerID':'containerd://registrar','imageID':IMAGE,'restartCount':0,'state':{'running':{'startedAt':'2026-10-25T00:00:00Z'}}})
        return api
    def invoke(self,api,**kw):
        def command(argv,uri):
            if kw.get('mutate'):kw['mutate'](api)
            f=self.fx;return b'CMTC_AUTHORITY_BEFORE\n'+f.authority()+b'\nCMTC_CHAIN\n'+f.chain(f.leaf(uri))+b'CMTC_AUTHORITY_AFTER\n'+f.authority()+b'\nCMTC_END\n'
        return p.execute_proof(api,cluster='cmtc-a',cluster_uid='cluster-uid',pod_uid='pod-uid',approval_uid='approval-uid',root_pin=p.sha(p.der(self.fx.root)),invoke=command,clock=lambda:NOW,registrar_image=kw.get('registrar_image',IMAGE))
    def test_default_profile_still_rejects_any_third_container(self):
        with self.assertRaises(p.Refusal):p.pod_identity(self.api().get(PATH),'pod-uid')
    def test_explicit_third_pin_passes_fresh_public_challenge(self):
        result=self.invoke(self.api());self.assertEqual(result['approvedRegistrarImage'],IMAGE);self.assertFalse(result['protected'])
    def test_unapproved_name_image_status_extra_container_or_missing_third_refused(self):
        changes=[lambda a:a.objects[PATH]['spec']['containers'][-1].update(name='foreign'),lambda a:a.objects[PATH]['spec']['containers'][-1].update(image=IMAGE[:-1]+'b'),lambda a:a.objects[PATH]['status']['containerStatuses'][-1].update(ready=False),lambda a:a.objects[PATH]['status']['containerStatuses'][-1].update(containerID=''),lambda a:a.objects[PATH]['spec']['containers'].append({'name':'foreign','image':IMAGE}),lambda a:a.objects[PATH]['spec']['containers'].pop()]
        for change in changes:
            api=self.api();change(api)
            with self.subTest(change=change),self.assertRaises(p.Refusal):self.invoke(api)
    def test_third_container_change_during_nonce_proof_refused(self):
        api=self.api()
        with self.assertRaises(p.Refusal):self.invoke(api,mutate=lambda a:a.objects[PATH]['spec']['containers'][-1].update(args=['foreign']))
    def test_invalid_third_pin_refused_before_api_read(self):
        api=self.api()
        with self.assertRaises(p.Refusal):self.invoke(api,registrar_image='localhost/registrar:latest')
        self.assertEqual(api.calls,[])
if __name__=='__main__':unittest.main()
