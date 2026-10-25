import copy, hashlib, json, sys, unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
import qualify_workload as q
from workload_api import Refusal

def fixture(identity='spiffe://cmtc-a.mesh.example/ns/demo/sa/client',role=True,expired=False,ca_leaf=False):
    now=datetime.now(timezone.utc);key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'approved direct SPIRE test CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
    leafkey=ec.generate_private_key(ec.SECP256R1())
    eku=[ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH] if role else [ExtendedKeyUsageOID.SERVER_AUTH]
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(name).public_key(leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now-timedelta(hours=1) if expired else now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=ca_leaf,path_length=None),True).add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]),False).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True).add_extension(x509.ExtendedKeyUsage(eku),False).sign(key,hashes.SHA256()))
    pem=lambda c:c.public_bytes(serialization.Encoding.PEM).decode();sha=lambda c:hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()
    proof={'domain':'cmtc-a.mesh.example','directIssuerPEM':pem(ca),'directIssuerSHA256':sha(ca),'rootSHA256':sha(ca)}
    wanted={'spiffeID':identity,'podUID':'11111111-2222-3333-4444-555555555555'}
    result={'schemaVersion':1,'identity':identity,'podUID':wanted['podUID'],'publicCertificateChain':[pem(leaf),pem(ca)],'privateKeyExported':False,'workloadAttestationPath':'native-ztunnel-CRI-PodUID-PID-delegated-SPIRE','packetProtectionTested':False}
    return proof,wanted,result

class Tests(unittest.TestCase):
    def test_real_signature_positive(self):
        p,w,r=fixture();self.assertTrue(q.verify_public_result(json.dumps(r),wanted=w,current_issuer_proof=p)['workloadSVIDVerified'])
    def test_wrong_real_signer(self):
        p,w,r=fixture();other,_,_=fixture()
        with self.assertRaises(InvalidSignature):q.verify_public_result(json.dumps(r),wanted=w,current_issuer_proof=other)
    def test_different_identity_uid_and_private_marker(self):
        p,w,r=fixture()
        for mutate in [lambda r:r.update(identity='spiffe://wrong/ns/demo/sa/client'),lambda r:r.update(podUID='new-uid'),lambda r:r.update(privateKeyExported=True),lambda r:r.update(unexpected='PRIVATE KEY')]:
            candidate=copy.deepcopy(r);mutate(candidate)
            with self.assertRaises(Refusal):q.verify_public_result(json.dumps(candidate),wanted=w,current_issuer_proof=p)
    def test_expired_or_ca_or_missing_role(self):
        for kwargs in [{'expired':True},{'ca_leaf':True},{'role':False}]:
            p,w,r=fixture(**kwargs)
            with self.assertRaises(Refusal):q.verify_public_result(json.dumps(r),wanted=w,current_issuer_proof=p)
    def test_duplicate_leaf_and_foreign_chain_rejected(self):
        p,w,r=fixture();r['publicCertificateChain'].insert(1,r['publicCertificateChain'][0])
        with self.assertRaises(Refusal):q.verify_public_result(json.dumps(r),wanted=w,current_issuer_proof=p)
    def test_probe_incarnation_changed(self):
        p={'metadata':{'uid':'x'},'spec':{'nodeName':'a'},'status':{'phase':'Running','containerStatuses':[{'name':'probe','ready':True,'containerID':'one','imageID':'sha256:1','restartCount':0,'state':{'running':{'startedAt':'old'}}}]}}
        q.same_running_pod(p,copy.deepcopy(p));other=copy.deepcopy(p);other['status']['containerStatuses'][0]['containerID']='two'
        with self.assertRaises(Refusal):q.same_running_pod(p,other)

class RetryTests(unittest.TestCase):
    def denied(self, text=None):
        return q.CommandFailure(SimpleNamespace(returncode=1,stderr=text or 'native PID-attested credential fetch: The caller does not have permission; message: "no identity issued"'))
    def test_propagation_rechecks_fetch_and_logs_recovery(self):
        logs=[]
        with patch.object(q,'native_fetch',side_effect=[self.denied(),{'verified':True}]) as fetch, patch.object(q.time,'sleep') as sleep:
            self.assertEqual(q.native_fetch_registered(None,emit=logs.append),{'verified':True})
        self.assertEqual(fetch.call_count,2);sleep.assert_called_once_with(2)
        self.assertTrue(logs[0]['retry']);self.assertEqual(logs[1]['stage'],'SVID-verified')
    def test_bounded_attempts_do_not_turn_denial_into_success(self):
        logs=[]
        with patch.object(q,'native_fetch',side_effect=self.denied()) as fetch, patch.object(q.time,'sleep') as sleep:
            with self.assertRaises(q.CommandFailure):q.native_fetch_registered(None,emit=logs.append)
        self.assertEqual(fetch.call_count,5);self.assertFalse(logs[-1]['retry'])
        self.assertEqual([call.args[0] for call in sleep.call_args_list],[2,4,8,8])
    def test_tls_and_structural_errors_are_fatal(self):
        for error in [self.denied('TLS certificate rejected'),Refusal('Pod UID changed')]:
            with patch.object(q,'native_fetch',side_effect=error) as fetch, patch.object(q.time,'sleep') as sleep:
                with self.assertRaises(Refusal):q.native_fetch_registered(None,emit=lambda _:None)
            self.assertEqual(fetch.call_count,1);sleep.assert_not_called()
    def test_elapsed_deadline_prevents_retry(self):
        logs=[]
        with patch.object(q,'native_fetch',side_effect=self.denied()) as fetch, patch.object(q.time,'monotonic',side_effect=[0,60]),patch.object(q.time,'sleep') as sleep:
            with self.assertRaises(q.CommandFailure):q.native_fetch_registered(None,emit=logs.append)
        self.assertEqual(fetch.call_count,1);sleep.assert_not_called();self.assertFalse(logs[0]['retry'])

if __name__=='__main__':unittest.main()
