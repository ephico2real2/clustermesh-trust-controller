import copy
import datetime as dt
import json
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import public_proof as q

NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
DOMAIN='cmtc-a.mesh.example'
NONCE='a'*64
URI='spiffe://'+DOMAIN+'/cmtc/issuer-proof/'+NONCE

def key(r=False): return rsa.generate_private_key(public_exponent=65537,key_size=2048) if r else ec.generate_private_key(ec.SECP256R1())
def cert(k,name,parent=None,parentkey=None,depth=0,uri=None,leaf=False,nb=None,na=None,eku=True):
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    b=x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(nb or NOW-dt.timedelta(minutes=1)).not_valid_after(na or NOW+dt.timedelta(hours=1))
    b=b.add_extension(x509.BasicConstraints(ca=not leaf,path_length=None if leaf else depth),critical=True)
    b=b.add_extension(x509.KeyUsage(digital_signature=leaf,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=not leaf,crl_sign=not leaf,encipher_only=None,decipher_only=None),critical=True)
    b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=False)
    if parent:
        b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(parentkey.public_key()),critical=False)
    if uri: b=b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),critical=False)
    if leaf and eku: b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
    return b.sign(parentkey or k,hashes.SHA256())

class Fixture:
    def __init__(self,depth=None,rsa_signer=True):
        self.rk=key();self.root=cert(self.rk,'root',depth=2)
        self.pk=key();self.parent=cert(self.pk,'parent',self.root,self.rk,depth=1)
        self.sk=key(rsa_signer);self.signer=cert(self.sk,'SPIRE CA',self.parent,self.pk,depth=depth,uri='spiffe://'+DOMAIN)
    def leaf(self,uri=URI,**kw): return cert(key(),'challenge',self.signer,self.sk,leaf=True,uri=uri,nb=NOW-dt.timedelta(seconds=5),na=kw.pop('na',NOW+dt.timedelta(seconds=30)),**kw)
    def authority(self): return json.dumps({'active':{'authority_id':q.ext(self.signer,x509.SubjectKeyIdentifier).value.digest.hex(),'upstream_authority_subject_key_id':q.ext(self.parent,x509.SubjectKeyIdentifier).value.digest.hex(),'expires_at':str(int(self.signer.not_valid_after_utc.timestamp()))}}).encode()
    def chain(self,leaf=None): return ''.join(q.pem(c) for c in [leaf or self.leaf(),self.signer,self.parent,self.root]).encode()
    def verify(self,raw=None,**kw):
        opts=dict(domain=DOMAIN,nonce=NONCE,parent=self.parent,root=self.root,before=NOW,after=NOW+dt.timedelta(seconds=1),authority_before=self.authority(),authority_after=self.authority());opts.update(kw)
        return q.verify_challenge(raw or self.chain(),**opts)
    def approval(self):
        a={'schemaVersion':1,'cluster':'cmtc-a','secretUID':'secret-uid','secretResourceVersion':'4','csrSHA256':'b'*64,'rootSHA256':q.sha(q.der(self.root)),'certificatePEM':q.pem(self.parent)+q.pem(self.root)}
        return {'kind':'ConfigMap','metadata':{'name':'cmtc-spire-cluster-ca-approval','uid':'approval-uid','resourceVersion':'12','labels':{'security.cmtc.io/pki-owner':'cmtc-lab-pki','security.cmtc.io/pki-cluster':'cmtc-a','security.cmtc.io/pki-role':'spire-cluster-ca-approval'}},'immutable':True,'data':{'approval.json':json.dumps(a)}}

def pod():
    return {'metadata':{'name':'spire-server-0','uid':'pod-uid','resourceVersion':'10'},'spec':{'serviceAccountName':'spire-server','nodeName':'worker','containers':[{'name':'spire-server','image':q.SERVER_IMAGE},{'name':'register-agent-node','image':q.SIDECAR_IMAGE}],'volumes':[{'name':'spire-server-cli','image':{'reference':q.SERVER_IMAGE}}]},'status':{'phase':'Running','containerStatuses':[{'name':n,'ready':True,'containerID':'containerd://'+n,'imageID':'sha256:'+n,'restartCount':0,'state':{'running':{'startedAt':'2026-10-24T00:00:00Z'}}} for n in ['spire-server','register-agent-node']]}}

class FakeAPI:
    argv=['kubectl','--context','kind-cmtc-a']
    def __init__(self,f):
        self.objects={'/api/v1/namespaces/kube-system':{'metadata':{'uid':'cluster-uid','resourceVersion':'1'}},'/api/v1/nodes/worker':{'metadata':{'uid':'node-uid','resourceVersion':'1'}},'/api/v1/namespaces/cilium-spire/pods/spire-server-0':pod(),'/api/v1/namespaces/cert-manager/configmaps/cmtc-spire-cluster-ca-approval':f.approval()}
        self.calls=[]
    def get(self,path):
        if '/secrets' in path: raise AssertionError('Secret read')
        self.calls.append(path);return copy.deepcopy(self.objects[path])

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f=Fixture()
    def test_actual_rsa_signer_and_bounded_parent_chain_success(self):
        result=self.f.verify();self.assertFalse(result['protected']);self.assertFalse(result['workloadAttestation']);self.assertEqual(q.sha(q.der(self.f.signer)),result['directIssuerSHA256'])
    def test_pathlen_zero_and_ec_signer_remain_supported(self): Fixture(depth=0,rsa_signer=False).verify()
    def test_only_exact_optional_chain_suffix_accepted(self):
        leaf=self.f.leaf()
        for suffix in [[],[self.f.parent],[self.f.parent,self.f.root]]:
            self.f.verify(''.join(q.pem(c) for c in [leaf,self.f.signer]+suffix).encode())
        with self.assertRaises(q.Refusal): self.f.verify((q.pem(leaf)+q.pem(self.f.signer)+q.pem(self.f.root)).encode())
    def test_wrong_nonce_role_expiry_and_domain_are_rejected(self):
        for leaf in [self.f.leaf(uri=URI+'1'),self.f.leaf(uri=URI.replace(DOMAIN,'other.mesh')),self.f.leaf(eku=False),self.f.leaf(na=NOW+dt.timedelta(minutes=5)),self.f.leaf(na=NOW)]:
            with self.subTest(leaf=leaf.serial_number),self.assertRaises(q.Refusal): self.f.verify(self.f.chain(leaf))
    def test_wrong_root_parent_and_delegated_signer_rejected(self):
        other=Fixture()
        with self.assertRaises(q.Refusal): self.f.verify(root=other.root)
        with self.assertRaises(q.Refusal): self.f.verify(parent=other.parent)
        childkey=key();child=cert(childkey,'delegated',self.f.signer,self.f.sk,depth=0,uri='spiffe://'+DOMAIN)
        leaf=cert(key(),'delegated leaf',child,childkey,leaf=True,uri=URI,na=NOW+dt.timedelta(seconds=30))
        with self.assertRaises(q.Refusal): self.f.verify((q.pem(leaf)+q.pem(child)+q.pem(self.f.signer)).encode())
    def test_authority_exact_skid_expiry_and_continuity(self):
        a=json.loads(self.f.authority())
        for k,v in [('authority_id','b'*40),('upstream_authority_subject_key_id','c'*40),('expires_at','1')]:
            bad=copy.deepcopy(a);bad['active'][k]=v
            with self.subTest(k=k),self.assertRaises(q.Refusal): self.f.verify(authority_before=json.dumps(bad),authority_after=json.dumps(bad))
        with self.assertRaises(q.Refusal): self.f.verify(authority_after=json.dumps(bad))
    def test_challenge_window_and_replay_bound(self):
        with self.assertRaises(q.Refusal): self.f.verify(before=NOW-dt.timedelta(seconds=60),after=NOW)
        with self.assertRaises(q.Refusal): self.f.verify(nonce='c'*64)
        with self.assertRaises(q.Refusal): self.f.verify(self.f.chain(self.f.leaf()),before=NOW+dt.timedelta(minutes=5),after=NOW+dt.timedelta(minutes=5,seconds=1))
    def test_public_only_canonical_envelope_rejects_private_trailing_duplicate(self):
        for raw in [self.f.chain()+b'private',b'-----BEGIN PRIVATE KEY-----\nsecret',self.f.chain().replace(b'CERTIFICATE',b'PRIVATE KEY')]:
            with self.assertRaises(q.Refusal): q.certs(raw)
        with self.assertRaises(q.Refusal): q.strict_json('{"active":{},"active":{}}')
        with self.assertRaises(q.Refusal): q.split_output(b'private_key')
    def test_approval_requires_exact_api_uid_immutable_root_and_owner(self):
        a=self.f.approval();opts=dict(uid='approval-uid',cluster='cmtc-a',root_pin=q.sha(q.der(self.f.root)),now=NOW)
        q.approved_parent(a,**opts)
        for mutate in [lambda a:a['metadata'].update(uid='replacement'),lambda a:a.update(immutable=False),lambda a:a['metadata']['labels'].update({'security.cmtc.io/pki-cluster':'cmtc-b'}),lambda a:a['metadata'].update(deletionTimestamp='now')]:
            b=copy.deepcopy(a);mutate(b)
            with self.assertRaises(q.Refusal):q.approved_parent(b,**opts)
        with self.assertRaises(q.Refusal):q.approved_parent(a,**dict(opts,root_pin='0'*64))
    def execute(self,mutate=None):
        f=self.f;api=FakeAPI(f)
        def invoke(argv,uri):
            self.assertIn('register-agent-node',argv);self.assertNotIn('secrets',' '.join(argv));self.assertIn('-write',q.PROOF_SCRIPT)
            if mutate:mutate(api)
            return b'CMTC_AUTHORITY_BEFORE\n'+f.authority()+b'\nCMTC_CHAIN\n'+f.chain(f.leaf(uri))+b'CMTC_AUTHORITY_AFTER\n'+f.authority()+b'\nCMTC_END\n'
        return q.execute_proof(api,cluster='cmtc-a',cluster_uid='cluster-uid',pod_uid='pod-uid',approval_uid='approval-uid',root_pin=q.sha(q.der(f.root)),invoke=invoke,clock=lambda:NOW)
    def test_live_invocation_generates_nonce_and_retains_public_source_binding(self):
        result=self.execute();self.assertEqual('approval-uid',result['approvalUID']);self.assertEqual('pod-uid',result['pod']['uid']);self.assertIn('BEGIN CERTIFICATE',result['challengeLeafPEM'])
    def test_uid_node_container_restart_image_and_approval_change_fail_after_mint(self):
        pp='/api/v1/namespaces/cilium-spire/pods/spire-server-0';ap='/api/v1/namespaces/cert-manager/configmaps/cmtc-spire-cluster-ca-approval'
        for mutate in [lambda a:a.objects[pp]['metadata'].update(uid='new'),lambda a:a.objects[pp]['status']['containerStatuses'][0].update(containerID='new'),lambda a:a.objects[pp]['status']['containerStatuses'][0].update(restartCount=1),lambda a:a.objects[pp]['status']['containerStatuses'][0].update(imageID='new'),lambda a:a.objects[ap]['metadata'].update(resourceVersion='13'),lambda a:a.objects['/api/v1/nodes/worker']['metadata'].update(uid='new'),lambda a:a.objects['/api/v1/namespaces/kube-system']['metadata'].update(uid='new')]:
            with self.subTest(mutate=mutate),self.assertRaises(q.Refusal):self.execute(mutate)
    def test_fixed_shell_never_prints_private_cli_default_and_cleans_owned_key(self):
        # Real shell/timeout execution, reviewed script with test-only binary/temp paths.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cli=root/'cli';private='NEVER-RETURN-THIS-KEY'
            cli.write_text('#!/bin/sh\nif [ "$1" = localauthority ]; then printf \'%s\' \'{}\'; exit 0; fi\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -write ]; then shift; dest=$1; fi; shift; done\nprintf \'%s\' '+shlex.quote(q.pem(self.f.leaf())+q.pem(self.f.signer))+' >"$dest/svid.pem"\nprintf \'%s\' '+repr(private)+' >"$dest/key.pem"\nprintf \'%s\' '+repr(private)+'\n')
            cli.chmod(0o700)
            script=q.PROOF_SCRIPT.replace('bin=/spire-cli/opt/spire/bin/spire-server','bin='+str(cli)).replace('/tmp/cmtc-proof.XXXXXX',str(root/'proof.XXXXXX'))
            proc=subprocess.run(['/bin/sh','-c',script,'test',URI],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(0,proc.returncode,proc.stderr);self.assertNotIn(private.encode(),proc.stdout);self.assertEqual([],list(root.glob('proof.*')));q.split_output(proc.stdout)
    def test_fixed_shell_failed_mint_has_no_public_ack_or_retained_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cli=root/'cli';cli.write_text('#!/bin/sh\nif [ "$1" = localauthority ]; then echo \'{}\'; exit 0; fi\necho NEVER-RETURN-KEY\nexit 1\n');cli.chmod(0o700)
            script=q.PROOF_SCRIPT.replace('bin=/spire-cli/opt/spire/bin/spire-server','bin='+str(cli)).replace('/tmp/cmtc-proof.XXXXXX',str(root/'proof.XXXXXX'))
            proc=subprocess.run(['/bin/sh','-c',script,'test',URI],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertNotEqual(0,proc.returncode);self.assertEqual(b'',proc.stdout);self.assertEqual([],list(root.glob('proof.*')))
if __name__=='__main__':unittest.main()
