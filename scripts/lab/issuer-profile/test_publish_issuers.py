import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID
import publish_issuers as u

ROOT=Path(__file__).resolve().parents[3]
pki=u.load(str(ROOT/'scripts/lab/pki/pki.py'),'pki_test_accepted')
q=u.load(str(ROOT/'scripts/lab/spire/public_proof.py'),'proof_test_accepted')
lab=u.load(str(ROOT/'scripts/lab/issuer-profile/test-issuer-profile.py'),'pub_test_accepted')
NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def key():return ec.generate_private_key(ec.SECP256R1())
def cert(k,name,parent=None,pk=None,depth=0,domain=None,ski=False,days=None,hours=2):
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    start,end=(NOW-dt.timedelta(minutes=1),NOW+dt.timedelta(hours=hours)) if days is None else (NOW+dt.timedelta(days=days),NOW+dt.timedelta(days=days,hours=2))
    b=x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end).add_extension(x509.BasicConstraints(ca=True,path_length=depth),critical=True).add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True)
    if domain:b=b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('spiffe://'+domain)]),critical=False)
    if ski:b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=False)
    return b.sign(pk or k,hashes.SHA256())

class Fixtures:
    def __init__(self):
        rk=key();root=cert(rk,'root',depth=2);self.parents={};self.proofs={};self.parent_keys={};self.signer_keys={};self.root,self.root_key=root,rk
        for cluster,domain in q.DOMAINS.items():
            pk=key();parent=cert(pk,cluster+' parent',root,rk,1);self.parent_keys[cluster]=pk
            sk=rsa.generate_private_key(public_exponent=65537,key_size=2048);signer=cert(sk,cluster+' SPIRE',parent,pk,None,domain);self.signer_keys[cluster]=sk
            self.parents[cluster]=(parent,root)
            self.proofs[cluster]={'cluster':cluster,'domain':domain,'protected':False,'workloadAttestation':False,'source':'authenticated-kubernetes-exec-local-SPIRE-admin-API-nonce-mint','observedAt':NOW.isoformat(),'directIssuerSHA256':q.sha(q.der(signer)),'directIssuerPEM':q.pem(signer),'parentPEM':q.pem(parent),'rootSHA256':q.sha(q.der(root))}
        self.rootpin=q.sha(q.der(root))
    def approval(self):return u.build_approval(self.proofs,self.parents,q,1,NOW,3600)
    def prepared(self,cluster,domain=None,signer=None,chain=None,depth=None,days=None,k=None,hours=2):
        """A public chain [prepared CA, parent] and the prepared CA's key identifier, as SPIRE logs it."""
        k=k or key();parent=self.parents[cluster][0]
        c=cert(k,cluster+' SPIRE prepared',signer[0] if signer else parent,signer[1] if signer else self.parent_keys[cluster],depth,domain or q.DOMAINS[cluster],True,days,hours)
        ski=c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
        return q.pem(c)+(chain if chain is not None else q.pem(parent)),ski

class MemoryState:
    poison=False
    def __init__(self):self.data={'owner':'owner-token','clusters':{'cmtc-a':{'uids':{}},'cmtc-b':{'uids':{}}}};self.saves=0
    def save(self):self.saves+=1
class API:
    argv=['kubectl','--context','kind-cmtc-a']
    def __init__(self):self.objects={};self.calls=[];self.counter=0;self.ambiguous=False
    def get(self,path):
        self.calls.append(('GET',path))
        if '/secrets/' in path:raise AssertionError('secretread')
        if path not in self.objects:raise pki.APIError(404,'NotFound')
        return copy.deepcopy(self.objects[path])
    def request(self,method,path,body):
        self.calls.append((method,path));self.counter+=1
        self.assertPublic(body)
        o=copy.deepcopy(body);o['metadata'].update(uid='uid-'+str(self.counter),resourceVersion=str(self.counter))
        target=path+'/'+o['metadata']['name']
        if target in self.objects:raise pki.APIError(409,'AlreadyExists')
        self.objects[target]=o
        if self.ambiguous:raise TimeoutError('unknowncommit')
        return copy.deepcopy(o)
    def assertPublic(self,o):u.public(u.compact(o))

def publisher(state=None,api=None):
    a=types.SimpleNamespace(generation=1)
    return u.Publisher(a,pki,q,lab.publication,state or MemoryState(),{'cmtc-a':api or API()})

def baseline():return {'metadata':{'labels':{'app':'controller'},'annotations':{'other':'unchanged'}},'spec':{'serviceAccountName':'cmtc-controller','containers':[{'name':'controller','image':'localhost/cmtc:qualified','imagePullPolicy':'Never','args':['--cluster-name=cmtc-a','--mode=controller'],'securityContext':{'runAsNonRoot':True}}],'securityContext':{'fsGroup':65532}}}

def deployment(t=None):return {'metadata':{'uid':'deployment-uid','resourceVersion':'3'},'spec':{'template':copy.deepcopy(t) if t else baseline(),'replicas':1}}

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fx=Fixtures()
    def test_actual_approval_wire_field_order_spki_lineage_and_common_root(self):
        a=self.fx.approval();self.assertEqual(['schemaVersion','generation','expiresAt','roots','clusters'],list(a));self.assertEqual(['cmtc-a','cmtc-b'],[c['clusterID'] for c in a['clusters']]);self.assertEqual(1,len(a['roots']))
        for cluster in a['clusters']:
            issuer=cluster['issuers'][0];self.assertEqual(['certificatePEM','chainPEM','spkiSHA256','rootSHA256'],list(issuer));self.assertEqual(1,len(q.certs(issuer['chainPEM'])));self.assertEqual(q.sha(q.spki(q.certs(issuer['certificatePEM'])[0])),issuer['spkiSHA256'])
    def test_stale_wrong_source_protected_wrong_domain_and_crosscluster_key_reuse_refused(self):
        for change in [lambda p:p['cmtc-a'].update(observedAt=(NOW-dt.timedelta(seconds=91)).isoformat()),lambda p:p['cmtc-a'].update(source='deleted-CR-replay'),lambda p:p['cmtc-a'].update(protected=True),lambda p:p['cmtc-a'].update(domain=q.DOMAINS['cmtc-b']),lambda p:p['cmtc-b'].update(directIssuerPEM=p['cmtc-a']['directIssuerPEM'],directIssuerSHA256=p['cmtc-a']['directIssuerSHA256'])]:
            proofs=copy.deepcopy(self.fx.proofs);change(proofs)
            with self.subTest(change=change),self.assertRaises(u.Refusal):u.build_approval(proofs,self.fx.parents,q,1,NOW,3600)
    def test_expiry_is_bounded_by_issuer_and_explicit_horizon(self):
        a=u.build_approval(self.fx.proofs,self.fx.parents,q,1,NOW,86400);self.assertEqual(u.stamp(NOW+dt.timedelta(hours=2)),a['expiresAt'])
        for gen,horizon in [(0,3600),(True,3600),(2**64,3600),(1,119),(1,86401)]:
            with self.assertRaises(u.Refusal):u.build_approval(self.fx.proofs,self.fx.parents,q,gen,NOW,horizon)
    def test_enable_changes_only_args_and_owned_template_annotation(self):
        base=baseline();desired=u.enabled_template(base,'owner','cmtc-a','source','source-uid','out-uid',self.fx.rootpin,1)
        self.assertEqual(base['spec']['containers'][0]['image'],desired['spec']['containers'][0]['image']);self.assertEqual(base['spec']['containers'][0]['imagePullPolicy'],desired['spec']['containers'][0]['imagePullPolicy'])
        args=desired['spec']['containers'][0]['args'];self.assertIn('--issuer-profile-source-uid=source-uid',args);self.assertIn('--issuer-profile-output-uid=out-uid',args)
        restored=copy.deepcopy(desired);restored['spec']['containers'][0]['args']=base['spec']['containers'][0]['args'];restored['metadata']['annotations'].pop(u.OWNER);self.assertEqual(base,restored)
        d=deployment();ops=u.template_patch(d,'deployment-uid',base,desired);self.assertEqual(['/metadata/uid','/metadata/resourceVersion','/spec/template','/spec/template'],[x['path'] for x in ops]);self.assertEqual(['test','test','test','replace'],[x['op']for x in ops])
    def test_wrong_deployment_uid_or_template_cannot_be_enabled_or_rolled_back(self):
        d=deployment()
        with self.assertRaises(u.Refusal):u.template_patch(d,'other',baseline(),baseline())
        d['spec']['template']['metadata']['annotations']['foreign']='new'
        with self.assertRaises(u.Refusal):u.template_patch(d,'deployment-uid',baseline(),baseline())
        b=baseline();b['spec']['containers'][0]['args'].append('--issuer-profile-producer=false')
        with self.assertRaises(u.Refusal):u.enabled_template(b,'owner','cmtc-a','s','suid','ouid',self.fx.rootpin,1)
    def test_exact_created_public_source_recorded_and_idempotently_reused(self):
        pub=publisher();body={'immutable':True,'data':{'approval.json':u.compact(self.fx.approval())}}
        first=pub.owned_object('cmtc-a','ConfigMap','source',body);second=pub.owned_object('cmtc-a','ConfigMap','source',body)
        self.assertEqual(first,second);self.assertEqual(1,sum(c[0]=='POST'for c in pub.apis['cmtc-a'].calls));self.assertEqual('uid-1',pub.s.data['clusters']['cmtc-a']['uids']['ConfigMap/source'])
    def test_collision_unknown_uid_missing_recorded_object_and_mutation_refused(self):
        pub=publisher();body={'immutable':True,'data':{'approval.json':'public'}};path=pub.cm_path('source')
        pub.owned_object('cmtc-a','ConfigMap','source',body)
        saved=copy.deepcopy(pub.apis['cmtc-a'].objects[path])
        for mutate in [lambda x:x['metadata'].update(uid='new'),lambda x:x['metadata']['labels'].update({u.OWNER:'foreign'}),lambda x:x['data'].update({'approval.json':'changed'})]:
            pub.apis['cmtc-a'].objects[path]=copy.deepcopy(saved);mutate(pub.apis['cmtc-a'].objects[path])
            with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap','source',body)
        del pub.apis['cmtc-a'].objects[path]
        with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap','source',body)
        pub.s.data['clusters']['cmtc-a']['uids'].clear();pub.apis['cmtc-a'].objects[path]=saved
        with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap','source',body)
    def test_unknown_create_commit_never_adopts_or_deletes_result(self):
        api=API();api.ambiguous=True;pub=publisher(api=api);body={'immutable':True,'data':{'approval.json':'public'}}
        with self.assertRaises(TimeoutError):pub.owned_object('cmtc-a','ConfigMap','source',body)
        self.assertNotIn('ConfigMap/source',pub.s.data['clusters']['cmtc-a']['uids']);api.ambiguous=False
        with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap','source',body)
        self.assertIn(pub.cm_path('source'),api.objects);self.assertFalse(any(c[0]=='DELETE'for c in api.calls))
    def test_initialized_empty_output_refused_before_any_template_patch(self):
        pub=publisher();o=pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'metadata':{'labels':{u.OUTPUT:'true'}},'data':{}})
        pub.apis['cmtc-a'].objects[pub.cm_path(u.OUT)]['metadata']['annotations']={u.INIT:'true'}
        with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'data':{}})
    def test_cumulative_floor_and_same_sequence_identity_never_reset(self):
        previous={'sequence':5,'acceptedGeneration':2,'digest':'old','acceptedSourceUID':'s','acceptedApprovalDigest':'a'}
        u.check_floor(dict(previous,sequence=6,digest='renewal'),previous)
        for change in [{'sequence':4},{'acceptedGeneration':1},{'digest':'changed'},{'sequence':6,'acceptedSourceUID':'new'},{'sequence':6,'acceptedApprovalDigest':'new'}]:
            with self.subTest(change=change),self.assertRaises(u.Refusal):u.check_floor(dict(previous,**change),previous)
    def test_owned_directory_lock_and_fsynced_ledger_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=str(Path(tmp).resolve());os.chmod(tmp,0o700)
            with u.State(tmp,pki)as s:
                s.data={'owner':'known','clusters':{}};s.save()
                with self.assertRaises(BlockingIOError):
                    with u.State(tmp,pki):pass
            with u.State(tmp,pki)as s:self.assertEqual('known',s.data['owner'])
    def test_ledger_symlink_fifo_unowned_partial_and_replacement_refused(self):
        for mode in ('symlink','fifo','partial'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                tmp=str(Path(tmp).resolve());os.chmod(tmp,0o700)
                if mode=='symlink':os.symlink('/dev/null',Path(tmp)/'ledger.json')
                elif mode=='fifo':os.mkfifo(Path(tmp)/'ledger.json',0o600)
                else:(Path(tmp)/'pending-lost').write_text('public')
                with self.assertRaises((u.Refusal,pki.Refusal,OSError)):
                    with u.State(tmp,pki):pass
        with tempfile.TemporaryDirectory()as tmp:
            tmp=str(Path(tmp).resolve());os.chmod(tmp,0o700)
            with u.State(tmp,pki)as s:
                s.data={'owner':'known'};s.save();os.unlink(Path(tmp)/'ledger.json');(Path(tmp)/'ledger.json').write_text('{}')
                with self.assertRaises(u.Refusal):s.save()
    def test_private_material_never_enters_ledger_or_public_command_artifacts(self):
        for raw in [b'-----BEGIN PRIVATE KEY-----\nsecret',b'{"tls.key":"no"}',b'{"private_key":"no"}']:
            with self.assertRaises(u.Refusal):u.public(raw)
    def test_unknown_pin_sets_duplicate_uid_pins_and_generation_cannot_takeover(self):
        with self.assertRaises(u.Refusal):u.pairs(['cmtc-a=x','cmtc-a=y'],['cmtc-a','cmtc-b'])
        with self.assertRaises(u.Refusal):u.pairs(['cmtc-a=x'],['cmtc-a','cmtc-b'])
        self.assertTrue(u.same_material(self.fx.approval(),dict(self.fx.approval(),expiresAt='later')))

class PreparedIssuerTests(unittest.TestCase):
    """SPIRE's prepared X509 CA becomes each cluster's second issuer before SPIRE activates it."""
    @classmethod
    def setUpClass(cls):cls.fx=Fixtures()
    def build(self,prepared):return u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,86400,prepared)
    def test_prepared_ca_is_the_second_issuer_sorted_by_key_with_the_same_expiry(self):
        prepared={c:self.fx.prepared(c) for c in q.DOMAINS};a=self.build(prepared);plain=u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,86400)
        self.assertEqual(plain['expiresAt'],a['expiresAt']);self.assertEqual(plain['roots'],a['roots'])
        for cluster,before in zip(a['clusters'],plain['clusters']):
            issuers=cluster['issuers'];keys=[i['spkiSHA256'] for i in issuers]
            self.assertEqual(2,len(issuers));self.assertEqual(sorted(keys),keys);self.assertIn(before['issuers'][0],issuers)
            new=next(i for i in issuers if i!=before['issuers'][0]);c=q.certs(new['certificatePEM'])[0]
            self.assertEqual(['certificatePEM','chainPEM','spkiSHA256','rootSHA256'],list(new));self.assertEqual(before['issuers'][0]['chainPEM'],new['chainPEM'])
            self.assertEqual(q.sha(q.spki(c)),new['spkiSHA256']);self.assertEqual(self.fx.rootpin,new['rootSHA256'])
            self.assertEqual(prepared[cluster['clusterID']][0].split('-----END CERTIFICATE-----\n')[0]+'-----END CERTIFICATE-----\n',new['certificatePEM'])
    def test_a_prepared_ca_that_expires_first_bounds_the_approval(self):
        a=u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,86400,{'cmtc-a':self.fx.prepared('cmtc-a',hours=1)})
        self.assertEqual(u.stamp(NOW+dt.timedelta(hours=1)),a['expiresAt'])
    def special(self,cluster,ski=None,ski_critical=False,aki_critical=False,hours=2,k=None):
        """A prepared CA signed by the approved parent, with a chosen key identifier, criticality or lifetime."""
        parent=self.fx.parents[cluster][0];pk=self.fx.parent_keys[cluster];k=k or key()
        b=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cluster+' special')])).issuer_name(parent.subject)
           .public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(NOW-dt.timedelta(minutes=1)).not_valid_after(NOW+dt.timedelta(hours=hours))
           .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
           .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True)
           .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('spiffe://'+q.DOMAINS[cluster])]),critical=False)
           .add_extension(x509.SubjectKeyIdentifier(ski) if ski else x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=ski_critical))
        if aki_critical:b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pk.public_key()),critical=True)
        c=b.sign(pk,hashes.SHA256())
        return q.pem(c)+q.pem(parent),c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
    def test_a_key_identifier_copied_onto_another_key_is_refused(self):
        # The parent signs whatever it is asked to: SPIRE's logged identifier on another key must not pass.
        genuine=self.fx.prepared('cmtc-a')[1]
        forged=self.special('cmtc-a',ski=bytes.fromhex(genuine))
        self.assertEqual(genuine,forged[1])
        with self.assertRaises(u.Refusal):self.build({'cmtc-a':forged})
        with self.assertRaises(u.Refusal):u.prepared_identity(q,'cmtc-a',*forged)
    def test_truncated_sha256_key_identifier_as_spire_writes_it_is_accepted(self):
        k=key();bits=k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        import hashlib
        self.assertEqual(2,len(self.build({'cmtc-a':self.special('cmtc-a',ski=hashlib.sha256(bits).digest()[:20],k=k)})['clusters'][0]['issuers']))
    def test_critical_key_identifiers_that_the_controller_refuses_are_refused(self):
        for name,prepared in {'critical SKI':self.special('cmtc-a',ski_critical=True),'critical AKI':self.special('cmtc-a',aki_critical=True)}.items():
            with self.subTest(name),self.assertRaises(u.Refusal):self.build({'cmtc-a':prepared})
    def test_a_prepared_ca_that_outlives_its_parent_is_refused(self):
        with self.assertRaises(u.Refusal):self.build({'cmtc-a':self.special('cmtc-a',hours=3)})
    def test_a_horizon_that_ends_before_the_certificates_is_refused_only_with_a_prepared_issuer(self):
        u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,3600)
        with self.assertRaises(u.Refusal):u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,3600,{'cmtc-a':self.fx.prepared('cmtc-a')})
    def test_a_prepared_key_that_sorts_first_is_the_first_issuer(self):
        # Random fixture keys leave the order to chance; pin the case the sort must fix.
        active=q.sha(q.spki(q.certs(self.fx.proofs['cmtc-a']['directIssuerPEM'])[0]));k=key()
        while q.sha(k.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))>active:k=key()
        keys=[i['spkiSHA256'] for i in self.build({'cmtc-a':self.fx.prepared('cmtc-a',k=k)})['clusters'][0]['issuers']]
        self.assertEqual(active,keys[1]);self.assertLess(keys[0],keys[1])
    def test_wrong_file_or_identifier_is_refused_without_the_parent(self):
        raw,ski=self.fx.prepared('cmtc-a');u.prepared_identity(q,'cmtc-a',raw,ski)
        for bad in [(raw,self.fx.prepared('cmtc-a')[1]),(self.fx.prepared('cmtc-b')[0],ski),(raw.split('-----END CERTIFICATE-----\n')[0]+'-----END CERTIFICATE-----\n',ski)]:
            with self.subTest(bad=bad[1][:8]),self.assertRaises((u.Refusal,q.Refusal)):u.prepared_identity(q,'cmtc-a',*bad)
    def test_one_cluster_may_carry_a_prepared_issuer_alone(self):
        a=self.build({'cmtc-b':self.fx.prepared('cmtc-b')})
        self.assertEqual([1,2],[len(c['issuers']) for c in a['clusters']])
    def test_prepared_issuer_outside_the_exact_lineage_or_binding_is_refused(self):
        other=self.fx.parents['cmtc-b'][0];chain_b=q.pem(other)
        cases={
            'wrong domain':lambda:self.fx.prepared('cmtc-a',domain=q.DOMAINS['cmtc-b']),
            'signed by the other cluster parent':lambda:self.fx.prepared('cmtc-a',signer=(other,self.fx.parent_keys['cmtc-b'])),
            'signed by the root directly':lambda:self.fx.prepared('cmtc-a',signer=(self.fx.root,self.fx.root_key)),
            'chain names another parent':lambda:self.fx.prepared('cmtc-a',chain=chain_b),
            'no parent in the chain':lambda:self.fx.prepared('cmtc-a',chain=''),
            'chain with the root too':lambda:self.fx.prepared('cmtc-a',chain=q.pem(self.fx.parents['cmtc-a'][0])+q.pem(self.fx.root)),
            'path length that allows sub-CAs':lambda:self.fx.prepared('cmtc-a',depth=1),
            'not yet valid':lambda:self.fx.prepared('cmtc-a',days=1),
            'expired':lambda:self.fx.prepared('cmtc-a',days=-1),
        }
        for name,make in cases.items():
            with self.subTest(name),self.assertRaises((u.Refusal,q.Refusal)):self.build({'cmtc-a':make()})
    def test_key_identifier_must_be_spire_prepared_authority(self):
        raw,ski=self.fx.prepared('cmtc-a');other=self.fx.prepared('cmtc-a')[1]
        with self.assertRaises(u.Refusal):self.build({'cmtc-a':(raw,other)})
    def test_active_signer_key_or_any_reused_key_is_refused(self):
        # SPIRE has activated the prepared CA: the proof's signer and the prepared CA share a key.
        cases={'the active signer of the cluster':self.fx.prepared('cmtc-a',k=self.fx.signer_keys['cmtc-a']),
               'the active signer of the other cluster':self.fx.prepared('cmtc-a',k=self.fx.signer_keys['cmtc-b']),
               'the cluster parent':self.fx.prepared('cmtc-a',k=self.fx.parent_keys['cmtc-a']),
               'the root':self.fx.prepared('cmtc-a',k=self.fx.root_key)}
        for name,prepared in cases.items():
            with self.subTest(name),self.assertRaises(u.Refusal):self.build({'cmtc-a':prepared})
    def test_prepared_issuer_for_an_unknown_cluster_is_refused(self):
        with self.assertRaises(u.Refusal):self.build({'cmtc-x':self.fx.prepared('cmtc-a')})
    def test_same_prepared_ca_in_both_clusters_is_refused(self):
        raw,ski=self.fx.prepared('cmtc-a')
        with self.assertRaises((u.Refusal,q.Refusal)):self.build({'cmtc-a':(raw,ski),'cmtc-b':(raw,ski)})
    def test_private_or_noncertificate_material_is_refused(self):
        raw,ski=self.fx.prepared('cmtc-a')
        for bad in [raw+'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n',raw.replace('\n','\r\n'),'']:
            with self.subTest(bad=bad[-30:]),self.assertRaises((u.Refusal,q.Refusal)):self.build({'cmtc-a':(bad,ski)})
    def test_material_check_sees_a_dropped_prepared_issuer(self):
        with_prepared=self.build({c:self.fx.prepared(c) for c in q.DOMAINS});without=u.build_approval(self.fx.proofs,self.fx.parents,q,2,NOW,3600)
        self.assertFalse(u.same_material(with_prepared,without))
    def test_cli_pins_need_a_key_identifier_per_file_and_known_clusters(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw,ski=self.fx.prepared('cmtc-a');f=Path(tmp,'a.pem');f.write_text(raw)
            self.assertEqual({'cmtc-a':(raw,ski)},u.prepared_pins(['cmtc-a='+str(f)],['cmtc-a='+ski],['cmtc-a','cmtc-b']))
            self.assertEqual({},u.prepared_pins([],[],['cmtc-a','cmtc-b']))
            for files,skis in [(['cmtc-a='+str(f)],[]),([],['cmtc-a='+ski]),(['cmtc-x='+str(f)],['cmtc-x='+ski]),(['cmtc-a='+str(f)],['cmtc-a='+ski.upper()]),(['cmtc-a='+str(f)],['cmtc-a='+ski[:-2]]),(['cmtc-a='+str(f),'cmtc-a='+str(f)],['cmtc-a='+ski]),(['cmtc-a'],['cmtc-a='+ski])]:
                with self.subTest(files=files,skis=skis),self.assertRaises(u.Refusal):u.prepared_pins(files,skis,['cmtc-a','cmtc-b'])

class PublicationRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fx=Fixtures()
    def setup_pub(self):
        pub=publisher();pub.a.generation=1;pub.s.data['approval']=self.fx.approval();c=pub.s.data['clusters']['cmtc-a'];api=pub.apis['cmtc-a']
        src=pub.owned_object('cmtc-a','ConfigMap','source',{'immutable':True,'data':{'approval.json':u.compact(pub.s.data['approval'])}})
        out=pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'metadata':{'labels':{u.OUTPUT:'true'}},'data':{}})
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        a=pub.s.data['approval'];ad=u.sha(u.compact(a).encode())
        p={'schemaVersion':1,'sequence':1,'state':'published','reason':'Validated','producerCluster':'cmtc-a','outputUID':out['metadata']['uid'],'expectedSourceUID':src['metadata']['uid'],'source':{'namespace':u.NS,'name':'source','uid':src['metadata']['uid'],'resourceVersion':src['metadata']['resourceVersion'],'generation':1},'acceptedGeneration':1,'acceptedSourceUID':src['metadata']['uid'],'acceptedApprovalDigest':ad,'approvalDigest':ad,'approval':a,'publishedAt':u.stamp(now),'validUntil':u.stamp(now+dt.timedelta(seconds=30))}
        self.install(pub,p)
        return pub,p
    def install(self,pub,p):
        p=copy.deepcopy(p);p.pop('digest',None);p['digest']=u.sha(u.compact(p).encode())
        cm=pub.apis['cmtc-a'].objects[pub.cm_path(u.OUT)];cm['data']={'profile.json':u.compact(p)};cm['metadata']['annotations']={u.INIT:'true'};cm['metadata']['resourceVersion']=str(int(cm['metadata']['resourceVersion'])+1)
        return p
    def test_real_wire_digest_and_source_binding_then_renewal(self):
        pub,p=self.setup_pub();one=pub.read_publication('cmtc-a','source');self.assertEqual(1,one['sequence']);self.assertEqual(pub.s.data['approval'],one['approval'])
        p['sequence']=2;p['publishedAt']=u.stamp(dt.datetime.now(dt.timezone.utc));self.install(pub,p)
        two=pub.read_publication('cmtc-a','source');self.assertEqual(2,two['sequence']);self.assertEqual(one['acceptedApprovalDigest'],two['acceptedApprovalDigest'])
    def test_canonical_corruption_uid_replacement_and_source_rv_change_refused(self):
        for mutation in ('corrupt','uid','source-rv'):
            pub,p=self.setup_pub();api=pub.apis['cmtc-a']
            if mutation=='corrupt':api.objects[pub.cm_path(u.OUT)]['data']['profile.json']='{corrupt'
            elif mutation=='uid':api.objects[pub.cm_path(u.OUT)]['metadata']['uid']='replaced'
            else:api.objects[pub.cm_path('source')]['metadata']['resourceVersion']='new'
            with self.subTest(mutation=mutation),self.assertRaises((u.Refusal,lab.Refusal,ValueError)):pub.read_publication('cmtc-a','source')
    def test_expired_stored_lease_preserves_floor_but_is_not_live_publication(self):
        pub,p=self.setup_pub();old=dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=2);p.update(publishedAt=u.stamp(old),validUntil=u.stamp(old+dt.timedelta(seconds=30)));p=self.install(pub,p)
        pub.s.data['clusters']['cmtc-a']['lastPublication']=p
        # Reopening owned output must preserve an expired checkpoint for recovery.
        pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'data':{}})
        with self.assertRaises(lab.Refusal):pub.read_publication('cmtc-a','source')
        p['sequence']=0;self.install(pub,p)
        with self.assertRaises((u.Refusal,lab.Refusal)):pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'data':{}})
    def test_known_output_deletion_is_not_recreated(self):
        pub,p=self.setup_pub();api=pub.apis['cmtc-a'];del api.objects[pub.cm_path(u.OUT)]
        before=len(api.calls)
        with self.assertRaises(u.Refusal):pub.owned_object('cmtc-a','ConfigMap',u.OUT,{'data':{}})
        self.assertTrue(all(x[0]=='GET' for x in api.calls[before:]))
    def test_failure_rolls_back_only_exact_owned_template_keeps_public_objects(self):
        pub,p=self.setup_pub();c=pub.s.data['clusters']['cmtc-a'];c.update(baseline=baseline(),deploymentUID='deployment-uid');c['active']=u.enabled_template(c['baseline'],'owner-token','cmtc-a','source','source-uid','out-uid',self.fx.rootpin,1)
        path='/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP;pub.apis['cmtc-a'].objects[path]=deployment(c['active'])
        changed=[]
        def patch_template(cluster,expected,desired):
            d=pub.apis[cluster].objects[path];u.template_patch(d,c['deploymentUID'],expected,desired);d['spec']['template']=copy.deepcopy(desired);changed.append(cluster)
        pub.patch_template=patch_template;pub.runtime=lambda cluster,template:None
        pub.disable_owned('cmtc-a');self.assertEqual(['cmtc-a','cmtc-a'],changed);self.assertEqual(c['baseline'],pub.apis['cmtc-a'].objects[path]['spec']['template']);self.assertIn(pub.cm_path(u.OUT),pub.apis['cmtc-a'].objects);self.assertIn(pub.cm_path('source'),pub.apis['cmtc-a'].objects)
        pub.apis['cmtc-a'].objects[path]=deployment(c['active']);pub.apis['cmtc-a'].objects[path]['spec']['template']['metadata']['annotations']['foreign']='change'
        with self.assertRaises(u.Refusal):pub.disable_owned('cmtc-a')

class AdvanceTests(unittest.TestCase):
    """Generation N-1 -> N on the same ledger owner, output and floors."""
    @classmethod
    def setUpClass(cls):cls.fx=Fixtures()
    def live(self,image='localhost/cmtc:current'):
        t=baseline();t['spec']['containers'][0]['image']=image;t['metadata']['annotations']['kubectl.kubernetes.io/restartedAt']='then'
        return u.enabled_template(t,'owner-token','cmtc-a',u.source_name(1),'src1-uid','out-uid',self.fx.rootpin,1)
    def setup_advance(self,live=None):
        pub=publisher();pub.a.generation=2;pub.a.image='localhost/cmtc:current';pub.a.root_sha256=self.fx.rootpin;pub.a.cluster_pins={'cmtc-a':'ks-uid'}
        pub.inspect_image=lambda cluster,node:None
        c=pub.s.data['clusters']['cmtc-a'];c.update(deploymentUID='deployment-uid',saUID='sa-uid');c['uids'].update({'ConfigMap/'+u.source_name(1):'src1-uid','ConfigMap/'+u.OUT:'out-uid','Role/'+u.ACCESS:'role-uid'})
        api=pub.apis['cmtc-a'];api.objects['/api/v1/namespaces/kube-system']={'metadata':{'uid':'ks-uid','resourceVersion':'1'}}
        api.objects['/api/v1/namespaces/'+u.NS+'/serviceaccounts/cmtc-controller']={'metadata':{'uid':'sa-uid','resourceVersion':'1'}}
        api.objects['/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP]=deployment(live or self.live())
        return pub,c,api
    def test_producer_disabled_round_trips_the_live_template_and_requires_ownership(self):
        live=self.live();disabled=u.producer_disabled(live,'owner-token')
        self.assertFalse(any(x.startswith('--issuer-profile') for x in disabled['spec']['containers'][0]['args']))
        self.assertEqual('then',disabled['metadata']['annotations']['kubectl.kubernetes.io/restartedAt'])
        self.assertEqual(live,u.enabled_template(disabled,'owner-token','cmtc-a',u.source_name(1),'src1-uid','out-uid',self.fx.rootpin,1))
        with self.assertRaises(u.Refusal):u.producer_disabled(live,'other-owner')
    def test_identity_advance_changes_only_generation_plus_one_and_image(self):
        old={'generation':1,'image':'a','imageConfig':'c','sourceRevision':'s','rootSHA256':'r','clusterPins':{'cmtc-a':'x'}}
        u.advanced_identity(old,dict(old,generation=2,image='b',imageConfig='d',sourceRevision='t'))
        for new in (dict(old,generation=3),dict(old,generation=1),dict(old,generation=2,rootSHA256='other'),dict(old,generation=2,clusterPins={'cmtc-a':'y'})):
            with self.subTest(new=new),self.assertRaises(u.Refusal):u.advanced_identity(old,new)
    def test_preflight_pins_exact_previous_generation_and_records_disabled_baseline(self):
        pub,c,api=self.setup_advance();pub.advance_preflight('cmtc-a',1)
        self.assertEqual('preflighted',c['advance']['phase']);self.assertEqual(self.live(),c['advance']['from'])
        self.assertEqual('localhost/cmtc:current',c['advance']['disabled']['spec']['containers'][0]['image'])
    def test_preflight_refuses_drifted_producer_wrong_image_or_replaced_identity(self):
        drifted=self.live();drifted['spec']['containers'][0]['args'].append('--issuer-profile-extra=1')
        cases=[('drift',lambda api:None,drifted),('image',lambda api:None,self.live('localhost/cmtc:other')),('sa',lambda api:api.objects['/api/v1/namespaces/'+u.NS+'/serviceaccounts/cmtc-controller']['metadata'].update(uid='new'),None),('cluster',lambda api:api.objects['/api/v1/namespaces/kube-system']['metadata'].update(uid='other'),None)]
        for name,change,live in cases:
            pub,c,api=self.setup_advance(live);change(api)
            with self.subTest(name),self.assertRaises(u.Refusal):pub.advance_preflight('cmtc-a',1)
            self.assertNotIn('advance',c)
    def test_advance_requires_a_qualified_ledger_at_the_previous_generation(self):
        for data in ({'success':False,'approval':{'generation':1}},{'success':True,'approval':{'generation':2}}):
            pub,c,api=self.setup_advance();pub.s.data.update(data)
            with self.subTest(data=data),self.assertRaises(u.Refusal):pub.advance()
            self.assertNotIn('advance',c)
    def test_access_is_cas_replaced_and_verified(self):
        pub,c,api=self.setup_advance();path='/apis/rbac.authorization.k8s.io/v1/namespaces/'+u.NS+'/roles/'+u.ACCESS
        api.objects[path]={'metadata':{'uid':'role-uid','resourceVersion':'7','labels':{u.OWNER:'owner-token'}},'rules':u.access_rules([u.source_name(1)])}
        sent=[]
        def command(argv,timeout=25):
            ops=json.loads(argv[argv.index('-p')+1]);sent.append(ops);api.objects[path]['rules']=ops[-1]['value'];return b''
        pub.command=command;pub.set_access('cmtc-a',[u.source_name(1),u.source_name(2)])
        self.assertEqual([{'op':'test','path':'/metadata/uid','value':'role-uid'},{'op':'test','path':'/metadata/resourceVersion','value':'7'},{'op':'test','path':'/rules','value':u.access_rules([u.source_name(1)])},{'op':'replace','path':'/rules','value':u.access_rules([u.source_name(1),u.source_name(2)])}],sent[0])
        pub.set_access('cmtc-a',[u.source_name(1),u.source_name(2)]);self.assertEqual(1,len(sent))
        pub.command=lambda argv,timeout=25:b''
        with self.assertRaises(u.Refusal):pub.set_access('cmtc-a',[u.source_name(2)])
    def test_agent_access_names_both_sources_then_the_new_one_and_needs_the_lab_label(self):
        pub,c,api=self.setup_advance();path='/apis/rbac.authorization.k8s.io/v1/namespaces/'+u.NS+'/roles/'+u.AGENT_ROLE
        label={u.AGENT_ROLE_LABEL[0]:u.AGENT_ROLE_LABEL[1]}
        api.objects[path]={'metadata':{'uid':'agent-role-uid','resourceVersion':'9','labels':label},'rules':u.agent_access_rules([u.source_name(1)])}
        sent=[]
        def command(argv,timeout=25):
            ops=json.loads(argv[argv.index('-p')+1]);sent.append(ops);api.objects[path]['rules']=ops[-1]['value'];return b''
        pub.command=command;pub.set_agent_access('cmtc-a',[u.source_name(1),u.source_name(2)])
        both=[{'apiGroups':[''],'resources':['configmaps'],'resourceNames':[u.source_name(1),u.source_name(2),u.OUT],'verbs':['get']}]
        self.assertEqual([{'op':'test','path':'/metadata/uid','value':'agent-role-uid'},{'op':'test','path':'/metadata/resourceVersion','value':'9'},{'op':'test','path':'/rules','value':u.agent_access_rules([u.source_name(1)])},{'op':'replace','path':'/rules','value':both}],sent[0])
        pub.set_agent_access('cmtc-a',[u.source_name(1),u.source_name(2)]);self.assertEqual(1,len(sent))
        pub.command=lambda argv,timeout=25:b''
        with self.assertRaisesRegex(u.Refusal,'acknowledgment'):pub.set_agent_access('cmtc-a',[u.source_name(2)])
        api.objects[path]['metadata']['labels']={}
        with self.assertRaisesRegex(u.Refusal,'lab-managed'):pub.set_agent_access('cmtc-a',[u.source_name(2)])
    def test_await_source_tolerates_the_previous_publication_then_times_out(self):
        pub,c,api=self.setup_advance();api.objects[pub.cm_path(u.OUT)]={'metadata':{'uid':'out-uid','resourceVersion':'1','labels':{u.OWNER:'owner-token',u.OUTPUT:'true'}},'data':{'profile.json':u.compact({'source':{'name':u.source_name(1)}})}}
        reads=[]
        real=api.get
        def get(path):
            reads.append(path)
            if path==pub.cm_path(u.OUT) and len([r for r in reads if r==path])==3:api.objects[path]['data']['profile.json']=u.compact({'source':{'name':u.source_name(2)}})
            return real(path)
        api.get=get
        with patch.object(u.time,'sleep',lambda s:None):pub.await_source('cmtc-a',u.source_name(2))
        self.assertEqual(3,reads.count(pub.cm_path(u.OUT)))
        api.objects[pub.cm_path(u.OUT)]['data']['profile.json']=u.compact({'source':{'name':u.source_name(1)}});api.get=real
        with patch.object(u.time,'sleep',lambda s:None),self.assertRaises(u.Refusal):pub.await_source('cmtc-a',u.source_name(2),timeout=0.05)
    def test_resume_accepts_an_interrupted_restore_fence_only(self):
        pub,c,api=self.setup_advance();pub.advance_preflight('cmtc-a',1);step=c['advance']
        fence=copy.deepcopy(step['from']);fence['metadata']['annotations'][u.ROLLBACK]='f';step.update(to={'other':1},fence=fence,phase='restore-intended')
        path='/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP;api.objects[path]['spec']['template']=copy.deepcopy(fence)
        pub.advance_preflight('cmtc-a',1)
        api.objects[path]['spec']['template']['metadata']['annotations']['foreign']='x'
        with self.assertRaises(u.Refusal):pub.advance_preflight('cmtc-a',1)
    def test_restore_fences_then_returns_exact_previous_template_only(self):
        pub,c,api=self.setup_advance();pub.advance_preflight('cmtc-a',1);step=c['advance']
        step.update(to=u.enabled_template(step['disabled'],'owner-token','cmtc-a',u.source_name(2),'src2-uid','out-uid',self.fx.rootpin,2),phase='patch-intended')
        path='/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP;api.objects[path]['spec']['template']=copy.deepcopy(step['to']);seen=[]
        def patch_template(cluster,expected,desired):
            d=api.objects[path];u.template_patch(d,'deployment-uid',expected,desired);d['spec']['template']=copy.deepcopy(desired);seen.append(desired)
        pub.patch_template=patch_template;pub.runtime=lambda cluster,template:None
        pub.restore_advance('cmtc-a')
        self.assertIn(u.ROLLBACK,seen[0]['metadata']['annotations']);self.assertEqual(step['from'],api.objects[path]['spec']['template']);self.assertEqual('restored-after-failure',step['phase'])
        pub,c,api=self.setup_advance();pub.advance_preflight('cmtc-a',1);c['advance'].update(to=step['to'],phase='patch-intended')
        api.objects[path]['spec']['template']['metadata']['annotations']['foreign']='change'
        with self.assertRaises(u.Refusal):pub.restore_advance('cmtc-a')

class RuntimeAndCASTests(unittest.TestCase):
    """Archive-imported image identity and Deployment CAS races."""
    def test_archive_import_accepts_only_the_exact_config_digest(self):
        pulled={'id':'sha256:'+'c'*64,'repoDigests':['localhost/cmtc@sha256:'+'m'*64]}
        self.assertEqual({'sha256:'+'m'*64},u.runtime_image_ids(pulled))
        self.assertNotIn('sha256:'+'c'*64,u.runtime_image_ids(pulled))
        self.assertEqual({'sha256:'+'c'*64},u.runtime_image_ids({'id':'sha256:'+'c'*64,'repoDigests':[]}))
    def cas(self,after_failure):
        pub=publisher();c=pub.s.data['clusters']['cmtc-a'];c['deploymentUID']='deployment-uid';api=pub.apis['cmtc-a']
        path='/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP;api.objects[path]=deployment(baseline())
        desired=copy.deepcopy(baseline());desired['metadata']['annotations']['next']='1';calls=[]
        def command(argv,timeout=25):
            calls.append(json.loads(argv[argv.index('-p')+1]))
            d=api.objects[path]
            if len(calls)==1:
                after_failure(d,desired);raise u.Refusal('public command failed (1): test operation failed')
            d['spec']['template']=copy.deepcopy(calls[-1][-1]['value']);d['metadata']['resourceVersion']=str(int(d['metadata']['resourceVersion'])+1);return b''
        pub.command=command
        return pub,api,path,desired,calls
    def test_status_write_race_retries_with_fresh_resource_version(self):
        def status_write(d,desired):d['metadata']['resourceVersion']='99'
        pub,api,path,desired,calls=self.cas(status_write)
        pub.patch_template('cmtc-a',baseline(),desired)
        self.assertEqual(2,len(calls));self.assertEqual('99',calls[1][1]['value']);self.assertEqual(desired,api.objects[path]['spec']['template'])
    def test_failed_ack_with_committed_template_is_not_reapplied(self):
        def committed(d,desired):d['spec']['template']=copy.deepcopy(desired);d['metadata']['resourceVersion']='4'
        pub,api,path,desired,calls=self.cas(committed)
        pub.patch_template('cmtc-a',baseline(),desired);self.assertEqual(1,len(calls))
    def test_foreign_template_change_is_never_retried(self):
        def foreign(d,desired):d['spec']['template']['metadata']['annotations']['foreign']='x';d['metadata']['resourceVersion']='5'
        pub,api,path,desired,calls=self.cas(foreign)
        with self.assertRaises(u.Refusal):pub.patch_template('cmtc-a',baseline(),desired)
        self.assertEqual(1,len(calls))

def cm_cert(k,name,parent=None,pk=None,path_length=None,usage=True,extra=None,hours=2,san=None):
    """A CA shaped like cert-manager's: no path length, Digital Signature, Key Encipherment and Cert Sign, key identifiers."""
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    b=(x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject).public_key(k.public_key())
       .serial_number(x509.random_serial_number()).not_valid_before(NOW-dt.timedelta(hours=3)).not_valid_after(NOW+dt.timedelta(hours=hours))
       .add_extension(x509.BasicConstraints(ca=True,path_length=path_length),critical=True)
       .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=usage,crl_sign=False,encipher_only=None,decipher_only=None),critical=True)
       .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=False))
    if parent:b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((pk or k).public_key()),critical=False)
    if san:b=b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]),critical=False)
    if extra:b=b.add_extension(extra,critical=False)
    return b.sign(pk or k,hashes.SHA256())

# A refusal from the shared certificate helpers (public_proof) is a refusal too.
REFUSED=(u.Refusal,q.Refusal)

class Mesh:
    """The mesh root and each cluster's SPIRE intermediate, and the Kubernetes objects that publish them."""
    def __init__(self):
        self.root_key=key();self.root=cm_cert(self.root_key,'cmtc mesh root CA',hours=24*400);self.rootpin=q.sha(q.der(self.root))
        self.keys={c:key() for c in q.DOMAINS};self.intermediates={c:cm_cert(self.keys[c],c+' SPIRE intermediate CA',self.root,self.root_key,hours=24*20) for c in q.DOMAINS}
    def evidence(self,cluster,intermediate=None,root=None,observed=None):
        return {'cluster':cluster,'source':'kubernetes-api-public-certificate-objects','protected':False,'observedAt':(observed or NOW).isoformat(),
                'intermediatePEM':q.pem(intermediate or self.intermediates[cluster]),'rootPEM':q.pem(root or self.root)}
    def objects(self,cluster):
        import base64
        name=cluster+'-spire-intermediate';ref={'name':'cmtc-mesh-root','kind':'ClusterIssuer','group':'cert-manager.io'};cert=self.intermediates[cluster]
        return {
            '/apis/cert-manager.io/v1/namespaces/cert-manager/certificates/'+name:{'metadata':{'uid':name+'-uid','resourceVersion':'1'},'spec':{'isCA':True,'secretName':name,'issuerRef':ref},
                'status':{'revision':2,'notAfter':u.stamp(cert.not_valid_after_utc),'conditions':[{'type':'Ready','status':'True'}]}},
            '/apis/cert-manager.io/v1/namespaces/cert-manager/certificaterequests':{'items':[
                {'metadata':{'uid':'old-cr','resourceVersion':'1','annotations':{'cert-manager.io/certificate-revision':'1'},'ownerReferences':[{'kind':'Certificate','uid':name+'-uid','controller':True}]},
                 'spec':{'issuerRef':ref},'status':{'certificate':'bm90IGEgY2VydGlmaWNhdGU=','conditions':[{'type':'Approved','status':'True'},{'type':'Ready','status':'True'}]}},
                {'metadata':{'uid':'cr-uid','resourceVersion':'1','annotations':{'cert-manager.io/certificate-revision':'2'},'ownerReferences':[{'kind':'Certificate','uid':name+'-uid','controller':True}]},
                 'spec':{'issuerRef':ref},'status':{'certificate':base64.b64encode(q.pem(cert).encode()).decode(),'conditions':[{'type':'Approved','status':'True'},{'type':'Ready','status':'True'}]}}]},
            '/apis/cert-manager.io/v1/clusterissuers/'+name:{'metadata':{'uid':'ci-uid','resourceVersion':'1'},'spec':{'ca':{'secretName':name}}},
            # trust-manager writes ca.crt without its last newline.
            '/api/v1/namespaces/'+u.NS+'/configmaps/cmtc-mesh-root':{'metadata':{'uid':'root-cm','resourceVersion':'1'},'data':{'ca.crt':q.pem(self.root).rstrip('\n')}},
            '/api/v1/namespaces/cilium-spire/configmaps/spire-server':{'metadata':{'uid':'spire-cm','resourceVersion':'1'},'data':{'server.conf':
                'plugins {\n  UpstreamAuthority "cert-manager" {\n    plugin_data {\n      namespace = "cilium-spire"\n      issuer_name = "'+name+'"\n      issuer_kind = "ClusterIssuer"\n    }\n  }\n}\n'}}}

class SPIREIntermediateTests(unittest.TestCase):
    """Issue #34: each cluster's SPIRE intermediate under the mesh root replaces SPIRE's 24-hour signer."""
    @classmethod
    def setUpClass(cls):cls.m=Mesh()
    def build(self,evidence=None,horizon=3600):
        return u.build_intermediate_approval(evidence or {c:self.m.evidence(c) for c in q.DOMAINS},q,6,NOW,horizon)
    def test_each_cluster_has_its_intermediate_as_its_one_issuer_under_one_root(self):
        a=self.build()
        self.assertEqual([{'certificatePEM':q.pem(self.m.root),'sha256':self.m.rootpin}],a['roots'])
        for c in a['clusters']:
            i=self.m.intermediates[c['clusterID']]
            self.assertEqual(q.DOMAINS[c['clusterID']],c['trustDomain'])
            self.assertEqual([{'certificatePEM':q.pem(i),'spkiSHA256':q.sha(q.spki(i)),'rootSHA256':self.m.rootpin,'signsSPIRECA':True}],c['issuers'])
        self.assertEqual(u.stamp(NOW+dt.timedelta(seconds=3600)),a['expiresAt'])
    def test_expiry_is_bounded_by_the_certificates_and_a_horizon_of_at_most_30_days(self):
        self.assertEqual(u.stamp(self.m.intermediates['cmtc-a'].not_valid_after_utc),self.build(horizon=30*86400)['expiresAt'])
        for horizon in (119,30*86400+1):
            with self.subTest(horizon=horizon),self.assertRaises(REFUSED):self.build(horizon=horizon)
    def test_refuses_what_the_verifiers_refuse(self):
        m=self.m;k=key();other=key();other_root=cm_cert(other,'other root')
        bad={
            'not signed by the root':cm_cert(k,'cmtc-a SPIRE intermediate CA',other_root,other),
            'wrong common name':cm_cert(k,'cmtc-b SPIRE intermediate CA',m.root,m.root_key),
            'no room for a SPIRE CA':cm_cert(k,'cmtc-a SPIRE intermediate CA',m.root,m.root_key,path_length=0),
            'not a signing CA':cm_cert(k,'cmtc-a SPIRE intermediate CA',m.root,m.root_key,usage=False),
            'a SAN':cm_cert(k,'cmtc-a SPIRE intermediate CA',m.root,m.root_key,san='spiffe://cmtc-a.mesh.example'),
            'another extension':cm_cert(k,'cmtc-a SPIRE intermediate CA',m.root,m.root_key,extra=x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])),
            'expired':cm_cert(k,'cmtc-a SPIRE intermediate CA',m.root,m.root_key,hours=-1),
            'the other cluster key':cm_cert(m.keys['cmtc-b'],'cmtc-a SPIRE intermediate CA',m.root,m.root_key),
        }
        for why,cert in bad.items():
            with self.subTest(why),self.assertRaises(REFUSED):self.build({'cmtc-a':m.evidence('cmtc-a',cert),'cmtc-b':m.evidence('cmtc-b')})
        shallow=cm_cert(other,'cmtc mesh root CA',path_length=1)
        with self.subTest('root with no room for the intermediate and a SPIRE CA'),self.assertRaises(REFUSED):
            self.build({'cmtc-a':m.evidence('cmtc-a',cm_cert(k,'cmtc-a SPIRE intermediate CA',shallow,other),shallow),'cmtc-b':m.evidence('cmtc-b')})
        with self.subTest('two roots'),self.assertRaises(REFUSED):
            self.build({'cmtc-a':m.evidence('cmtc-a',cm_cert(k,'cmtc-a SPIRE intermediate CA',other_root,other),other_root),'cmtc-b':m.evidence('cmtc-b')})
        with self.subTest('stale evidence'),self.assertRaises(REFUSED):
            self.build({'cmtc-a':m.evidence('cmtc-a',observed=NOW-dt.timedelta(minutes=5)),'cmtc-b':m.evidence('cmtc-b')})
        with self.subTest('one cluster'),self.assertRaises(REFUSED):self.build({'cmtc-a':m.evidence('cmtc-a')})
    def publisher(self):
        pub=publisher();pub.a.issuer_mode=u.INTERMEDIATE;pub.a.root_sha256=self.m.rootpin;pub.a.generation=6;pub.a.horizon=3600
        pub.a.root_issuer='cmtc-mesh-root';pub.a.root_configmap='cmtc-mesh-root';pub.a.cert_manager_namespace='cert-manager'
        pub.a.intermediate_pins={c:c+'-spire-intermediate-uid' for c in q.DOMAINS}
        pub.apis={c:API() for c in q.DOMAINS}
        for c in q.DOMAINS:pub.apis[c].objects.update(self.m.objects(c))
        return pub
    def test_evidence_comes_from_public_objects_of_the_current_revision_and_no_secret(self):
        pub=self.publisher();evidence,approval=pub.current_approval(lambda c:None)
        self.assertEqual(approval['clusters'],self.build()['clusters'])
        self.assertEqual('cr-uid',evidence['cmtc-a']['certificateRequestUID']);self.assertEqual(2,evidence['cmtc-a']['revision'])
        self.assertFalse([c for api in pub.apis.values() for c in api.calls if '/secrets' in c[1]])
    def test_evidence_refuses_each_broken_binding(self):
        def edit(path,f):
            def apply(objects):f(objects[path])
            return apply
        cert='/apis/cert-manager.io/v1/namespaces/cert-manager/certificates/cmtc-a-spire-intermediate'
        crs='/apis/cert-manager.io/v1/namespaces/cert-manager/certificaterequests'
        cases={
            'a replaced Certificate':edit(cert,lambda o:o['metadata'].update(uid='other')),
            'not Ready':edit(cert,lambda o:o['status'].update(conditions=[{'type':'Ready','status':'False'}])),
            'another issuer':edit(cert,lambda o:o['spec']['issuerRef'].update(name='cmtc-spire-issuer')),
            'a status that is not the issued certificate':edit(cert,lambda o:o['status'].update(notAfter='2030-01-01T00:00:00Z')),
            'no request of the current revision':edit(crs,lambda o:o['items'].pop()),
            'a request that was not approved':edit(crs,lambda o:o['items'][1]['status'].update(conditions=[{'type':'Ready','status':'True'}])),
            'an issuer of another Secret':edit('/apis/cert-manager.io/v1/clusterissuers/cmtc-a-spire-intermediate',lambda o:o['spec']['ca'].update(secretName='x')),
            'another root':edit('/api/v1/namespaces/'+u.NS+'/configmaps/cmtc-mesh-root',lambda o:o['data'].update({'ca.crt':q.pem(cm_cert(key(),'other'))})),
            'SPIRE on another issuer':edit('/api/v1/namespaces/cilium-spire/configmaps/spire-server',lambda o:o['data'].update({'server.conf':o['data']['server.conf'].replace('cmtc-a-spire-intermediate','cmtc-spire-issuer')})),
        }
        for why,mutate in cases.items():
            with self.subTest(why):
                pub=self.publisher();mutate(pub.apis['cmtc-a'].objects)
                with self.assertRaises(REFUSED):pub.current_approval(lambda c:None)
    def test_spire_issuer_name_needs_exactly_one_cert_manager_upstream(self):
        conf=self.m.objects('cmtc-a')['/api/v1/namespaces/cilium-spire/configmaps/spire-server']['data']['server.conf']
        self.assertEqual('cmtc-a-spire-intermediate',u.spire_issuer_name(conf))
        for bad in ('',conf.replace('"cert-manager"','"disk"'),conf+conf):
            with self.assertRaises(REFUSED):u.spire_issuer_name(bad)
    def test_the_succession_advance_alone_may_change_the_root_and_the_evidence_pins(self):
        signer={'generation':5,'image':'a','imageConfig':'c','sourceRevision':'s','rootSHA256':'old','clusterPins':{'cmtc-a':'x'},'approvalPins':{'cmtc-a':'p'},'spireServerImage':'i'}
        succession={'generation':6,'image':'b','imageConfig':'d','sourceRevision':'t','rootSHA256':'mesh','clusterPins':{'cmtc-a':'x'},'issuerMode':u.INTERMEDIATE,'intermediatePins':{'cmtc-a':'q'}}
        u.advanced_identity(signer,succession)
        u.advanced_identity(succession,dict(succession,generation=7,image='c'))
        for old,new in ((signer,dict(signer,generation=6,rootSHA256='mesh')),(succession,dict(succession,generation=7,rootSHA256='other')),
                        (succession,dict(succession,generation=7,intermediatePins={'cmtc-a':'r'})),(signer,dict(succession,clusterPins={'cmtc-a':'y'})),(signer,dict(succession,generation=7))):
            with self.subTest(new=new),self.assertRaises(REFUSED):u.advanced_identity(old,new)
    def test_preflight_matches_the_live_producer_against_the_previous_root(self):
        fx=Fixtures();t=baseline();t['spec']['containers'][0]['image']='localhost/cmtc:current'
        live=u.enabled_template(t,'owner-token','cmtc-a',u.source_name(5),'src5-uid','out-uid',fx.rootpin,5)
        pub=publisher();pub.a.generation=6;pub.a.image='localhost/cmtc:current';pub.a.root_sha256=self.m.rootpin;pub.a.previous_root_sha256=fx.rootpin
        pub.a.cluster_pins={'cmtc-a':'ks-uid'};pub.inspect_image=lambda cluster,node:None
        c=pub.s.data['clusters']['cmtc-a'];c.update(deploymentUID='deployment-uid',saUID='sa-uid');c['uids'].update({'ConfigMap/'+u.source_name(5):'src5-uid','ConfigMap/'+u.OUT:'out-uid'})
        api=pub.apis['cmtc-a'];api.objects['/api/v1/namespaces/kube-system']={'metadata':{'uid':'ks-uid','resourceVersion':'1'}}
        api.objects['/api/v1/namespaces/'+u.NS+'/serviceaccounts/cmtc-controller']={'metadata':{'uid':'sa-uid','resourceVersion':'1'}}
        api.objects['/apis/apps/v1/namespaces/'+u.NS+'/deployments/'+u.DEP]=deployment(live)
        pub.advance_preflight('cmtc-a',5);self.assertEqual(live,c['advance']['from'])
        pub.a.previous_root_sha256=self.m.rootpin;c.pop('advance')
        with self.assertRaises(REFUSED):pub.advance_preflight('cmtc-a',5)

if __name__=='__main__':unittest.main()
