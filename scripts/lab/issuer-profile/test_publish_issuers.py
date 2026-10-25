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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID
import publish_issuers as u

ROOT=Path(__file__).resolve().parents[3]
pki=u.load(str(ROOT/'scripts/lab/pki/pki.py'),'pki_test_accepted')
q=u.load(str(ROOT/'scripts/lab/spire/public_proof.py'),'proof_test_accepted')
lab=u.load(str(ROOT/'scripts/lab/issuer-profile/test-issuer-profile.py'),'pub_test_accepted')
NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def key():return ec.generate_private_key(ec.SECP256R1())
def cert(k,name,parent=None,pk=None,depth=0,domain=None):
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    b=x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(NOW-dt.timedelta(minutes=1)).not_valid_after(NOW+dt.timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=True,path_length=depth),critical=True).add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True)
    if domain:b=b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('spiffe://'+domain)]),critical=False)
    return b.sign(pk or k,hashes.SHA256())

class Fixtures:
    def __init__(self):
        rk=key();root=cert(rk,'root',depth=2);self.parents={};self.proofs={}
        for cluster,domain in q.DOMAINS.items():
            pk=key();parent=cert(pk,cluster+' parent',root,rk,1)
            sk=rsa.generate_private_key(public_exponent=65537,key_size=2048);signer=cert(sk,cluster+' SPIRE',parent,pk,None,domain)
            self.parents[cluster]=(parent,root)
            self.proofs[cluster]={'cluster':cluster,'domain':domain,'protected':False,'workloadAttestation':False,'source':'authenticated-kubernetes-exec-local-SPIRE-admin-API-nonce-mint','observedAt':NOW.isoformat(),'directIssuerSHA256':q.sha(q.der(signer)),'directIssuerPEM':q.pem(signer),'parentPEM':q.pem(parent),'rootSHA256':q.sha(q.der(root))}
        self.rootpin=q.sha(q.der(root))
    def approval(self):return u.build_approval(self.proofs,self.parents,q,1,NOW,3600)

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

if __name__=='__main__':unittest.main()
