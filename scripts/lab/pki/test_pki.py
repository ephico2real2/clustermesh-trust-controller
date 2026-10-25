import copy
import base64
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import pki

class Fake:
    def __init__(self):
        self.objects={}
        self.calls=[]
        self.number=0
        self.fail=None
    def get(self,path,metadata=False):
        self.calls.append(('GET',path,metadata))
        if '/secrets/' in path and not metadata:
            raise AssertionError('private Secret host fetch')
        if path not in self.objects:
            raise pki.APIError(404,'NotFound')
        obj=copy.deepcopy(self.objects[path])
        if metadata:
            return {'apiVersion':'meta.k8s.io/v1','kind':'PartialObjectMetadata','metadata':obj['metadata']}
        return obj
    def request(self,method,path,body=None,metadata=False):
        if method=='GET':
            return self.get(path,metadata)
        self.calls.append((method,path,copy.deepcopy(body)))
        if self.fail:
            self.fail(method,path,body)
        if method=='POST':
            name=body['metadata']['name']
            target=path+'/'+name
            if target in self.objects:
                raise pki.APIError(409,'AlreadyExists')
            self.number+=1
            o=copy.deepcopy(body)
            o['metadata'].update(uid='uid-'+str(self.number),resourceVersion=str(self.number))
            self.objects[target]=o
            return copy.deepcopy(o)
        if method=='PUT':
            old=self.objects[path]
            m=body['metadata']
            if (m['uid'],m['resourceVersion'])!=(old['metadata']['uid'],old['metadata']['resourceVersion']):
                raise pki.APIError(409,'Conflict')
            self.number+=1
            o=copy.deepcopy(body)
            o['metadata']['resourceVersion']=str(self.number)
            self.objects[path]=o
            return copy.deepcopy(o)
        if method=='DELETE':
            old=self.objects[path]
            pre=body['preconditions']
            if (pre['uid'],pre['resourceVersion'])!=(old['metadata']['uid'],old['metadata']['resourceVersion']):
                raise pki.APIError(409,'Conflict')
            del self.objects[path]
            return {'kind':'Status','status':'Success'}
        raise AssertionError(method)

class Tests(unittest.TestCase):
    def temp(self):
        d=tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        os.chmod(d.name,0o700)
        return str(Path(d.name).resolve())
    def csr(self,cluster,pin):
        key=ec.generate_private_key(ec.SECP256R1())
        csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,cluster+' SPIRE cluster CA')])).sign(key,hashes.SHA256())
        return {'schemaVersion':1,'cluster':cluster,'secretNamespace':pki.NS,'secretName':pki.SECRET,
            'secretUID':'secret-uid','resourceVersion':'22','rootSHA256':pin,
            'csrSHA256':pki.digest(csr.public_bytes(serialization.Encoding.DER)),
            'clusterIssuerCSR':csr.public_bytes(serialization.Encoding.PEM).decode(),'status':'pending'}
    def test_root_real_crypto_stable_sign_two_distinct_parents(self):
        directory=self.temp()
        with pki.Root(directory) as r:
            pin=r.pin
            rootkey=Path(directory,'current/key.pem').read_bytes()
            chains=[]
            for cluster in ['cmtc-a','cmtc-b']:
                request=self.csr(cluster,pin)
                chain=r.sign(request)
                certs=x509.load_pem_x509_certificates(chain.encode())
                self.assertEqual(len(certs),2)
                self.assertLessEqual(certs[0].serial_number.bit_length(),159)
                self.assertLessEqual(certs[1].serial_number.bit_length(),159)
                self.assertEqual(certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.path_length,1)
                self.assertEqual(certs[1].extensions.get_extension_for_class(x509.BasicConstraints).value.path_length,2)
                certs[1].public_key().verify(certs[0].signature,certs[0].tbs_certificate_bytes,ec.ECDSA(certs[0].signature_hash_algorithm))
                self.assertNotIn(rootkey.decode(),chain)
                chains.append(certs[0])
            self.assertNotEqual(pki.public_der(chains[0].public_key()),pki.public_der(chains[1].public_key()))
            self.assertNotEqual(chains[0].serial_number,chains[1].serial_number)
        with pki.Root(directory) as r:
            self.assertEqual(r.pin,pin)
            self.assertEqual(Path(directory,'current/key.pem').read_bytes(),rootkey)
    def test_root_partial_symlink_mode_mismatch_fail_closed(self):
        for kind in ['partial','symlink','mode','key-mismatch']:
            with self.subTest(kind=kind):
                directory=self.temp()
                if kind=='partial':
                    Path(directory,'pending-stale').mkdir(mode=0o700)
                elif kind=='symlink':
                    os.symlink(self.temp(),Path(directory,'current'))
                elif kind=='mode':
                    os.chmod(directory,0o755)
                else:
                    with pki.Root(directory):
                        pass
                    k=ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
                    Path(directory,'current/key.pem').write_bytes(k)
                with self.assertRaises((pki.Refusal,OSError)):
                    with pki.Root(directory):
                        pass
    def test_root_lock_exclusive(self):
        with pki.Root(self.temp()) as r:
            with self.assertRaises(BlockingIOError):
                with pki.Root(r.path):
                    pass
    def test_root_rejects_wrong_csr_signature_subject_digest_and_pin(self):
        with pki.Root(self.temp()) as r:
            request=self.csr('cmtc-a',r.pin)
            for field,value in [('csrSHA256','0'*64),('rootSHA256','0'*64),('cluster','cmtc-b')]:
                with self.subTest(field=field):
                    bad=dict(request)
                    bad[field]=value
                    with self.assertRaises(pki.Refusal):
                        r.sign(bad)
            bad=dict(request)
            bad['clusterIssuerCSR']+='extra'
            with self.assertRaises((pki.Refusal,ValueError)):
                r.sign(bad)
    def test_ledger_initialization_metadata_only_and_stable_retry(self):
        a=Fake()
        ledger=pki.ensure_ledger(a,'cmtc-a','a'*64)
        uid=ledger['data']['secretUID']
        # Simulate initialized key material. The host must still fetch only metadata.
        a.objects[pki.PREFIX+'secrets/'+pki.SECRET]['data']={'tls.key':'DO_NOT_FETCH'}
        again=pki.ensure_ledger(a,'cmtc-a','a'*64)
        self.assertEqual(again['data']['secretUID'],uid)
        self.assertEqual(sum(x[0]=='POST' and x[1].endswith('/secrets') for x in a.calls),1)
        self.assertTrue(all(x[2] is True for x in a.calls if x[0]=='GET' and '/secrets/' in x[1]))
    def test_missing_ledger_existing_secret_refuses(self):
        a=Fake()
        a.objects[pki.PREFIX+'secrets/'+pki.SECRET]={'metadata':{'uid':'foreign','resourceVersion':'1'}}
        with self.assertRaisesRegex(pki.Refusal,'without ledger'):
            pki.ensure_ledger(a,'cmtc-a','a'*64)
        self.assertFalse(any(x[0]=='POST' for x in a.calls))
    def test_lost_secret_creation_ledger_commit_preserves_unknown_authority(self):
        a=Fake()
        def fail(method,path,body):
            if method=='PUT':
                raise pki.APIError(500,'lost ledger ACK')
        a.fail=fail
        with self.assertRaises(pki.APIError):
            pki.ensure_ledger(a,'cmtc-a','a'*64)
        a.fail=None
        with self.assertRaisesRegex(pki.Refusal,'unrecorded Secret'):
            pki.ensure_ledger(a,'cmtc-a','a'*64)
        self.assertIn(pki.PREFIX+'secrets/'+pki.SECRET,a.objects)
        self.assertFalse(any(x[0]=='DELETE' for x in a.calls))
    def test_ledger_uid_replacement_wrong_root_missing_secret_refuse(self):
        for kind in ['replacement','root','missing']:
            with self.subTest(kind=kind):
                a=Fake()
                pki.ensure_ledger(a,'cmtc-a','a'*64)
                path=pki.PREFIX+'secrets/'+pki.SECRET
                if kind=='replacement':
                    a.objects[path]['metadata']['uid']='replacement'
                elif kind=='missing':
                    del a.objects[path]
                with self.assertRaises(pki.Refusal):
                    pki.ensure_ledger(a,'cmtc-a',('b' if kind=='root' else 'a')*64)
    def test_public_output_strict_and_no_implicit_ack(self):
        with pki.Root(self.temp()) as r:
            o=self.csr('cmtc-a',r.pin)
            log={'component':'lab-cluster-ca','msg':'acknowledged','attempt':1}
            raw=(json.dumps(log)+'\n'+json.dumps(o)+'\n').encode()
            self.assertEqual(pki.public_result(raw,'cmtc-a','secret-uid',r.pin),o)
            for raw in [b'',(json.dumps(o)+'\n'+json.dumps(o)).encode(),json.dumps(dict(o,**{'tls.key':'NO'})).encode(),b'{"a":1,"a":2}']:
                with self.assertRaises((pki.Refusal,ValueError)):
                    pki.public_result(raw,'cmtc-a','secret-uid',r.pin)
    def test_approval_persist_uid_before_completion_and_idempotent_recovery(self):
        a=Fake()
        with pki.Root(self.temp()) as r:
            ledger=pki.ensure_ledger(a,'cmtc-a',r.pin)
            request=self.csr('cmtc-a',r.pin)
            request['secretUID']=ledger['data']['secretUID']
            approval=pki.approval_for(a,ledger,request,r)
            self.assertEqual(ledger['data']['approvalUID'],approval['metadata']['uid'])
            old=copy.deepcopy(approval)
            request['status']='ready'
            request['resourceVersion']='1000'
            self.assertEqual(pki.approval_for(a,ledger,request,r),old)
            self.assertTrue(approval['immutable'])
            self.assertNotIn('tls.key',pki.canon(approval))
            a.objects[pki.PREFIX+'configmaps/'+pki.APPROVAL]['metadata']['uid']='changed'
            with self.assertRaises(pki.Refusal):
                pki.approval_for(a,ledger,request,r)
    def test_cleanup_uid_and_rv_preconditions_never_deletes_replacement(self):
        a=Fake()
        path=pki.PREFIX+'configmaps'
        o=a.request('POST',path,{'metadata':{'name':'temporary','labels':pki.labels('cmtc-a','test')}})
        with self.assertRaises(pki.Refusal):
            pki.delete_owned(a,path,'temporary','cmtc-a','test','old-uid')
        self.assertIn(path+'/temporary',a.objects)
        pki.delete_owned(a,path,'temporary','cmtc-a','test',o['metadata']['uid'])
        delete=[x for x in a.calls if x[0]=='DELETE'][0]
        self.assertEqual(delete[2]['preconditions'],{'uid':o['metadata']['uid'],'resourceVersion':o['metadata']['resourceVersion']})
    def test_full_secret_proxy_calls_rejected_before_connection(self):
        proxy=pki.Proxy('/unused','kind-cmtc-a')
        for method,path,body in [('GET',pki.PREFIX+'secrets/'+pki.SECRET,None),
                ('GET',pki.PREFIX+'secrets',None),('PUT',pki.PREFIX+'secrets/'+pki.SECRET,{}),
                ('POST',pki.PREFIX+'secrets',{'type':'Opaque','data':{'tls.key':'NO'}})]:
            with self.subTest(method=method,path=path),self.assertRaises(pki.Refusal):
                proxy.request(method,path,body)

    def test_root_path_replacement_refuses_signing(self):
        directory=self.temp()
        with pki.Root(directory) as r:
            os.rename(Path(directory,'current'),Path(directory,'held-old'))
            Path(directory,'current').mkdir(mode=0o700)
            with self.assertRaisesRegex(pki.Refusal,'replaced'):
                r.sign(self.csr('cmtc-a',r.pin))
    def test_public_certificate_request_signer_exact_source_and_lineage(self):
        with pki.Root(self.temp()) as root:
            parent_key=ec.generate_private_key(ec.SECP256R1())
            csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME,'cmtc-a SPIRE cluster CA')])).sign(parent_key,hashes.SHA256())
            request=self.csr('cmtc-a',root.pin)
            request.update(clusterIssuerCSR=csr.public_bytes(serialization.Encoding.PEM).decode(),
                           csrSHA256=pki.digest(csr.public_bytes(serialization.Encoding.DER)))
            parent_chain=root.sign(request)
            parent=x509.load_pem_x509_certificates(parent_chain.encode())[0]
            key=ec.generate_private_key(ec.SECP256R1())
            subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SPIRE signing CA')])
            sans=x509.SubjectAlternativeName([x509.UniformResourceIdentifier('spiffe://cmtc-a.mesh.example')])
            signing_csr=x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(sans,False).sign(key,hashes.SHA256())
            now=dt.datetime.now(dt.timezone.utc)
            signer=(x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(parent.not_valid_before_utc).not_valid_after(now+dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
                .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
                .add_extension(sans,False).sign(parent_key,hashes.SHA256()))
            path='/apis/cert-manager.io/v1/namespaces/cmtc-system/certificaterequests/spire-ca-1'
            a=Fake()
            issuer={'name':'cmtc-spire-issuer','kind':'ClusterIssuer','group':'cert-manager.io'}
            a.objects[path]={'metadata':{'uid':'request-uid','resourceVersion':'12'},
                'spec':{'username':'system:serviceaccount:cmtc-system:spire-server','issuerRef':issuer,
                        'request':base64.b64encode(signing_csr.public_bytes(serialization.Encoding.PEM)).decode()},
                'status':{'conditions':[{'type':'Ready','status':'True'},{'type':'Approved','status':'True'}],
                          'certificate':base64.b64encode(signer.public_bytes(serialization.Encoding.PEM)+parent_chain.encode()).decode()}}
            def derive(**extra):
                opts={'request_uid':'request-uid','username':'system:serviceaccount:cmtc-system:spire-server',
                      'issuer_ref':issuer,'domain':'cmtc-a.mesh.example','approved_parent_chain':parent_chain}
                opts.update(extra)
                return pki.derive_spire_candidate(a,'cmtc-system','spire-ca-1',**opts)
            candidate=derive()
            self.assertFalse(candidate['qualified'])
            # Compatibility also preserves an explicitly constrained pathLen0 signer.
            zero_builder=(x509.CertificateBuilder().subject_name(signer.subject).issuer_name(signer.issuer)
                .public_key(signer.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(signer.not_valid_before_utc).not_valid_after(signer.not_valid_after_utc))
            for extension in signer.extensions:
                value=x509.BasicConstraints(ca=True,path_length=0) if isinstance(extension.value,x509.BasicConstraints) else extension.value
                zero_builder=zero_builder.add_extension(value,extension.critical)
            zero=zero_builder.sign(parent_key,hashes.SHA256())
            actual_status=a.objects[path]['status']['certificate']
            a.objects[path]['status']['certificate']=base64.b64encode(zero.public_bytes(serialization.Encoding.PEM)+parent_chain.encode()).decode()
            self.assertFalse(derive()['qualified'])
            a.objects[path]['status']['certificate']=actual_status
            self.assertIn('running SPIRE',candidate['missingGate'])
            self.assertEqual(candidate['directIssuerSHA256'],pki.digest(signer.public_bytes(serialization.Encoding.DER)))
            for override in [{'request_uid':'replaced'},{'username':'other'},{'domain':'cmtc-b.mesh.example'},
                             {'issuer_ref':dict(issuer,name='other')}]:
                with self.subTest(override=override),self.assertRaises(pki.Refusal):
                    derive(**override)
            leaf_key=ec.generate_private_key(ec.SECP256R1())
            identity='spiffe://cmtc-a.mesh.example/ns/orders/sa/api'
            def make_leaf(issuer,signing_key):
                return (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(issuer.subject)
                    .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(signer.not_valid_before_utc).not_valid_after(now+dt.timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                    .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]),False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),False)
                    .sign(signing_key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
            self.assertTrue(pki.verify_spire_direct_leaf(candidate,make_leaf(signer,key),identity))
            delegated_key=ec.generate_private_key(ec.SECP256R1())
            delegated=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'child')]))
                .issuer_name(signer.subject).public_key(delegated_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(signer.not_valid_before_utc).not_valid_after(now+dt.timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(key,hashes.SHA256()))
            for wrong_issuer,signing_key in [(parent,parent_key),(root.cert,serialization.load_pem_private_key(
                    Path(root.path,'current/key.pem').read_bytes(),None)),(delegated,delegated_key)]:
                with self.subTest(wrongSigner=wrong_issuer.subject),self.assertRaises(pki.Refusal):
                    pki.verify_spire_direct_leaf(candidate,make_leaf(wrong_issuer,signing_key),identity)
            saved=a.objects[path]['status']['certificate']
            for wrong in [parent,root.cert]:
                a.objects[path]['status']['certificate']=base64.b64encode(wrong.public_bytes(serialization.Encoding.PEM)).decode()
                with self.assertRaises((pki.Refusal,x509.ExtensionNotFound)):
                    derive()
            a.objects[path]['status']['certificate']=saved
            original=a.get
            calls=0
            def changed(path,metadata=False):
                nonlocal calls
                obj=original(path,metadata)
                calls+=1
                if calls==2:
                    obj['metadata']['resourceVersion']='13'
                return obj
            a.get=changed
            with self.assertRaisesRegex(pki.Refusal,'changed during'):
                derive()
    def test_unknown_temporary_create_outcome_is_recorded_not_adopted(self):
        a=Fake()
        a.fail=lambda *_: (_ for _ in ()).throw(pki.APIError(500,'ambiguous'))
        op=pki.Orchestrator(a,'cmtc-a',None,'image','config','revision','manifest')
        with self.assertRaises(pki.APIError):
            op.create(pki.PREFIX+'serviceaccounts',{'metadata':{'name':'ours'}},'init-service-account')
        leftovers=op.cleanup()
        self.assertEqual(leftovers[0]['name'],'ours')
        self.assertIn('unknown',leftovers[0]['error'])
        self.assertFalse(any(x[0]=='DELETE' for x in a.calls))

    def test_worker_manifest_pin_is_exact_and_uid_replacement_refuses(self):
        a=Fake()
        a.objects['/api/v1/nodes/cmtc-a-worker']={'metadata':{'uid':'worker-uid','resourceVersion':'1'}}
        op=pki.Orchestrator(a,'cmtc-a',None,'image','sha256:config','revision','sha256:manifest',
                            {'cmtc-a-worker':'worker-uid','cmtc-a-control-plane':'control-uid'})
        pod={'spec':{'nodeName':'cmtc-a-worker'},'status':{'containerStatuses':[{'imageID':'repo@sha256:manifest'}]}}
        cri={'status':{'id':'sha256:config'},'info':{'imageSpec':{'config':{'Labels':{'org.opencontainers.image.revision':'revision'}}}}}
        with patch.object(pki,'run',return_value=json.dumps(cri).encode()) as command:
            op.verify_image(pod)
            self.assertIn('cmtc-a-worker',command.call_args.args[0])
        wrong=copy.deepcopy(pod)
        wrong['spec']['nodeName']='cmtc-a-control-plane'
        with self.assertRaisesRegex(pki.Refusal,'exact manifest-pinned'):
            op.verify_image(wrong)
        a.objects['/api/v1/nodes/cmtc-a-worker']['metadata']['uid']='new-worker'
        with self.assertRaisesRegex(pki.Refusal,'UID replaced'):
            op.verify_image(pod)
    def test_failed_job_retains_structured_retry_logs_before_error(self):
        a=Fake()
        a.objects['/api/v1/nodes/cmtc-a-worker']={'metadata':{'uid':'worker-uid','resourceVersion':'1'}}
        class Root:
            pin='a'*64
        op=pki.Orchestrator(a,'cmtc-a',Root(),'image','config','revision','manifest',{'cmtc-a-worker':'worker-uid'})
        op.sa='owned-sa'
        name='cmtc-ca-init-'+op.runid
        a.objects[pki.PREFIX+'pods?labelSelector=job-name%3D'+name]={'items':[{
            'metadata':{'name':'failed-pod','uid':'pod-uid','resourceVersion':'5',
                        'ownerReferences':[{'uid':'uid-1'}]},'spec':{'nodeName':'cmtc-a-worker'},
            'status':{'phase':'Failed','containerStatuses':[{'imageID':'manifest'}]}}]}
        op.verify_image=lambda _:None
        retry={'component':'lab-cluster-ca','msg':'Cluster CA operation failed','stage':'read-secret',
               'attempt':2,'elapsed':'50ms','deadline':'2026-10-24T12:00:00Z','backoff':'100ms','error':'conflict'}
        op.log=lambda _: (json.dumps(retry)+'\noperation failed\n').encode()
        with self.assertRaisesRegex(pki.Refusal,'diagnostics retained'):
            op.job('cluster-ca-init','secret-uid')
        self.assertEqual(op.public_logs[0]['entries'][0],retry)
        self.assertEqual(op.public_logs[0]['phase'],'Failed')
        created=[x[2] for x in a.calls if x[0]=='POST'][0]
        self.assertEqual(created['spec']['template']['spec']['nodeName'],'cmtc-a-worker')
    def test_log_private_markers_never_enter_evidence(self):
        for raw in [b'-----BEGIN PRIVATE KEY-----',b'-----BEGIN EC PRIVATE KEY-----',b'{"tls.key":"base64"}']:
            with self.subTest(raw=raw),self.assertRaisesRegex(pki.Refusal,'content withheld'):
                pki.sanitize_public_logs(raw)
        self.assertEqual(pki.sanitize_public_logs(b'plain public error'),[{'diagnostic':'plain public error'}])
    def test_cleanup_waits_for_uid_absence_and_refuses_replacement(self):
        for kind in ['delayed','timeout','replacement']:
            with self.subTest(kind=kind):
                a=Fake()
                collection=pki.PREFIX+'configmaps'
                o=a.request('POST',collection,{'metadata':{'name':'tmp','labels':pki.labels('cmtc-a','temporary')}})
                path=collection+'/tmp'
                old_request=a.request
                old_get=a.get
                calls=0
                def request(method,path,body=None,metadata=False):
                    if method=='DELETE':
                        self.assertEqual(body['preconditions']['uid'],o['metadata']['uid'])
                        a.objects[path]['metadata']['deletionTimestamp']='now'
                        return {'status':'Success'}
                    return old_request(method,path,body,metadata)
                def get(path,metadata=False):
                    nonlocal calls
                    calls+=1
                    if calls>=3 and kind=='delayed':
                        a.objects.pop(path,None)
                    if calls>=2 and kind=='replacement':
                        a.objects[path]['metadata']['uid']='replacement'
                    return old_get(path,metadata)
                a.request=request
                a.get=get
                if kind=='delayed':
                    pki.delete_owned(a,collection,'tmp','cmtc-a','temporary',o['metadata']['uid'],timeout=.1,poll=.001)
                    self.assertGreaterEqual(calls,3)
                else:
                    with self.assertRaisesRegex(pki.Refusal,'replacement' if kind=='replacement' else 'still present'):
                        pki.delete_owned(a,collection,'tmp','cmtc-a','temporary',o['metadata']['uid'],timeout=.01,poll=.001)
                    self.assertIn(path,a.objects)

    def test_secret_transport_guard_covers_queries_and_encoded_paths(self):
        proxy=pki.Proxy('/unused','kind-cmtc-a')
        for path in [pki.PREFIX+'secrets?limit=1',pki.PREFIX+'secrets/'+pki.SECRET+'?resourceVersion=0',
                     pki.PREFIX+'%73ecrets/'+pki.SECRET,pki.PREFIX+'secrets/../secrets/'+pki.SECRET,
                     'http://localhost'+pki.PREFIX+'secrets/'+pki.SECRET]:
            with self.subTest(path=path),self.assertRaises(pki.Refusal):
                proxy.request('GET',path)

if __name__=='__main__':
    unittest.main()
