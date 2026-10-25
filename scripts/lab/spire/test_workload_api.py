import copy, hashlib, unittest, uuid
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import workload_api as w

def U(n):return str(uuid.UUID(int=n))
def cert(name='cmtc-a-worker',expired=False,server=True,ca_key=None,ca_cert=None):
    now=datetime.now(timezone.utc)
    if ca_key is None:
        ca_key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name+'-ca')])
        ca_cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=3)).not_valid_after(now+timedelta(days=3)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,True,False,False,False),True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False).sign(ca_key,hashes.SHA256()))
    leaf_key=ec.generate_private_key(ec.SECP256R1())
    value=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])).issuer_name(ca_cert.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1) if expired else now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),False).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),True).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False).sign(ca_key,hashes.SHA256()))
    pem=value.public_bytes(serialization.Encoding.PEM).decode()+ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem,value.fingerprint(hashes.SHA256()).hex(),ca_cert.fingerprint(hashes.SHA256()).hex(),ca_key,ca_cert,leaf_key

def snapshot():
    cluster='cmtc-a';domain=w.r.CLUSTERS[cluster];ds=w.r.agent_daemon_set(cluster,w.r.require_images(None))
    ds['metadata'].update(uid=U(1),resourceVersion='7')
    pem,pin,capin,*_=cert();node={'name':'cmtc-a-worker','uid':U(2),'ip':'172.18.0.2','kubeletCertificatePEM':pem,'kubeletCertificateSHA256':pin,'kubeletCASHA256':capin}
    def pod(n,name,ns,sa):return {'apiVersion':'v1','kind':'Pod','metadata':{'uid':U(n),'name':name,'namespace':ns,'resourceVersion':'9'},'spec':{'nodeName':node['name'],'serviceAccountName':sa,'containers':[{'name':'app','image':'fixture'}]},'status':{'phase':'Running','containerStatuses':[{'name':'app','ready':True,'state':{'running':{'startedAt':'2026-10-24T00:00:00Z'}}}]}}
    return {'schema':'cmtc-workload-api-plan-input/v1','cluster':cluster,'domain':domain,'clusterUID':U(3),'nodes':[node],'expectedNodes':[node['name']], 'approvedAgentImage':'localhost/cmtc-spire-agent@sha256:'+'a'*64,'approvedAgentSource':'28f6b8d84ade21c6accb32ba9689a3bdf64877ec','agentDaemonSet':ds,'agentConfigMap':{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'spire-agent','namespace':w.r.NAMESPACE,'uid':U(4)},'data':{'agent.conf':w.r.agent_config(cluster,domain)}},'delegateNamespace':'cmtc-workload-api-lab','delegateServiceAccount':'node-probe','delegates':[{'pod':pod(5,'probe','cmtc-workload-api-lab','node-probe'),'namespaceUID':U(6)}],'workloads':[{'pod':pod(7,'client','cmtc-workload-api-lab','client'),'namespaceUID':U(6)}]}

class Tests(unittest.TestCase):
    def setUp(self):self.s=snapshot()
    def test_node_probe_has_explicit_host_pid_and_no_api_token_or_capabilities(self):
        pod=w.probe_pod('cmtc-a',self.s['nodes'][0],self.s['approvedAgentImage'])
        self.assertTrue(pod['spec']['hostPID'])
        self.assertEqual(pod['spec']['securityContext']['runAsUser'],1000)
        self.assertEqual(pod['spec']['securityContext']['runAsGroup'],0)
        self.assertEqual(pod['spec']['containers'][0]['workingDir'],'/')
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertEqual(pod['spec']['containers'][0]['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertFalse(pod['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])
        self.assertFalse(self.s['workloads'][0]['pod']['spec'].get('hostPID',False))

    def test_exact_optin_preserves_default(self):
        before=copy.deepcopy(self.s);p=w.make_plan(self.s)
        self.assertEqual(before,self.s);self.assertFalse(p['qualified']);self.assertFalse(p['protectionAvailable'])
        text=p['configMaps'][0]['data']['agent.conf'];self.assertIn('skip_kubelet_verification = false',text);self.assertIn('use_new_container_locator = true',text)
        self.assertIn('authorized_delegates = ["spiffe://cmtc-a.mesh.example/ztunnel-proxy"]',text);self.assertNotIn('cilium-operator',text)
        ps=p['newTemplate']['spec'];self.assertEqual(ps['containers'][0]['image'],self.s['approvedAgentImage']);self.assertEqual(ps['securityContext'],self.s['agentDaemonSet']['spec']['template']['spec']['securityContext'])
        self.assertEqual(p['daemonSetPatch'][:2],[{'op':'test','path':'/metadata/uid','value':U(1)},{'op':'test','path':'/metadata/resourceVersion','value':'7'}])
        self.assertEqual(ps['hostAliases'],[{'ip':'172.18.0.2','hostnames':['cmtc-a-worker']}])
        self.assertIn('node_name_env = \"CMTC_NODE_NAME\"',text)
        for entry in p['registrations']:
            self.assertEqual(len(entry['selectors']),4);self.assertIn('k8s:pod-uid:'+entry['podUID'],entry['selectors']);self.assertIn('k8s:node-name:cmtc-a-worker',entry['selectors'])
    def test_wrong_public_certificate_pin(self):
        self.s['nodes'][0]['kubeletCertificateSHA256']='0'*64
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_wrong_node_dns_san(self):
        self.s['nodes'][0]['name']='cmtc-a-other';self.s['expectedNodes']=['cmtc-a-other']
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_expired_certificate(self):
        pem,pin,capin,*_=cert(expired=True);self.s['nodes'][0].update(kubeletCertificatePEM=pem,kubeletCertificateSHA256=pin,kubeletCASHA256=capin)
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_wrong_certificate_role(self):
        pem,pin,capin,*_=cert(server=False);self.s['nodes'][0].update(kubeletCertificatePEM=pem,kubeletCertificateSHA256=pin,kubeletCASHA256=capin)
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_exact_node_set(self):
        self.s['expectedNodes']=['foreign']
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_deleting_or_unready_pod(self):
        for mutate in [lambda s:s['workloads'][0]['pod']['metadata'].update(deletionTimestamp='now'), lambda s:s['workloads'][0]['pod']['status']['containerStatuses'][0].update(ready=False)]:
            s=copy.deepcopy(self.s);mutate(s)
            with self.assertRaises(w.Refusal):w.make_plan(s)
    def test_wrong_pod_node(self):
        self.s['workloads'][0]['pod']['spec']['nodeName']='foreign'
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_delegate_sa_mismatch(self):
        self.s['delegates'][0]['pod']['spec']['serviceAccountName']='foreign'
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_no_implicit_stock_agent_qualification(self):
        self.s['approvedAgentImage']=w.r.AGENT_IMAGE
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_no_default_path_host_mount(self):
        p=w.make_plan(self.s);vols=p['newTemplate']['spec']['volumes'];host=next(x['hostPath'] for x in vols if 'hostPath' in x)
        self.assertEqual(host,{'path':'/run/cmtc-spire/cmtc-a','type':'DirectoryOrCreate'})
        self.assertNotIn('/var/lib/kubelet',str(p));self.assertNotIn('Secret',str(p))
    def test_foreign_daemonset_refused(self):
        self.s['agentDaemonSet']['metadata']['labels']['security.cmtc.io/pki-owner']='foreign'
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_old_uid_is_not_reused(self):
        first=w.make_plan(self.s)['registrations'][1];self.s['workloads'][0]['pod']['metadata']['uid']=U(9);second=w.make_plan(self.s)['registrations'][1]
        self.assertNotEqual(first['entryID'],second['entryID']);self.assertEqual(first['spiffeID'],second['spiffeID']);self.assertNotEqual(first['selectors'],second['selectors'])
    def test_no_datapath_or_server_mutation(self):
        p=w.make_plan(self.s);self.assertNotIn('StatefulSet',str(p));self.assertNotIn('enable-ztunnel',str(p));self.assertEqual(len(p['configMaps']),2)
    def test_strict_entry_and_duplicate_selector(self):
        want=w.make_plan(self.s)['registrations'][1]
        def sid(s):d,path=s[9:].split('/',1);return {'trust_domain':d,'path':'/'+path}
        got={'id':want['entryID'],'spiffe_id':sid(want['spiffeID']),'parent_id':sid(want['parentID']),'selectors':[{'type':x.split(':',1)[0],'value':x.split(':',1)[1]} for x in want['selectors']],'x509_svid_ttl':120}
        w.compare_entry(got,want);got['selectors'].append(got['selectors'][0])
        with self.assertRaises(w.Refusal):w.compare_entry(got,want)
    def test_wrong_ca_pin(self):
        self.s['nodes'][0]['kubeletCASHA256']='0'*64
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_other_ca_cannot_replace_pinned_ca(self):
        old=self.s['nodes'][0]['kubeletCASHA256'];pem,pin,capin,*_=cert()
        self.assertNotEqual(old,capin);self.s['nodes'][0].update(kubeletCertificatePEM=pem,kubeletCertificateSHA256=pin)
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_valid_leaf_renewal_preserves_exact_ca_anchor(self):
        pem,pin,capin,key,ca,_=cert();self.s['nodes'][0].update(kubeletCertificatePEM=pem,kubeletCertificateSHA256=pin,kubeletCASHA256=capin)
        first=w.make_plan(self.s)['configMaps'][1]['data']
        pem2,pin2,capin2,*_=cert(ca_key=key,ca_cert=ca);self.assertNotEqual(pin,pin2);self.assertEqual(capin,capin2)
        self.s['nodes'][0].update(kubeletCertificatePEM=pem2,kubeletCertificateSHA256=pin2)
        self.assertEqual(first,w.make_plan(self.s)['configMaps'][1]['data'])
    def test_duplicate_node_alias_not_silently_replaced(self):
        self.s['agentDaemonSet']['spec']['template']['spec']['hostAliases']=[{'ip':'127.0.0.1','hostnames':['cmtc-a-worker']}]
        with self.assertRaises(w.Refusal):w.make_plan(self.s)
    def test_actual_four_public_kind_chains(self):
        from pathlib import Path
        files=sorted((Path(__file__).parent/'testdata').glob('*-kubelet-public.pem'));self.assertEqual(len(files),4)
        for p in files:
            name=p.name.removesuffix('-kubelet-public.pem');pem=p.read_text();leaf,ca=x509.load_pem_x509_certificates(pem.encode())
            record={'name':name,'kubeletCertificatePEM':pem,'kubeletCertificateSHA256':leaf.fingerprint(hashes.SHA256()).hex(),'kubeletCASHA256':ca.fingerprint(hashes.SHA256()).hex()}
            anchor=w.public_kubelet_certificate(record,datetime.now(timezone.utc));self.assertEqual(anchor,ca.public_bytes(serialization.Encoding.PEM).decode());self.assertNotEqual(leaf.issuer,leaf.subject)
if __name__=='__main__':unittest.main()

