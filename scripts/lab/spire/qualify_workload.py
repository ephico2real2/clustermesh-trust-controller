"""Real native credential qualification primitives for the primary lab runner.

No function runs on import. All commands have explicit context and wall time.
The caller creates/owns the probe Pod and exact registrations separately.
"""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from workload_api import Refusal, require, compare_entry

BINARY='/usr/local/bin/spire-workload-check'

def bounded(argv, *, timeout=40, input=None, success=True):
    result=subprocess.run(argv,input=input,text=True,capture_output=True,timeout=timeout)
    # These subcommands only emit public data, but refuse malformed/private output
    # rather than copying any accidentally leaked key into an exception/evidence.
    require(len(result.stdout)<=131072 and len(result.stderr)<=65536,'bounded public output exceeded')
    require('PRIVATE KEY' not in result.stdout and 'PRIVATE KEY' not in result.stderr,'unsafe diagnostic output suppressed')
    if success and result.returncode:
        raise Refusal(f'public command failed ({result.returncode}): {result.stderr[:4096]}')
    return result

def server_cli(api, args):
    result=bounded(api.argv+['exec','-n','cilium-spire','spire-server-0','-c','register-agent-node','--',
        '/bin/timeout','-s','KILL','12','/spire-cli/opt/spire/bin/spire-server',*args],timeout=20)
    return json.loads(result.stdout)

def show_exact(api, wanted):
    result=server_cli(api,wanted['showArguments'])
    require(isinstance(result,dict) and len(result.get('entries',[]))==1,'one exact registration required')
    compare_entry(result['entries'][0],wanted)
    return result['entries'][0]

def same_running_pod(before,after):
    def bound(p):
        m=p['metadata'];s=p['spec'];st=p.get('status',{})
        require(not m.get('deletionTimestamp') and st.get('phase')=='Running','Pod not live')
        statuses=st.get('containerStatuses',[])
        require(statuses and all(c.get('ready') and c.get('state',{}).get('running') and c.get('containerID') for c in statuses),'Pod containers not ready')
        return (m['uid'],s,[(c['name'],c['containerID'],c.get('imageID'),c.get('restartCount'),c['state']['running']) for c in statuses])
    require(bound(before)==bound(after),'Pod or container incarnation changed during credential observation')

def verify_public_result(raw, *, wanted, current_issuer_proof):
    require(len(raw)<=65536 and 'PRIVATE KEY' not in raw,'public-only bounded result required')
    result=json.loads(raw)
    require(set(result)=={'schemaVersion','identity','podUID','publicCertificateChain','privateKeyExported','workloadAttestationPath','packetProtectionTested'},'unknown credential result fields')
    require(result['schemaVersion']==1 and result['identity']==wanted['spiffeID'] and result['podUID']==wanted['podUID'] and result['privateKeyExported'] is False and result['packetProtectionTested'] is False,'credential result binding mismatch')
    require(result['workloadAttestationPath']=='native-ztunnel-CRI-PodUID-PID-delegated-SPIRE','wrong credential path')
    chain=result['publicCertificateChain'];require(1<=len(chain)<=4 and all(isinstance(c,str) and len(c)<32768 and c.count('BEGIN CERTIFICATE')==1 for c in chain),'bounded public chain required')
    issuer=x509.load_pem_x509_certificate(current_issuer_proof['directIssuerPEM'].encode())
    require(hashlib.sha256(issuer.public_bytes(serialization.Encoding.DER)).hexdigest()==current_issuer_proof['directIssuerSHA256'],'independent signer proof digest mismatch')
    leaf=x509.load_pem_x509_certificate(chain[0].encode());leaf.verify_directly_issued_by(issuer)
    require(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)==[x509.UniformResourceIdentifier(wanted['spiffeID'])],'actual certificate SAN differs')
    try:require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,'CA certificate is not a workload SVID')
    except x509.ExtensionNotFound:pass
    require(leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature,'workload cannot sign')
    allowed={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER,ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
    require(not any(e.critical and e.oid not in allowed for e in leaf.extensions),'unsupported critical leaf extension')
    eku=leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    require(ExtendedKeyUsageOID.CLIENT_AUTH in eku and ExtendedKeyUsageOID.SERVER_AUTH in eku,'missing workload TLS roles')
    now=datetime.now(timezone.utc)
    require(issuer.not_valid_before_utc<=leaf.not_valid_before_utc<=now<leaf.not_valid_after_utc<=issuer.not_valid_after_utc,'invalid current workload validity')
    known=[issuer]
    if current_issuer_proof.get('parentPEM'):known.append(x509.load_pem_x509_certificate(current_issuer_proof['parentPEM'].encode()))
    for index,pem in enumerate(chain[1:]):
        actual=x509.load_pem_x509_certificate(pem.encode())
        raw=actual.public_bytes(serialization.Encoding.DER)
        if index<len(known):
            require(raw==known[index].public_bytes(serialization.Encoding.DER),'unexpected returned signer/parent')
        else:
            require(index==len(known) and hashlib.sha256(raw).hexdigest()==current_issuer_proof['rootSHA256'],'unexpected additional chain authority')
    return {'workloadSVIDVerified':True,'identity':result['identity'],'podUID':result['podUID'],
        'leafSHA256':hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
        'directIssuerSHA256':current_issuer_proof['directIssuerSHA256'],'privateKeyExported':False,'packetProtectionTested':False}

def native_fetch(api, *, probe_pod, wanted, issuer_proof, expected_probe_image):
    """Exec inside the trusted node probe; no application socket/key mount.

    CRI and delegated API privileges make this Pod part of the node TCB.
    Source/container image must also be independently CRI-qualified by caller.
    """
    ns,name=probe_pod['metadata']['namespace'],probe_pod['metadata']['name']
    require(len(probe_pod['spec']['containers'])==1 and probe_pod['spec']['containers'][0]['image']==expected_probe_image,'unexpected probe image')
    ppath=f'/api/v1/namespaces/{ns}/pods/{name}'
    tpath=f'/api/v1/namespaces/{wanted["namespace"]}/pods/{wanted["podName"]}'
    before_probe=api.get(ppath);same_running_pod(probe_pod,before_probe)
    before_target=api.get(tpath);require(before_target['metadata']['uid']==wanted['podUID'],'target UID changed')
    require(before_target['spec']['nodeName']==before_probe['spec']['nodeName'],'remote PID must never be delegated locally')
    show_exact(api,wanted)
    result=bounded(api.argv+['exec','-n',ns,name,'-c','probe','--',BINARY,'fetch',wanted['spiffeID'],wanted['podUID'],wanted['podName']],timeout=40)
    same_running_pod(before_target,api.get(tpath));same_running_pod(before_probe,api.get(ppath));show_exact(api,wanted)
    return verify_public_result(result.stdout,wanted=wanted,current_issuer_proof=issuer_proof)

def expect_native_denied(api, *, probe_pod, identity, pod_uid, pod_name, diagnostic_substring):
    ns,name=probe_pod['metadata']['namespace'],probe_pod['metadata']['name']
    before=api.get(f'/api/v1/namespaces/{ns}/pods/{name}');same_running_pod(probe_pod,before)
    result=bounded(api.argv+['exec','-n',ns,name,'-c','probe','--',BINARY,'fetch',identity,pod_uid,pod_name],timeout=40,success=False)
    require(result.returncode!=0 and diagnostic_substring in result.stderr,'expected explicit native credential denial absent')
    require(not result.stdout.strip(),'negative credential case emitted successful payload')
    same_running_pod(before,api.get(f'/api/v1/namespaces/{ns}/pods/{name}'))
    return {'credentialDenied':True,'exitCode':result.returncode,'publicDiagnostic':result.stderr[:4096],'packetProtectionTested':False}
