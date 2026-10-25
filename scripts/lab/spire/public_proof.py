#!/usr/bin/env python3
"""Public active-SPIRE-key qualification. Never reads a populated Secret or emits a key.

Run from the repository using its reviewed scripts/lab/pki/pki.py transport. This
is an administrator challenge, not workload attestation, federation or protection.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import secrets
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

MAX = 65536
DOMAINS = {'cmtc-a':'cmtc-a.mesh.example','cmtc-b':'cmtc-b.mesh.example'}
SERVER_IMAGE = 'ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384'
SIDECAR_IMAGE = 'docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e'
class Refusal(RuntimeError): pass

def strict_json(raw):
    if len(raw)>MAX: raise Refusal('JSON size bound')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d: raise Refusal('duplicate JSON key')
            d[k]=v
        return d
    try: return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite JSON')))
    except (ValueError,RecursionError) as e: raise Refusal('invalid JSON') from e

def sha(raw): return hashlib.sha256(raw).hexdigest()
def der(cert): return cert.public_bytes(serialization.Encoding.DER)
def pem(cert): return cert.public_bytes(serialization.Encoding.PEM).decode()
def spki(cert): return cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
def live_meta(obj):
    m=obj.get('metadata',{})
    if not m.get('uid') or not m.get('resourceVersion') or m.get('deletionTimestamp'): raise Refusal('object not live UID/RV bound')
    return m

def certs(raw):
    if isinstance(raw,str): raw=raw.encode()
    if len(raw)>32768 or not raw: raise Refusal('public chain size bound')
    blocks=re.findall(rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n',raw)
    if not blocks or b''.join(blocks)!=raw: raise Refusal('noncertificate or private material in public proof')
    try:
        out=[x509.load_pem_x509_certificate(b) for b in blocks]
    except ValueError as e: raise Refusal('bad certificate PEM') from e
    if len(out)>4 or any(c.public_bytes(serialization.Encoding.PEM)!=b for c,b in zip(out,blocks)): raise Refusal('noncanonical certificate chain')
    return out

def issued(child,parent):
    try: child.verify_directly_issued_by(parent)
    except (ValueError,TypeError,InvalidSignature) as e: raise Refusal('exact issuer signature verification failed') from e

def ext(cert, cls):
    try: return cert.extensions.get_extension_for_class(cls)
    except x509.ExtensionNotFound as e: raise Refusal('required certificate extension absent') from e

def current(cert,now):
    if not cert.not_valid_before_utc<=now<cert.not_valid_after_utc: raise Refusal('certificate not currently valid')

def ca(cert,depth,now,san=False):
    current(cert,now)
    allowed={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    if san: allowed.add(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if any(e.oid not in allowed for e in cert.extensions): raise Refusal('unsupported CA extension')
    bc=ext(cert,x509.BasicConstraints);ku=ext(cert,x509.KeyUsage)
    allowed_depth=(0,None) if depth=='signer' else (depth,)
    if not bc.critical or not bc.value.ca or bc.value.path_length not in allowed_depth or not ku.critical or not ku.value.key_cert_sign or not ku.value.crl_sign:
        raise Refusal('CA constraints do not match approved lineage')

def approved_parent(obj,*,uid,cluster,root_pin,now):
    m=live_meta(obj)
    expected={'security.cmtc.io/pki-owner':'cmtc-lab-pki','security.cmtc.io/pki-cluster':cluster,'security.cmtc.io/pki-role':'spire-cluster-ca-approval'}
    if m['uid']!=uid or obj.get('kind')!='ConfigMap' or obj.get('immutable') is not True or set(obj.get('data',{}))!={'approval.json'} or m.get('ownerReferences') or any(m.get('labels',{}).get(k)!=v for k,v in expected.items()):
        raise Refusal('public approval ownership/immutability mismatch')
    a=strict_json(obj['data']['approval.json'])
    expected_keys={'schemaVersion','cluster','secretUID','secretResourceVersion','csrSHA256','rootSHA256','certificatePEM'}
    if set(a)!=expected_keys or a['schemaVersion']!=1 or a['cluster']!=cluster or a['rootSHA256']!=root_pin or not a['secretUID'] or not a['secretResourceVersion'] or not re.fullmatch('[0-9a-f]{64}',a['csrSHA256']):
        raise Refusal('public approval pin mismatch')
    chain=certs(a['certificatePEM'])
    if len(chain)!=2: raise Refusal('approved parent/root chain must be exact')
    parent,root=chain
    if sha(der(root))!=root_pin: raise Refusal('wrong organizational root')
    ca(parent,1,now);ca(root,2,now);issued(root,root);issued(parent,root)
    if spki(parent)==spki(root) or parent.not_valid_before_utc<root.not_valid_before_utc or parent.not_valid_after_utc>root.not_valid_after_utc:
        raise Refusal('approved parent binding/validity invalid')
    return parent,root

def active(raw):
    obj=strict_json(raw);a=obj.get('active')
    if not isinstance(a,dict) or set(a)!={'authority_id','expires_at','upstream_authority_subject_key_id'}: raise Refusal('unexpected current-authority schema')
    if any(not isinstance(a[k],str) for k in a) or not re.fullmatch('[0-9a-f]{40,128}',a['authority_id']) or not re.fullmatch('[0-9a-f]{40,128}',a['upstream_authority_subject_key_id']) or not re.fullmatch('[0-9]{1,12}',a['expires_at']):
        raise Refusal('invalid current-authority identifiers')
    return a

def verify_challenge(raw,*,domain,nonce,parent,root,before,after,authority_before,authority_after):
    if not re.fullmatch('[0-9a-f]{64}',nonce) or before>after or (after-before).total_seconds()>45: raise Refusal('invalid challenge window/nonce')
    a=active(authority_before)
    if active(authority_after)!=a: raise Refusal('active authority changed during challenge')
    chain=certs(raw)
    if len(chain) not in (2,3,4): raise Refusal('missing direct SPIRE signer')
    leaf,signer=chain[:2]
    for got,want in zip(chain[2:],[parent,root]):
        if der(got)!=der(want): raise Refusal('unapproved chain suffix/order')
    ca(parent,1,after);ca(root,2,after);ca(signer,'signer',after,True)
    if len({spki(c) for c in (root,parent,signer,leaf)})!=4: raise Refusal('CA/leaf key role reuse')
    issued(root,root);issued(parent,root);issued(signer,parent);issued(leaf,signer)
    if list(ext(signer,x509.SubjectAlternativeName).value)!=[x509.UniformResourceIdentifier('spiffe://'+domain)]: raise Refusal('SPIRE signer domain mismatch')
    if not parent.not_valid_before_utc<=signer.not_valid_before_utc or signer.not_valid_after_utc>parent.not_valid_after_utc: raise Refusal('SPIRE signer validity outside approved parent')
    signer_ski=ext(signer,x509.SubjectKeyIdentifier).value.digest.hex()
    parent_ski=ext(parent,x509.SubjectKeyIdentifier).value.digest.hex()
    if a['authority_id']!=signer_ski or a['upstream_authority_subject_key_id']!=parent_ski or int(a['expires_at'])!=int(signer.not_valid_after_utc.timestamp()): raise Refusal('active API authority does not match verified public signer')
    if ext(signer,x509.AuthorityKeyIdentifier).value.key_identifier!=bytes.fromhex(parent_ski): raise Refusal('SPIRE authority-key binding mismatch')
    current(leaf,after)
    allowed_leaf={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER,ExtensionOID.SUBJECT_ALTERNATIVE_NAME}
    if any(e.critical and e.oid not in allowed_leaf for e in leaf.extensions): raise Refusal('unsupported critical leaf extension')
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: raise Refusal('challenge leaf is a CA')
    except x509.ExtensionNotFound: pass
    if not ext(leaf,x509.KeyUsage).value.digital_signature: raise Refusal('challenge signing usage absent')
    eku=ext(leaf,x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku or ExtendedKeyUsageOID.SERVER_AUTH not in eku: raise Refusal('challenge lacks client/server roles')
    uri='spiffe://'+domain+'/cmtc/issuer-proof/'+nonce
    if list(ext(leaf,x509.SubjectAlternativeName).value)!=[x509.UniformResourceIdentifier(uri)]: raise Refusal('challenge replay/domain/identity mismatch')
    if not signer.not_valid_before_utc<=leaf.not_valid_before_utc or leaf.not_valid_after_utc>signer.not_valid_after_utc: raise Refusal('challenge validity exceeds signer')
    if leaf.not_valid_before_utc<before-dt.timedelta(seconds=120) or leaf.not_valid_before_utc>after+dt.timedelta(seconds=2) or leaf.not_valid_after_utc>before+dt.timedelta(seconds=90): raise Refusal('challenge is stale or overlong')
    return {'schemaVersion':1,'source':'authenticated-kubernetes-exec-local-SPIRE-admin-API-nonce-mint',
        'qualifiedFor':'current direct signing key and approved public lineage only','workloadAttestation':False,'protected':False,
        'domain':domain,'challenge':uri,'challengeLeafSHA256':sha(der(leaf)),
        'directIssuerSHA256':sha(der(signer)),'directIssuerPEM':pem(signer),'parentPEM':pem(parent),'rootSHA256':sha(der(root)),
        'activeAuthority':a,'observedAt':after.isoformat(),'validUntil':signer.not_valid_after_utc.isoformat()}

# All CLI output that might contain a generated key is redirected INSIDE the pod.
# Only the public certificate file and public authority JSON reach stdout.
PROOF_SCRIPT = r'''set -euf
umask 077
work=$(mktemp -d /tmp/cmtc-proof.XXXXXX)
cleanup() { rm -f "$work/key.pem" "$work/svid.pem" "$work/bundle.pem" "$work/before.json" "$work/after.json"; rmdir "$work"; }
trap cleanup EXIT
trap 'exit 143' TERM HUP INT
bin=/spire-cli/opt/spire/bin/spire-server
sock=/tmp/spire-server/private/api.sock
timeout -s KILL 8 "$bin" localauthority x509 show -socketPath "$sock" -output json >"$work/before.json" 2>/dev/null || { echo 'authority-before failed' >&2; exit 20; }
timeout -s KILL 8 "$bin" x509 mint -socketPath "$sock" -spiffeID "$1" -ttl 30s -write "$work" >/dev/null 2>/dev/null || { echo 'mint-public-proof failed' >&2; exit 21; }
timeout -s KILL 8 "$bin" localauthority x509 show -socketPath "$sock" -output json >"$work/after.json" 2>/dev/null || { echo 'authority-after failed' >&2; exit 22; }
[ -f "$work/svid.pem" ] && [ ! -L "$work/svid.pem" ] && [ "$(wc -c <"$work/svid.pem")" -le 32768 ] || exit 23
[ "$(wc -c <"$work/before.json")" -le 4096 ] && [ "$(wc -c <"$work/after.json")" -le 4096 ] || exit 24
if grep -q 'PRIVATE KEY' "$work/svid.pem" "$work/before.json" "$work/after.json"; then exit 25; fi
printf 'CMTC_AUTHORITY_BEFORE\n'; cat "$work/before.json"; printf '\nCMTC_CHAIN\n'; cat "$work/svid.pem"; printf 'CMTC_AUTHORITY_AFTER\n'; cat "$work/after.json"; printf '\nCMTC_END\n'
'''

def split_output(raw):
    if len(raw)>MAX or b'PRIVATE KEY' in raw or b'private_key' in raw: raise Refusal('nonpublic or oversized proof response; content withheld')
    m=re.fullmatch(rb'CMTC_AUTHORITY_BEFORE\n(.*?)\nCMTC_CHAIN\n(.*?)CMTC_AUTHORITY_AFTER\n(.*?)\nCMTC_END\n',raw,re.S)
    if not m: raise Refusal('incomplete public proof envelope')
    return m[1],m[2],m[3]

def approved_server_image(value):
    """Validate an independent administrator pin; never discover it from a Pod.

    The caller must first verify the exact local image/source/config and imported
    per-node CRI manifests. Syntax validation is not that source verification.
    """
    pattern = (r"(?:localhost|[a-z0-9][a-z0-9.-]*)(?::[1-9][0-9]{0,4})?/"
               r"(?:[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*/)*"
               r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
               r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}")
    if not isinstance(value, str) or len(value) > 512 or not re.fullmatch(pattern, value):
        raise Refusal("explicit full registry/repository@sha256 server image required")
    registry = value.split("/", 1)[0]
    host, separator, port = registry.partition(":")
    if separator and int(port) > 65535:
        raise Refusal("invalid image registry port")
    labels = host.split(".")
    if host != "localhost" and (len(labels) < 2 or any(len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)):
        raise Refusal("canonical explicit image registry required")
    return value


def pod_identity(pod,expected_uid,*,server_image=SERVER_IMAGE):
    server_image=approved_server_image(server_image)
    m=live_meta(pod)
    spec=pod.get('spec',{});status=pod.get('status',{})
    if m['uid']!=expected_uid or m.get('name')!='spire-server-0' or spec.get('serviceAccountName')!='spire-server' or not spec.get('nodeName') or status.get('phase')!='Running': raise Refusal('SPIRE Pod identity mismatch')
    expected={'spire-server':server_image,'register-agent-node':SIDECAR_IMAGE}
    containers=spec.get('containers',[])
    if len(containers)!=2 or {c['name']:c.get('image') for c in containers}!=expected: raise Refusal('SPIRE Pod image/spec mismatch')
    statuses=status.get('containerStatuses',[])
    if len(statuses)!=2 or {s.get('name') for s in statuses}!=set(expected): raise Refusal('SPIRE container status mismatch')
    observed=[]
    for s in sorted(statuses,key=lambda s:s['name']):
        if not s.get('ready') or not s.get('containerID') or not s.get('imageID') or not s.get('state',{}).get('running',{}).get('startedAt'): raise Refusal('SPIRE container not independently running/ready')
        observed.append((s['name'],s['containerID'],s['imageID'],s.get('restartCount'),s['state']['running']['startedAt']))
    cli_volumes=[v for v in spec.get('volumes',[]) if v.get('name')=='spire-server-cli']
    if len(cli_volumes)!=1 or cli_volumes[0].get('image',{}).get('reference')!=server_image: raise Refusal('SPIRE CLI image-volume pin mismatch')
    return {'uid':m['uid'],'nodeName':spec['nodeName'],'containers':observed,'specSHA256':sha(json.dumps(spec,sort_keys=True,separators=(',',':')).encode())}

def execute_proof(api,*,cluster,cluster_uid,pod_uid,approval_uid,root_pin,invoke=None,clock=None,server_image=SERVER_IMAGE):
    server_image=approved_server_image(server_image)
    if cluster not in DOMAINS or not re.fullmatch('[0-9a-f]{64}',root_pin): raise Refusal('invalid independent cluster/root approval')
    domain=DOMAINS[cluster]
    podpath='/api/v1/namespaces/cilium-spire/pods/spire-server-0'
    apppath='/api/v1/namespaces/cert-manager/configmaps/cmtc-spire-cluster-ca-approval'
    if live_meta(api.get('/api/v1/namespaces/kube-system'))['uid']!=cluster_uid: raise Refusal('wrong cluster API')
    pod=pod_identity(api.get(podpath),pod_uid,server_image=server_image)
    nodepath='/api/v1/nodes/'+pod['nodeName'];nodeuid=live_meta(api.get(nodepath))['uid']
    approval=api.get(apppath);approval_rv=live_meta(approval)['resourceVersion']
    clock=clock or (lambda:dt.datetime.now(dt.timezone.utc))
    parent,root=approved_parent(approval,uid=approval_uid,cluster=cluster,root_pin=root_pin,now=clock())
    nonce=secrets.token_hex(32);uri='spiffe://'+domain+'/cmtc/issuer-proof/'+nonce
    argv=api.argv+['exec','-n','cilium-spire','spire-server-0','-c','register-agent-node','--','/bin/sh','-c',PROOF_SCRIPT,'cmtc-public-proof',uri]
    before=clock()
    if invoke is None:
        try: p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35,check=False)
        except subprocess.TimeoutExpired as e: raise Refusal('public proof timed out; no evidence accepted') from e
        if p.returncode: raise Refusal('in-pod public proof failed; raw CLI output withheld')
        raw=p.stdout
    else: raw=invoke(argv,uri)
    after=clock()
    a,chain,b=split_output(raw)
    result=verify_challenge(chain,domain=domain,nonce=nonce,parent=parent,root=root,before=before,after=after,authority_before=a,authority_after=b)
    # API continuity checks are mandatory after the cryptographic challenge.
    if pod_identity(api.get(podpath),pod_uid,server_image=server_image)!=pod or live_meta(api.get(nodepath))['uid']!=nodeuid or live_meta(api.get('/api/v1/namespaces/kube-system'))['uid']!=cluster_uid: raise Refusal('SPIRE execution incarnation or cluster changed during proof')
    last=api.get(apppath)
    if live_meta(last)['uid']!=approval_uid or live_meta(last)['resourceVersion']!=approval_rv or last.get('data')!=approval.get('data') or last.get('immutable') is not True: raise Refusal('approval changed during proof')
    result.update(approvedServerImage=server_image,cluster=cluster,clusterUID=cluster_uid,pod=pod,nodeUID=nodeuid,approvalUID=approval_uid,approvalResourceVersion=approval_rv,challengeLeafPEM=pem(certs(chain)[0]))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('kubeconfig','cluster','cluster-uid','pod-uid','approval-uid','root-sha256','pki-module'): p.add_argument('--'+name,required=True)
    p.add_argument("--server-image",default=SERVER_IMAGE,help="Independent approved digest-qualified server/CLI image; verify source/config and all-node CRI imports first")
    args=p.parse_args()
    try:approved_server_image(args.server_image)
    except Refusal as error:p.error(str(error))
    if args.cluster not in DOMAINS: p.error('owned cmtc-a/b clusters only')
    spec=importlib.util.spec_from_file_location('reviewed_cmtc_pki',args.pki_module);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with module.Proxy(args.kubeconfig,'kind-'+args.cluster) as api:
        result=execute_proof(api,cluster=args.cluster,cluster_uid=args.cluster_uid,pod_uid=args.pod_uid,approval_uid=args.approval_uid,root_pin=args.root_sha256,server_image=args.server_image)
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__': main()
