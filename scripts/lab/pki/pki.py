#!/usr/bin/env python3
"""Owned cluster-parent CA issuance. No host-side populated Secret GET is permitted."""
import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

NS = 'cert-manager'
SECRET = 'cmtc-spire-cluster-ca'
LEDGER = 'cmtc-spire-cluster-ca-ledger'
APPROVAL = 'cmtc-spire-cluster-ca-approval'
OWNER = 'security.cmtc.io/pki-owner'
CLUSTER = 'security.cmtc.io/pki-cluster'
ROLE = 'security.cmtc.io/pki-role'
ROOT = 'security.cmtc.io/root-sha256'
PREFIX = '/api/v1/namespaces/cert-manager/'
MAX = 256 * 1024

class Refusal(RuntimeError):
    pass

class APIError(Refusal):
    def __init__(self, status, message):
        self.status = status
        super().__init__(f'API status {status}: {message}')

def strict_json(raw):
    def pairs(xs):
        out = {}
        for k, v in xs:
            if k in out:
                raise Refusal('duplicate JSON key')
            out[k] = v
        return out
    if len(raw) > MAX:
        raise Refusal('JSON exceeds limit')
    return json.loads(raw, object_pairs_hook=pairs)

def canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False)

def digest(b):
    return hashlib.sha256(b).hexdigest()

def run(args, *, data=None, timeout=30, pass_fds=()):
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, check=False, pass_fds=pass_fds)
    if p.returncode:
        # Do not echo process stderr: commands can handle private root material.
        raise Refusal(f'{Path(args[0]).name} failed with exit {p.returncode}')
    return p.stdout

def labels(cluster, role):
    return {OWNER: 'cmtc-lab-pki', CLUSTER: cluster, ROLE: role}

def meta(o):
    m = o.get('metadata', {})
    if not m.get('uid') or not m.get('resourceVersion') or m.get('deletionTimestamp'):
        raise Refusal('missing/live UID or resourceVersion')
    return m

def owned(o, cluster, role, uid=None):
    m = meta(o)
    if m.get('ownerReferences') or any(m.get('labels', {}).get(k) != v
                                     for k, v in labels(cluster, role).items()):
        raise Refusal('foreign object ownership')
    if uid is not None and m['uid'] != uid:
        raise Refusal('object UID replacement')
    return m

class Proxy:
    """Local authenticated kubectl proxy, UNIX socket in a private directory."""
    def __init__(self, kubeconfig, context):
        self.argv = ['kubectl', '--kubeconfig', kubeconfig, '--context', context]
        self.process = None
        self.directory = None
    def __enter__(self):
        self.directory = tempfile.mkdtemp(prefix='cmtc-pki-proxy-')
        os.chmod(self.directory, 0o700)
        self.sock = self.directory + '/api.sock'
        self.process = subprocess.Popen(self.argv + ['proxy', '--unix-socket=' + self.sock],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if self.process.poll() is not None:
                raise Refusal('kubectl proxy exited')
            if os.path.exists(self.sock):
                return self
            time.sleep(.05)
        self.__exit__(None, None, None)
        raise Refusal('kubectl proxy startup timeout')
    def __exit__(self, *_):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.directory:
            shutil.rmtree(self.directory)  # only our fresh private proxy directory, no key files
    def request(self, method, path, body=None, *, metadata=False):
        # No host request may retrieve or update an initialized Secret.
        parsed=urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith('/') or '%' in parsed.path or '..' in parsed.path.split('/'):
            raise Refusal('noncanonical API path')
        route=parsed.path
        secret_path = re.fullmatch(r'/api/v1/namespaces/[^/]+/secrets(?:/[^/]+)?', route)
        if secret_path:
            if method == 'GET' and route.endswith('/secrets'):
                raise Refusal('Secret list forbidden')
            if method == 'GET' and not metadata:
                raise Refusal('full Secret GET forbidden')
            if method == 'POST':
                if body.get('data') or body.get('stringData') or body.get('type') != 'Opaque':
                    raise Refusal('only empty Opaque Secret creation allowed')
            elif method != 'GET':
                raise Refusal('host Secret mutation forbidden')
        headers = {'Content-Type': 'application/json'}
        if metadata:
            headers['Accept'] = 'application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1'
        c = http.client.HTTPConnection('localhost', timeout=15)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(self.sock)
        c.sock = s
        try:
            c.request(method, path, None if body is None else canon(body), headers)
            r = c.getresponse()
            raw = r.read(MAX + 1)
            if len(raw) > MAX:
                raise Refusal('API response exceeds limit')
            obj = strict_json(raw)
            if r.status >= 300:
                raise APIError(r.status, obj.get('reason', 'request refused'))
            if metadata and (obj.get('kind') != 'PartialObjectMetadata' or 'data' in obj):
                raise Refusal('server ignored metadata-only negotiation')
            return obj
        finally:
            c.close()
    def get(self, path, metadata=False):
        return self.request('GET', path, metadata=metadata)

def maybe(api, path, metadata=False):
    try:
        return api.get(path, metadata=metadata)
    except APIError as e:
        if e.status == 404:
            return None
        raise

def write_private(fd, name, data):
    f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(f, 'wb', closefd=False) as out:
            out.write(data)
            out.flush()
        os.fsync(f)
    finally:
        os.close(f)

def private_file(fd, name, limit=65536):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(f)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > limit:
            raise Refusal('unsafe private root file')
        data = os.read(f, limit + 1)
        if len(data) > limit or os.fstat(f).st_ino != st.st_ino:
            raise Refusal('private root read changed')
        return data
    finally:
        os.close(f)

def open_directory(path):
    if not os.path.isabs(path):
        raise Refusal('root directory must be absolute')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for p in Path(path).parts[1:]:
            nxt = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise Refusal('root directory must be owned mode 0700')
        return fd
    except BaseException:
        os.close(fd)
        raise

def load_cert(pem):
    c = x509.load_pem_x509_certificate(pem)
    if c.public_bytes(serialization.Encoding.PEM) != pem:
        raise Refusal('noncanonical or multiple certificate PEM')
    return c

def ca_extensions(c, depth):
    allowed = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
               ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    if any(e.oid not in allowed for e in c.extensions):
        raise Refusal('unexpected CA extension')
    bc = c.extensions.get_extension_for_class(x509.BasicConstraints)
    ku = c.extensions.get_extension_for_class(x509.KeyUsage)
    if not bc.critical or not bc.value.ca or bc.value.path_length != depth or not ku.critical or not ku.value.key_cert_sign or not ku.value.crl_sign:
        raise Refusal('wrong CA constraints')
    now = dt.datetime.now(dt.timezone.utc)
    if not c.not_valid_before_utc <= now < c.not_valid_after_utc:
        raise Refusal('expired or future CA')

def public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

class Root:
    def __init__(self, directory):
        self.path = directory
    def __enter__(self):
        self.fd = open_directory(self.path)
        try:
            self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            st = os.fstat(self.lock)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
                raise Refusal('unsafe root lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._load_or_create()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise
    def _load_or_create(self):
        entries = set(os.listdir(self.fd))
        if entries - {'lock', 'current'}:
            raise Refusal('partial or unknown root state requires explicit administrator recovery')
        if 'current' not in entries:
            pending = 'pending-' + uuid.uuid4().hex
            os.mkdir(pending, 0o700, dir_fd=self.fd)
            pfd = os.open(pending, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                key_bytes = run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'])
                write_private(pfd, 'key.pem', key_bytes)
                key_fd = os.open('key.pem', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
                try:
                    certificate = run(['openssl', 'req', '-new', '-x509', '-key', '/dev/fd/' + str(key_fd),
                         '-days', '1825', '-sha256', '-set_serial', '0x' + format(secrets.randbits(159) or 1, 'x'),
                         '-subj', '/CN=CMTC Lab Organization Root',
                         '-addext', 'basicConstraints=critical,CA:true,pathlen:2',
                         '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash'],
                         pass_fds=(key_fd,))
                finally:
                    os.close(key_fd)
                write_private(pfd, 'cert.pem', certificate)
                for n in ('key.pem', 'cert.pem'):
                    f = os.open(n, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
                    try:
                        os.fsync(f)
                    finally:
                        os.close(f)
                os.fsync(pfd)
                os.rename(pending, 'current', src_dir_fd=self.fd, dst_dir_fd=self.fd)
                os.fsync(self.fd)
            finally:
                os.close(pfd)
            # A crash before rename leaves a partial marker; never generate a second root automatically.
        self.current = os.open('current', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        st = os.fstat(self.current)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700 or set(os.listdir(self.current)) != {'key.pem', 'cert.pem'}:
            raise Refusal('partial or unsafe committed root')
        self.pem = private_file(self.current, 'cert.pem')
        self.cert = load_cert(self.pem)
        ca_extensions(self.cert, 2)
        key = serialization.load_pem_private_key(private_file(self.current, 'key.pem'), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != 'secp256r1' or public_der(key.public_key()) != public_der(self.cert.public_key()) or self.cert.issuer != self.cert.subject:
            raise Refusal('root key/certificate mismatch')
        self.cert.public_key().verify(self.cert.signature, self.cert.tbs_certificate_bytes, ec.ECDSA(self.cert.signature_hash_algorithm))
        self.pin = digest(self.cert.public_bytes(serialization.Encoding.DER))
        # Requalify a possibly visible rename after a previous process died before directory fsync.
        for n in ('key.pem', 'cert.pem'):
            f = os.open(n, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.current)
            try:
                os.fsync(f)
            finally:
                os.close(f)
        os.fsync(self.current)
        os.fsync(self.fd)
    def assert_paths(self):
        check=open_directory(self.path)
        try:
            if (os.fstat(check).st_dev,os.fstat(check).st_ino)!=(os.fstat(self.fd).st_dev,os.fstat(self.fd).st_ino):
                raise Refusal('root directory replaced')
            current=os.stat('current',dir_fd=check,follow_symlinks=False)
            held=os.fstat(self.current)
            lock=os.stat('lock',dir_fd=check,follow_symlinks=False)
            heldlock=os.fstat(self.lock)
            if (current.st_dev,current.st_ino)!=(held.st_dev,held.st_ino) or (lock.st_dev,lock.st_ino)!=(heldlock.st_dev,heldlock.st_ino):
                raise Refusal('root authority or lock path replaced')
        finally:
            os.close(check)
    def sign(self, request):
        self.assert_paths()
        csr_pem = request['clusterIssuerCSR'].encode()
        csr = x509.load_pem_x509_csr(csr_pem)
        if csr.public_bytes(serialization.Encoding.PEM) != csr_pem or not csr.is_signature_valid or len(csr.extensions) != 0 or list(csr.attributes):
            raise Refusal('invalid CSR')
        expected = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, request['cluster'] + ' SPIRE cluster CA')])
        if csr.subject != expected or not isinstance(csr.public_key(), ec.EllipticCurvePublicKey) or csr.public_key().curve.name != 'secp256r1' or digest(csr.public_bytes(serialization.Encoding.DER)) != request['csrSHA256']:
            raise Refusal('CSR subject/key/digest mismatch')
        if request['rootSHA256'] != self.pin:
            raise Refusal('CSR independently pinned root mismatch')
        tmp = 'sign-' + uuid.uuid4().hex
        os.mkdir(tmp, 0o700, dir_fd=self.fd)
        tfd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            write_private(tfd, 'request.pem', csr_pem)
            write_private(tfd, 'extensions.cnf', b'basicConstraints=critical,CA:true,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
            # Max365days and root expiry check below. Root key path never appears in evidence.
            days = min(365, (self.cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).days - 1)
            if days < 1:
                raise Refusal('root too near expiry')
            key_fd = os.open('key.pem', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.current)
            cert_fd = os.open('cert.pem', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.current)
            ext_fd = os.open('extensions.cnf', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=tfd)
            try:
                pem = run(['openssl', 'x509', '-req', '-in', '/dev/stdin',
                     '-CA', '/dev/fd/' + str(cert_fd), '-CAkey', '/dev/fd/' + str(key_fd),
                     '-set_serial', '0x' + format(secrets.randbits(159) or 1, 'x'), '-days', str(days), '-sha256',
                     '-extfile', '/dev/fd/' + str(ext_fd)], data=csr_pem, pass_fds=(key_fd,cert_fd,ext_fd))
            finally:
                for fd in (key_fd, cert_fd, ext_fd):
                    os.close(fd)
            c = load_cert(pem)
            ca_extensions(c, 1)
            if c.subject != csr.subject or c.issuer != self.cert.subject or public_der(c.public_key()) != public_der(csr.public_key()) or c.not_valid_before_utc < self.cert.not_valid_before_utc or c.not_valid_after_utc > self.cert.not_valid_after_utc:
                raise Refusal('signed certificate mismatch')
            self.cert.public_key().verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
            self.assert_paths()
            return pem.decode() + self.pem.decode()
        finally:
            for n in os.listdir(tfd):
                os.unlink(n, dir_fd=tfd)
            os.close(tfd)
            os.rmdir(tmp, dir_fd=self.fd)
    def __exit__(self, *_):
        for name in ('current', 'lock', 'fd'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

# All Secret reads here negotiate PartialObjectMetadata on the server.
def ensure_ledger(api, cluster, pin):
    lp = PREFIX + 'configmaps/' + LEDGER
    ledger = maybe(api, lp)
    secret = maybe(api, PREFIX + 'secrets/' + SECRET, metadata=True)
    if ledger is None:
        if secret is not None:
            raise Refusal('Secret exists without ledger; automatic adoption forbidden')
        ledger = api.request('POST', PREFIX + 'configmaps', {
            'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': LEDGER, 'namespace': NS,
            'labels': labels(cluster, 'spire-cluster-ca-ledger')},
            'data': {'schemaVersion': '1', 'rootSHA256': pin, 'phase': 'reserved'}})
    lm = owned(ledger, cluster, 'spire-cluster-ca-ledger')
    data = ledger.get('data', {})
    if data.get('rootSHA256') != pin or data.get('schemaVersion') != '1' or ledger.get('immutable'):
        raise Refusal('invalid ledger/root pin')
    if 'secretUID' not in data:
        if secret is not None:
            # We may have crashed between Secret creation and recording UID. Never infer ownership.
            raise Refusal('unrecorded Secret creation; explicit administrator recovery required')
        secret = api.request('POST', PREFIX + 'secrets', {'apiVersion': 'v1', 'kind': 'Secret',
            'metadata': {'name': SECRET, 'namespace': NS, 'labels': labels(cluster, 'spire-cluster-ca'),
            'annotations': {ROOT: pin}}, 'type': 'Opaque'})
        if secret.get('data') or secret.get('stringData'):
            raise Refusal('new Secret response unexpectedly contains private data')
        sm = owned(secret, cluster, 'spire-cluster-ca')
        # Commit ledger before any Job can write a private key.
        ledger['data'].update(secretUID=sm['uid'], phase='reserved')
        ledger = api.request('PUT', lp, ledger)
        owned(ledger, cluster, 'spire-cluster-ca-ledger', lm['uid'])
        if ledger['data'].get('secretUID') != sm['uid']:
            raise Refusal('ledger UID commit failed')
    if secret is None:
        raise Refusal('recorded CA Secret missing; never replace authority automatically')
    owned(secret, cluster, 'spire-cluster-ca', ledger['data']['secretUID'])
    if secret['metadata'].get('annotations', {}).get(ROOT) != pin:
        raise Refusal('Secret root pin mismatch')
    return ledger

def public_result(raw, cluster, uid, pin):
    lines = [line for line in raw.splitlines() if line.strip()]
    candidates=[]
    for line in lines:
        o = strict_json(line)
        if 'schemaVersion' in o:
            candidates.append(o)
        elif o.get('component') != 'lab-cluster-ca' or not o.get('msg'):
            raise Refusal('unexpected Job log structure')
    if len(candidates) != 1:
        raise Refusal('expected exactly one public Job acknowledgment')
    o=candidates[0]
    required = {'schemaVersion','cluster','secretNamespace','secretName','secretUID','resourceVersion',
                'rootSHA256','csrSHA256','clusterIssuerCSR','status'}
    if set(o) not in (required, required | {'certificateSHA256'}) or o['schemaVersion'] != 1 or o['cluster'] != cluster or o['secretNamespace'] != NS or o['secretName'] != SECRET or o['secretUID'] != uid or o['rootSHA256'] != pin or o['status'] not in ('pending','ready'):
        raise Refusal('invalid public acknowledgment')
    if not re.fullmatch('[0-9a-f]{64}', o['csrSHA256']) or not o['resourceVersion'] or len(o['clusterIssuerCSR']) > 8192:
        raise Refusal('invalid public CSR metadata')
    return o

def approval_for(api, ledger, request, root):
    cluster = request['cluster']
    path = PREFIX + 'configmaps/' + APPROVAL
    old = maybe(api, path)
    if old is not None:
        owned(old, cluster, 'spire-cluster-ca-approval', ledger['data'].get('approvalUID', 'UNRECORDED'))
        if old.get('immutable') is not True or set(old.get('data', {})) != {'approval.json'}:
            raise Refusal('approval not exact immutable public object')
        a = strict_json(old['data']['approval.json'])
        expected = {'schemaVersion':1, 'cluster':cluster, 'secretUID':request['secretUID'],
                    'secretResourceVersion':a.get('secretResourceVersion'), 'csrSHA256':request['csrSHA256'],
                    'rootSHA256':root.pin, 'certificatePEM':a.get('certificatePEM')}
        if a != expected or not a['secretResourceVersion']:
            raise Refusal('existing approval differs; no automatic rotation')
        # Completing an already TLS Secret is idempotent even though its RV advanced.
        return old
    if request['status'] == 'ready':
        raise Refusal('completed Secret has missing approval; preserve and require explicit recovery')
    a = {'schemaVersion':1, 'cluster':cluster, 'secretUID':request['secretUID'],
         'secretResourceVersion':request['resourceVersion'], 'csrSHA256':request['csrSHA256'],
         'rootSHA256':root.pin, 'certificatePEM':root.sign(request)}
    approval = api.request('POST', PREFIX + 'configmaps', {'apiVersion':'v1','kind':'ConfigMap',
        'metadata':{'name':APPROVAL,'namespace':NS,'labels':labels(cluster,'spire-cluster-ca-approval')},
        'immutable':True,'data':{'approval.json':canon(a)}})
    am=owned(approval,cluster,'spire-cluster-ca-approval')
    lm=owned(ledger,cluster,'spire-cluster-ca-ledger')
    ledger['data']['approvalUID']=am['uid']
    saved=api.request('PUT',PREFIX+'configmaps/'+LEDGER,ledger)
    owned(saved,cluster,'spire-cluster-ca-ledger',lm['uid'])
    ledger.clear()
    ledger.update(saved)
    return approval

def delete_owned(api, collection, name, cluster, role, uid, *, timeout=30, poll=.1):
    path = collection + '/' + name
    current = maybe(api, path)
    if current is None:
        return
    m = owned(current, cluster, role, uid)
    api.request('DELETE', path, {'apiVersion':'v1','kind':'DeleteOptions',
        'preconditions':{'uid':m['uid'],'resourceVersion':m['resourceVersion']},
        'propagationPolicy':'Foreground'})
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        current=maybe(api,path)
        if current is None:
            return
        # Terminating original objects may have deletionTimestamp; only UID decides
        # whether this is still OUR in-flight deletion. Replacement is never removed.
        if current.get('metadata',{}).get('uid')!=uid:
            raise Refusal('replacement appeared during cleanup; preserved')
        time.sleep(poll)
    raise Refusal('recorded UID still present after cleanup deadline')

def snapshot(api, argv):
    nodes = api.get('/api/v1/nodes')
    ns = api.get('/api/v1/namespaces/kube-system')
    if len(nodes.get('items', [])) != 2:
        raise Refusal('expected retained two-node kind cluster')
    ds = api.get('/apis/apps/v1/namespaces/kube-system/daemonsets/cilium')
    cm = api.get('/api/v1/namespaces/kube-system/configmaps/cilium-config')
    certmanager=api.get('/apis/apps/v1/namespaces/cert-manager/deployments/cert-manager')
    return {'certManagerUID':meta(certmanager)['uid'],'certManagerSpec':certmanager['spec'],
        'currentContext':run(argv + ['config','current-context']).decode().strip(),
        'clusterUID':meta(ns)['uid'], 'nodes':sorted((n['metadata']['name'],meta(n)['uid']) for n in nodes['items']),
        'ciliumUID':meta(ds)['uid'],'ciliumSpec':ds['spec'],'ciliumConfigUID':meta(cm)['uid'],
        'ciliumConfig':cm.get('data',{})}

class Orchestrator:
    def __init__(self, api, cluster, root, image, config_id, revision, manifest_digest, expected_nodes=None):
        self.api,self.cluster,self.root = api,cluster,root
        self.image,self.config_id,self.revision,self.manifest_digest=image,config_id,revision,manifest_digest
        self.expected_nodes=expected_nodes or {}
        self.worker=cluster+'-worker'
        self.public_logs=[]
        self.runid = uuid.uuid4().hex[:12]
        self.temporary=[]
        self.unconfirmed=[]
    def create(self, collection, obj, role):
        m=obj.setdefault('metadata',{})
        m['labels']=labels(self.cluster,role)
        try:
            created=self.api.request('POST',collection,obj)
        except Exception:
            self.unconfirmed.append({'kind':collection.rsplit('/',1)[-1],'name':m['name'],
                                     'error':'create outcome unknown; no UID obtained; preserved'})
            raise
        owned(created,self.cluster,role)
        self.temporary.append((collection,m['name'],role,created['metadata']['uid']))
        return created
    def setup(self):
        api=self.api
        self.sa='cmtc-ca-init-'+self.runid
        self.create(PREFIX+'serviceaccounts',{'apiVersion':'v1','kind':'ServiceAccount',
            'metadata':{'name':self.sa,'namespace':NS},'automountServiceAccountToken':False},'init-service-account')
        base='/apis/rbac.authorization.k8s.io/v1/namespaces/'+NS+'/'
        self.create(base+'roles',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role',
            'metadata':{'name':self.sa,'namespace':NS},'rules':[
                {'apiGroups':[''],'resources':['secrets'],'resourceNames':[SECRET],'verbs':['get','update']},
                {'apiGroups':[''],'resources':['configmaps'],'resourceNames':[APPROVAL],'verbs':['get']}]},'init-role')
        self.create(base+'rolebindings',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding',
            'metadata':{'name':self.sa,'namespace':NS},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':self.sa},
            'subjects':[{'kind':'ServiceAccount','name':self.sa,'namespace':NS}]},'init-rolebinding')
    def check_permissions(self):
        user='system:serviceaccount:'+NS+':'+self.sa
        cases=[('get','secret/'+SECRET,True),('update','secret/'+SECRET,True),
               ('get','configmap/'+APPROVAL,True),('list','secrets',False),
               ('watch','secrets',False),('create','secrets',False),('delete','secret/'+SECRET,False),
               ('get','secret/cluster-intermediate',False),('update','secret/cluster-intermediate',False),
               ('create','configmaps',False),('list','configmaps',False),('watch','configmaps',False),
               ('delete','configmap/'+APPROVAL,False),('get','configmap/cilium-config',False),
               ('update','configmap/'+APPROVAL,False)]
        for verb,resource,expected in cases:
            result=subprocess.run(self.api.argv+['auth','can-i',verb,resource,'-n',NS,'--as='+user],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            if result.returncode not in (0,1):
                raise Refusal('RBAC probe failed')
            answer=result.stdout.decode().strip()
            if answer != ('yes' if expected else 'no'):
                raise Refusal('initializer effective RBAC mismatch: '+verb+' '+resource)
    def validate_worker(self):
        if self.worker not in self.expected_nodes or not self.expected_nodes[self.worker]:
            raise Refusal('exact independent worker node UID pin required')
        node=self.api.get('/api/v1/nodes/'+self.worker)
        if meta(node)['uid']!=self.expected_nodes[self.worker]:
            raise Refusal('worker node UID replaced')
    def verify_image(self,pod):
        self.validate_worker()
        status=pod.get('status',{}).get('containerStatuses',[])
        if len(status)!=1 or status[0].get('imageID','').split('://', 1)[-1].rsplit('@', 1)[-1] != self.manifest_digest:
            raise Refusal('runtime manifest identity mismatch')
        node=pod['spec']['nodeName']
        if node!=self.worker:
            raise Refusal('Job scheduled outside exact manifest-pinned worker')
        raw=run(['colima','ssh','--profile','cmtc-cilium','--','docker','exec',node,
                 'crictl','inspecti',self.image])
        cri=strict_json(raw)
        if cri['status']['id'] != self.config_id or cri['info']['imageSpec']['config'].get('Labels',{}).get('org.opencontainers.image.revision') != self.revision:
            raise Refusal('runtime config/source mismatch')
    def job(self,mode,uid,approval_uid=None):
        self.validate_worker()
        name='cmtc-ca-'+('complete' if approval_uid else 'init')+'-'+self.runid
        env={'LAB_INIT_MODE':mode,'CLUSTER_NAME':self.cluster,'CLUSTER_CA_SECRET_UID':uid,
             'CLUSTER_CA_ROOT_SHA256':self.root.pin}
        if approval_uid:
            env['CLUSTER_CA_APPROVAL_UID']=approval_uid
        job=self.create('/apis/batch/v1/namespaces/'+NS+'/jobs',{'apiVersion':'batch/v1','kind':'Job',
            'metadata':{'name':name,'namespace':NS},'spec':{'backoffLimit':0,'activeDeadlineSeconds':60,
            'template':{'metadata':{'labels':labels(self.cluster,'init-job')},'spec':{
            'nodeName':self.worker,'restartPolicy':'Never','serviceAccountName':self.sa,'automountServiceAccountToken':True,
            'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}},
            'containers':[{'name':'initializer','image':self.image,'imagePullPolicy':'Never',
            'command':['/lab-identity-init'],'env':[{'name':k,'value':v} for k,v in env.items()],
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
            'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'1','memory':'128Mi'}}}]}}}},'init-job')
        end=time.monotonic()+90
        while time.monotonic()<end:
            current=self.api.get('/apis/batch/v1/namespaces/'+NS+'/jobs/'+name)
            owned(current,self.cluster,'init-job',job['metadata']['uid'])
            pods=self.api.get(PREFIX+'pods?labelSelector='+urllib.parse.quote('job-name='+name))['items']
            if len(pods)>1:
                raise Refusal('multiple initializer Pods')
            if pods and pods[0].get('status',{}).get('phase') in ('Succeeded','Failed'):
                pod=pods[0]
                refs=pod['metadata'].get('ownerReferences',[])
                if len(refs)!=1 or refs[0].get('uid')!=job['metadata']['uid']:
                    raise Refusal('Job Pod ownership mismatch')
                self.verify_image(pod)
                raw=self.collect_logs(pod)
                if pod['status']['phase']!='Succeeded':
                    raise Refusal('initializer Job failed; reviewed public diagnostics retained; authority retained for retry')
                return public_result(raw,self.cluster,uid,self.root.pin)
            time.sleep(.25)
        raise Refusal('initializer Job timeout')
    def collect_logs(self,pod):
        raw=self.log(pod['metadata']['name'])
        entries=sanitize_public_logs(raw)
        self.public_logs.append({'pod':pod['metadata']['name'],'uid':meta(pod)['uid'],
            'imageID':pod['status']['containerStatuses'][0].get('imageID'),
            'phase':pod['status']['phase'],'entries':entries})
        return raw
    def log(self,name):
        # kubectl logs is bounded and kept only in memory. Acknowledgment is public stdout.
        return run(self.api.argv+['logs','-n',NS,name,'-c','initializer','--limit-bytes=65536'],timeout=15)
    def execute(self):
        ledger=ensure_ledger(self.api,self.cluster,self.root.pin)
        self.setup()
        self.check_permissions()
        uid=ledger['data']['secretUID']
        request=self.job('cluster-ca-init',uid)
        approval=approval_for(self.api,ledger,request,self.root)
        am=owned(approval,self.cluster,'spire-cluster-ca-approval')
        done=self.job('cluster-ca-complete',uid,am['uid'])
        if done['status']!='ready' or done['csrSHA256']!=request['csrSHA256']:
            raise Refusal('completion acknowledgment mismatch')
        lm=owned(ledger,self.cluster,'spire-cluster-ca-ledger')
        ledger['data'].update(phase='ready',approvalUID=am['uid'],csrSHA256=done['csrSHA256'],
                              certificateSHA256=done['certificateSHA256'])
        updated=self.api.request('PUT',PREFIX+'configmaps/'+LEDGER,ledger)
        owned(updated,self.cluster,'spire-cluster-ca-ledger',lm['uid'])
        return {'cluster':self.cluster,'secretUID':uid,'approvalUID':am['uid'],'rootSHA256':self.root.pin,
                'csrSHA256':done['csrSHA256'],'certificateSHA256':done['certificateSHA256'],
                'scope':'public cluster-parent issuance only; no workload mTLS'}
    def cleanup(self):
        errors=list(self.unconfirmed)
        for collection,name,role,uid in reversed(self.temporary):
            try:
                delete_owned(self.api,collection,name,self.cluster,role,uid)
            except Exception as e:
                errors.append({'kind':collection.rsplit('/',1)[-1],'name':name,'uid':uid,'error':str(e)})
        return errors

def sanitize_public_logs(raw):
    if len(raw)>65536:
        raise Refusal('public logs exceed bound')
    text=raw.decode('utf-8',errors='strict')
    if re.search(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|["\'](?:tls\.key|privateKey|private_key)["\']\s*:',text):
        raise Refusal('private key marker in Job logs; content withheld')
    entries=[]
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj=strict_json(line.encode())
        except (ValueError,RecursionError):
            # The reviewed main writes one final plain error line on failure.
            if len(line)>4096:
                raise Refusal('unbounded diagnostic line')
            entries.append({'diagnostic':line})
            continue
        if not isinstance(obj,dict) or not ('schemaVersion' in obj or obj.get('component')=='lab-cluster-ca'):
            raise Refusal('unrecognized reviewed Job log object')
        entries.append(obj)
    return entries

def derive_spire_candidate(api, namespace, request_name, *, request_uid, username, issuer_ref,
                           domain, approved_parent_chain):
    """Return validated PUBLIC candidate only. Caller still needs running-server key proof.

    api exposes only public CertificateRequest here. No bundle-order inference, endpoint claim,
    or root/parent key is promoted to a direct workload signer.
    """
    if not re.fullmatch('[a-z0-9.-]+',namespace) or not re.fullmatch('[a-z0-9.-]+',request_name):
        raise Refusal('invalid CertificateRequest reference')
    path='/apis/cert-manager.io/v1/namespaces/'+namespace+'/certificaterequests/'+request_name
    request=api.get(path)
    m=meta(request)
    if m['uid']!=request_uid or request.get('spec',{}).get('username')!=username or request['spec'].get('issuerRef')!=issuer_ref:
        raise Refusal('CertificateRequest source/issuer/SA mismatch')
    ready=[c for c in request.get('status',{}).get('conditions',[]) if c.get('type')=='Ready']
    approved=[c for c in request.get('status',{}).get('conditions',[]) if c.get('type')=='Approved']
    if len(ready)!=1 or ready[0].get('status')!='True' or len(approved)!=1 or approved[0].get('status')!='True':
        raise Refusal('CertificateRequest not explicitly approved and ready')
    try:
        csr_pem=base64.b64decode(request['spec']['request'],validate=True)
        cert_pem=base64.b64decode(request['status']['certificate'],validate=True)
    except (ValueError,KeyError) as e:
        raise Refusal('invalid public CSR/certificate encoding') from e
    if len(csr_pem)>16384 or len(cert_pem)>65536:
        raise Refusal('public SPIRE material exceeds limit')
    csr=x509.load_pem_x509_csr(csr_pem)
    chain=x509.load_pem_x509_certificates(cert_pem)
    parent_chain=x509.load_pem_x509_certificates(approved_parent_chain.encode())
    if not csr.is_signature_valid or len(parent_chain)!=2 or not 1<=len(chain)<=3:
        raise Refusal('invalid SPIRE signer request/chain')
    signer=chain[0]
    parent,root=parent_chain
    ca_extensions(parent,1)
    ca_extensions(root,2)
    root.public_key().verify(parent.signature,parent.tbs_certificate_bytes,ec.ECDSA(parent.signature_hash_algorithm))
    if parent.issuer!=root.subject or public_der(parent.public_key())==public_der(root.public_key()):
        raise Refusal('invalid approved parent lineage')
    # Any additional status certificates must match exact approved lineage/order.
    for got,want in zip(chain[1:],[parent,root]):
        if got.public_bytes(serialization.Encoding.DER)!=want.public_bytes(serialization.Encoding.DER):
            raise Refusal('unexpected SPIRE signer lineage')
    ca_extensions_signer=signer.extensions.get_extension_for_class(x509.BasicConstraints)
    if not ca_extensions_signer.critical or not ca_extensions_signer.value.ca or ca_extensions_signer.value.path_length not in (0,None):
        raise Refusal('SPIRE direct signer must be pathLen0 or unconstrained CA')
    ku=signer.extensions.get_extension_for_class(x509.KeyUsage).value
    if not ku.key_cert_sign or not ku.crl_sign:
        raise Refusal('SPIRE signer lacks certificate signing usages')
    sans=signer.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    csans=csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(sans)!=[x509.UniformResourceIdentifier('spiffe://'+domain)] or list(csans)!=list(sans):
        raise Refusal('SPIRE trust-domain URI SAN mismatch')
    if signer.subject!=csr.subject or public_der(signer.public_key())!=public_der(csr.public_key()) or signer.issuer!=parent.subject:
        raise Refusal('SPIRE signer/CSR/key mismatch')
    now=dt.datetime.now(dt.timezone.utc)
    if not parent.not_valid_before_utc<=signer.not_valid_before_utc<=now<signer.not_valid_after_utc<=parent.not_valid_after_utc:
        raise Refusal('SPIRE signer validity outside approved parent')
    parent.public_key().verify(signer.signature,signer.tbs_certificate_bytes,ec.ECDSA(signer.signature_hash_algorithm))
    # Reobserve exact public source; a mutation cannot be called a coherent candidate.
    again=api.get(path)
    if meta(again)['uid']!=m['uid'] or meta(again)['resourceVersion']!=m['resourceVersion']:
        raise Refusal('CertificateRequest changed during observation')
    return {'qualified':False,'missingGate':'running SPIRE server matching-key proof',
        'requestUID':m['uid'],'requestResourceVersion':m['resourceVersion'],'domain':domain,
        'directIssuerSHA256':digest(signer.public_bytes(serialization.Encoding.DER)),
        'directIssuerPEM':signer.public_bytes(serialization.Encoding.PEM).decode(),
        'parentPEM':parent.public_bytes(serialization.Encoding.PEM).decode(),
        'rootSHA256':digest(root.public_bytes(serialization.Encoding.DER))}

def verify_spire_direct_leaf(candidate, leaf_pem, expected_spiffe, role='server'):
    """Qualification only: exact direct signer; never a delegated child signer.

    Does not set qualified or provide running-server matching-key proof.
    """
    signer=load_cert(candidate['directIssuerPEM'].encode())
    leaf=load_cert(leaf_pem.encode() if isinstance(leaf_pem,str) else leaf_pem)
    if role not in ('server','client') or not expected_spiffe.startswith('spiffe://'+candidate['domain']+'/'):
        raise Refusal('wrong workload role/domain')
    if leaf.issuer!=signer.subject:
        raise Refusal('leaf not issued by exact SPIRE direct signer')
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise Refusal('workload leaf cannot be a CA')
    sans=leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(sans)!=[x509.UniformResourceIdentifier(expected_spiffe)]:
        raise Refusal('workload identity mismatch')
    now=dt.datetime.now(dt.timezone.utc)
    if not signer.not_valid_before_utc<=leaf.not_valid_before_utc<=now<leaf.not_valid_after_utc<=signer.not_valid_after_utc:
        raise Refusal('workload expiry outside direct issuer')
    from cryptography.x509.oid import ExtendedKeyUsageOID
    required=ExtendedKeyUsageOID.SERVER_AUTH if role=='server' else ExtendedKeyUsageOID.CLIENT_AUTH
    if required not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        raise Refusal('workload certificate role mismatch')
    signer.public_key().verify(leaf.signature,leaf.tbs_certificate_bytes,ec.ECDSA(leaf.signature_hash_algorithm))
    return digest(leaf.public_bytes(serialization.Encoding.DER))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kubeconfig',required=True)
    p.add_argument('--cluster',choices=['cmtc-a','cmtc-b'],required=True)
    p.add_argument('--expected-cluster-uid',required=True)
    p.add_argument('--expected-node',action='append',required=True,help='exact nodeName=UID, twice')
    p.add_argument('--repository-root',default=os.getcwd(),help='root key directory must be external to this repository')
    p.add_argument('--root-directory',required=True,help='precreated owned0700 external directory')
    p.add_argument('--image',required=True)
    p.add_argument('--image-config',required=True)
    p.add_argument('--image-manifest',required=True)
    p.add_argument('--source-revision',required=True)
    args=p.parse_args()
    for s,n in ((args.image_config,64),(args.image_manifest,64)):
        if not re.fullmatch('sha256:[0-9a-f]{'+str(n)+'}',s):
            p.error('full SHA256 image config/manifest required')
    if not re.fullmatch('[0-9a-f]{40}',args.source_revision):
        p.error('full source revision required')
    expected=sorted(tuple(x.split('=',1)) for x in args.expected_node)
    if len(expected)!=2 or any(len(x)!=2 or not x[1] for x in expected):
        p.error('two exact independent node UID pins required')
    repository=Path(args.repository_root).resolve()
    root_path=Path(args.root_directory)
    if repository==root_path or repository in root_path.parents:
        p.error('organizational root must be stored outside the repository/evidence tree')
    context='kind-'+args.cluster
    report={'success':False,'cluster':args.cluster}
    failure=None
    with Root(args.root_directory) as root, Proxy(args.kubeconfig,context) as api:
        before=snapshot(api,api.argv)
        if before['clusterUID']!=args.expected_cluster_uid or before['nodes']!=expected:
            raise Refusal('independent cluster/node identity mismatch')
        # Existing cert-manager must be available; no installation/upgrade is attempted.
        cm=api.get('/apis/apps/v1/namespaces/cert-manager/deployments/cert-manager')
        if cm.get('status',{}).get('availableReplicas',0)<1:
            raise Refusal('existing cert-manager not available')
        operation=Orchestrator(api,args.cluster,root,args.image,args.image_config,args.source_revision,args.image_manifest,dict(expected))
        try:
            report['publication']=operation.execute()
            report['success']=True
        except Exception as e:
            failure=e
            report['error']=str(e)
        finally:
            report['temporaryLeftovers']=operation.cleanup()
            report['publicJobLogs']=operation.public_logs
            try:
                after=snapshot(api,api.argv)
                report['preserved']=after==before
                if after!=before:
                    report['success']=False
                    report['preservationError']='Cilium/current-context/node identity changed'
            except Exception as e:
                report['success']=False
                report['preservationError']=str(e)
            if report['temporaryLeftovers']:
                report['success']=False
            report['persistentRetained']=[SECRET,LEDGER,APPROVAL]
            print(canon(report))
    if failure is not None or not report['success']:
        return 1
    return 0

if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print(canon({'success':False,'error':str(e)}),file=sys.stderr)
        sys.exit(1)
