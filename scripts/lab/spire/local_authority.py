#!/usr/bin/env python3
"""SPIRE local X.509 authority operations for one cluster (issue #34, LOCAL_ISSUER_PROFILE.md).

SPIRE rotates its signing CA on its own: it prepares the next CA at half of the current CA's lifetime and activates
it at five sixths. This script runs the same operations on demand, through `spire-server localauthority x509`, on the
server's private socket inside the SPIRE server Pod (the container and socket that `entry create` uses). It never
exposes the socket and never reads a Secret.

  show                      print the active, prepared and old authorities
  prepare                   mint the next CA now from the configured upstream; it must be signed by the cluster's
                            SPIRE intermediate (cert-manager/<cluster>-spire-intermediate)
  activate --authority-id   make that prepared CA the signer now
  rotate                    prepare (unless the prepared CA is already from the intermediate), wait until the SPIRE
                            trust bundle holds the mesh root, wait --propagation seconds, then activate
  taint --authority-id      mark the old authority tainted, so agents and workloads rotate away from it
  revoke --authority-id     remove a tainted old authority from the trust bundle

taint and revoke act only on the old authority and are never part of rotate.

Usage: local_authority.py [--context CTX] [--kube-system-uid UID] [--ledger FILE] CLUSTER COMMAND [options]
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

SPIRE_NS = 'cilium-spire'
SERVER_POD = 'spire-server-0'
CLI_CONTAINER = 'register-agent-node'
CLI = '/spire-cli/opt/spire/bin/spire-server'
SOCKET = '/tmp/spire-server/private/api.sock'
CM_NS = 'cert-manager'
ROOT_CM = ('cmtc-system', 'cmtc-mesh-root')
PEM = re.compile(r'-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----', re.S)


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def run(argv, *, timeout=60, stdin=None):
    r = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=timeout)
    require('PRIVATE KEY' not in r.stdout + r.stderr, 'private material in command output; suppressed')
    if r.returncode:
        raise Refusal(f'{argv[0]} {" ".join(argv[1:6])} failed ({r.returncode}): {r.stderr.strip()[:1500]}')
    return r.stdout


def subject_key_id(pem):
    """Lowercase hex of the certificate's Subject Key Identifier, the form SPIRE reports as the upstream authority."""
    out = run(['openssl', 'x509', '-noout', '-ext', 'subjectKeyIdentifier'], stdin=pem)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    require(len(lines) == 2 and lines[0].startswith('X509v3 Subject Key Identifier'), 'certificate has no Subject Key ID')
    return lines[1].replace(':', '').lower()


def der_sha256(pem):
    der = base64.b64decode(''.join(pem.strip().splitlines()[1:-1]), validate=True)
    return hashlib.sha256(der).hexdigest()


class Cluster:
    def __init__(self, name, context, kube_system_uid, ledger):
        self.name, self.context, self.ledger = name, context or 'kind-' + name, ledger
        if kube_system_uid:
            uid = self.kubectl('get', 'ns', 'kube-system', '-o', 'jsonpath={.metadata.uid}')
            require(uid == kube_system_uid, f'{self.name}: kube-system UID {uid} is not the pinned {kube_system_uid}')

    def kubectl(self, *args, timeout=60):
        return run(['kubectl', '--context', self.context, *args], timeout=timeout)

    def get(self, *args):
        return json.loads(self.kubectl(*args, '-o', 'json'))

    def spire(self, *args):
        out = self.kubectl('-n', SPIRE_NS, 'exec', SERVER_POD, '-c', CLI_CONTAINER, '--', '/bin/timeout', '-s', 'KILL',
                           '30', CLI, 'localauthority', 'x509', *args, '-socketPath', SOCKET, '-output', 'json',
                           timeout=45)
        return json.loads(out) if out.strip() else {}

    def record(self, event, **fields):
        line = {'at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'cluster': self.name, 'event': event,
                **fields}
        print(json.dumps(line), flush=True)
        if self.ledger:
            with open(self.ledger, 'a') as f:
                f.write(json.dumps(line) + '\n')

    def state(self):
        return self.spire('show')

    def intermediate(self):
        """The current certificate of cert-manager/<cluster>-spire-intermediate, from its CertificateRequest."""
        name = self.name + '-spire-intermediate'
        cert = self.get('-n', CM_NS, 'get', 'certificate', name)
        revision = cert.get('status', {}).get('revision')
        ready = any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in cert.get('status', {}).get('conditions', []))
        require(ready and isinstance(revision, int), f'{name} is not Ready')
        uid = cert['metadata']['uid']
        requests = [r for r in self.get('-n', CM_NS, 'get', 'certificaterequests')['items']
                    if r['metadata'].get('annotations', {}).get('cert-manager.io/certificate-revision') == str(revision)
                    and any(o.get('uid') == uid and o.get('controller') for o in r['metadata'].get('ownerReferences', []))]
        require(len(requests) == 1, f'expected one CertificateRequest for {name} revision {revision}')
        pem = base64.b64decode(requests[0]['status']['certificate'], validate=True).decode()
        certs = PEM.findall(pem)
        require(len(certs) == 1, f'{name} CertificateRequest does not hold exactly one certificate')
        conf = self.get('-n', SPIRE_NS, 'get', 'configmap', 'spire-server')['data'].get('server.conf', '')
        issuers = re.findall(r'issuer_name\s*=\s*"([^"]+)"', conf)
        require(issuers == [name], f'SPIRE server.conf names upstream issuer {issuers}, not {name}')
        return subject_key_id(certs[0])

    def mesh_root_in_bundle(self):
        root = self.get('-n', ROOT_CM[0], 'get', 'configmap', ROOT_CM[1])['data'].get('ca.crt', '')
        roots = PEM.findall(root)
        require(len(roots) == 1, f'{ROOT_CM[0]}/{ROOT_CM[1]} does not hold exactly one root')
        bundle = self.get('-n', SPIRE_NS, 'get', 'configmap', 'spire-bundle')['data'].get('bundle.crt', '')
        return der_sha256(roots[0]) in {der_sha256(c) for c in PEM.findall(bundle)}


def authority(state, slot):
    a = state.get(slot) or {}
    return {'id': a.get('authority_id', ''), 'upstream': a.get('upstream_authority_subject_key_id', ''),
            'expires': int(a.get('expires_at') or 0)}


def check_prepared(state, upstream, authority_id=None):
    prepared = authority(state, 'prepared')
    require(prepared['id'], 'no prepared X.509 authority')
    if authority_id is not None:
        require(prepared['id'] == authority_id, f'prepared authority is {prepared["id"]}, not {authority_id}')
    require(prepared['upstream'] == upstream,
            f'prepared authority {prepared["id"]} is signed by upstream {prepared["upstream"]}, not the SPIRE '
            f'intermediate {upstream}')
    return prepared


def check_old(state, authority_id):
    for slot in ('active', 'prepared'):
        require(authority(state, slot)['id'] != authority_id, f'{authority_id} is the {slot} authority; refused')
    require(authority(state, 'old')['id'] == authority_id, f'{authority_id} is not the old authority')


def prepare(c, upstream):
    before = c.state()
    require(authority(before, 'active')['id'], 'SPIRE has no active X.509 authority')
    out = c.spire('prepare')
    prepared = authority({'prepared': out.get('prepared_authority')}, 'prepared')
    c.record('prepared', authority=prepared, replaced=authority(before, 'prepared'), intermediate=upstream)
    return check_prepared(c.state(), upstream, prepared['id'])


def activate(c, upstream, authority_id):
    state = c.state()
    check_prepared(state, upstream, authority_id)
    require(c.mesh_root_in_bundle(), 'the SPIRE trust bundle does not hold the mesh root yet; refused')
    c.spire('activate', '-authorityID', authority_id)
    after = c.state()
    require(authority(after, 'active')['id'] == authority_id, 'activation acknowledgment differs')
    c.record('activated', authority=authority(after, 'active'), previous=authority(state, 'active'))


def rotate(c, upstream, propagation, bundle_timeout):
    state = c.state()
    active = authority(state, 'active')
    require(active['id'], 'SPIRE has no active X.509 authority')
    try:
        prepared = check_prepared(state, upstream)
        c.record('prepared-kept', authority=prepared)
    except Refusal:
        prepared = prepare(c, upstream)
    deadline = time.monotonic() + bundle_timeout
    while not c.mesh_root_in_bundle():
        require(time.monotonic() < deadline, f'mesh root not in the SPIRE trust bundle after {bundle_timeout}s')
        time.sleep(2)
    c.record('bundle-has-mesh-root', propagationSeconds=propagation)
    # Agents and workloads that verify with the SPIRE bundle need the new root before SVIDs chain to it.
    time.sleep(propagation)
    activate(c, upstream, prepared['id'])


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--context')
    p.add_argument('--kube-system-uid')
    p.add_argument('--ledger')
    p.add_argument('cluster')
    p.add_argument('command', choices=['show', 'prepare', 'activate', 'rotate', 'taint', 'revoke'])
    p.add_argument('--authority-id')
    p.add_argument('--propagation', type=int, default=60)
    p.add_argument('--bundle-timeout', type=int, default=120)
    a = p.parse_args()
    needs_id = a.command in ('activate', 'taint', 'revoke')
    if needs_id != bool(a.authority_id):
        p.error(f'--authority-id is {"required" if needs_id else "not used"} for {a.command}')
    try:
        c = Cluster(a.cluster, a.context, a.kube_system_uid, a.ledger)
        if a.command == 'show':
            print(json.dumps({slot: authority(c.state(), slot) for slot in ('active', 'prepared', 'old')}, indent=2))
        elif a.command in ('taint', 'revoke'):
            check_old(c.state(), a.authority_id)
            c.spire(a.command, '-authorityID', a.authority_id)
            c.record({'taint': 'tainted', 'revoke': 'revoked'}[a.command], authority=a.authority_id, state=c.state())
        else:
            upstream = c.intermediate()
            if a.command == 'prepare':
                prepare(c, upstream)
            elif a.command == 'activate':
                activate(c, upstream, a.authority_id)
            else:
                rotate(c, upstream, a.propagation, a.bundle_timeout)
    except Refusal as error:
        sys.exit(f'{a.cluster}: refused: {error}')


if __name__ == '__main__':
    main()
