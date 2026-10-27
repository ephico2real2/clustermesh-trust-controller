#!/usr/bin/env python3
"""Renew the SPIRE intermediate issuer approval before it expires (issue #34, LOCAL_ISSUER_PROFILE.md).

The controller accepts an approval for at most 30 days, so a new generation must be published before the current
one expires. This script reads the qualified ledger of publish_issuers.py, and when the approval expires within
--renew-before, runs the same `publish_issuers.py --spire-intermediate --advance` with generation + 1 and every pin
taken from the ledger's identity. The advance re-reads the public evidence, publishes the new generation and moves
the Cilium agent's and the producer's Roles to it; ztunnel accepts it as a successor with its floors carried.

It refuses, and changes nothing, when:
  - the ledger is not a qualified intermediate-mode ledger, or an advance is unfinished;
  - a cluster's <cluster>-spire-intermediate has a new revision since the ledger's evidence. cert-manager then
    has a new intermediate key, and SPIRE's active CA may still be under the old one; publishing only the new
    intermediate would refuse every workload certificate. That move needs its own procedure.

Exit status: 0 renewed or not due; 10 due (with --check); 20 refused; other: the advance failed (its output is kept).
Usage: renew_approval.py --state-dir DIR --kubeconfig FILE [--renew-before SECONDS] [--horizon SECONDS] [--check]
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
PUBLISHER = HERE / 'publish_issuers.py'
MODULES = ['--pki-module', str(LAB / 'pki' / 'pki.py'), '--proof-module', str(LAB / 'spire' / 'public_proof.py'),
           '--publication-module', str(HERE / 'test-issuer-profile.py')]
INTERMEDIATE = 'spire-intermediate'
DAY = 86400


def now():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def log(message, **fields):
    print(json.dumps({'at': now().isoformat(timespec='seconds'), 'message': message, **fields}), flush=True)


def load_ledger(state_dir):
    ledger = json.loads((Path(state_dir) / 'ledger.json').read_text())
    identity = ledger.get('identity', {})
    if ledger.get('success') is not True or ledger.get('advancing') is not None:
        raise SystemExit(log('refused: the ledger is not qualified or an advance is unfinished') or 20)
    if identity.get('issuerMode') != INTERMEDIATE:
        raise SystemExit(log('refused: the ledger is not in SPIRE intermediate mode') or 20)
    if ledger['approval']['generation'] != identity['generation']:
        raise SystemExit(log('refused: the approval and identity generations differ') or 20)
    return ledger


def advance_argv(ledger, args):
    """The advance command for generation + 1, every pin from the ledger identity."""
    i = ledger['identity']
    argv = [args.python, str(PUBLISHER), *MODULES, '--kubeconfig', args.kubeconfig, '--state-dir', args.state_dir,
            '--generation', str(i['generation'] + 1), '--horizon', str(args.horizon), '--image', i['image'],
            '--image-config', i['imageConfig'], '--source-sha', i['sourceRevision'], '--root-sha256', i['rootSHA256'],
            '--spire-intermediate']
    for cluster in sorted(i['clusterPins']):
        argv += ['--cluster-pin', f'{cluster}={i["clusterPins"][cluster]}',
                 '--intermediate-pin', f'{cluster}={i["intermediatePins"][cluster]}',
                 '--deployment-pin', f'{cluster}={i["deploymentPins"][cluster]}']
    for node in sorted(i['nodePins']):
        argv += ['--node-pin', f'{node}={i["nodePins"][node]}']
    return argv + ['--advance']


def intermediate_revisions(ledger, kubeconfig):
    """{cluster: (ledger revision, live revision)} of each cluster's SPIRE intermediate Certificate."""
    out = {}
    for cluster, proof in sorted(ledger['freshProofs'].items()):
        r = subprocess.run(['kubectl', '--kubeconfig', kubeconfig, '--context', 'kind-' + cluster, '-n', 'cert-manager',
                            'get', 'certificate', cluster + '-spire-intermediate', '-o', 'json'],
                           text=True, capture_output=True, timeout=60)
        if r.returncode:
            raise SystemExit(log('refused: cannot read the SPIRE intermediate', cluster=cluster,
                                 error=r.stderr.strip()[:500]) or 20)
        cert = json.loads(r.stdout)
        if cert['metadata']['uid'] != proof['certificateUID']:
            raise SystemExit(log('refused: the SPIRE intermediate Certificate was replaced', cluster=cluster) or 20)
        out[cluster] = (proof['revision'], cert.get('status', {}).get('revision'))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--state-dir', required=True)
    p.add_argument('--kubeconfig', required=True)
    p.add_argument('--renew-before', type=int, default=7 * DAY, help='renew when the approval expires within this')
    # One day under the controller's 30-day limit, for clock skew between this host and the nodes.
    p.add_argument('--horizon', type=int, default=29 * DAY)
    p.add_argument('--python', default=sys.executable, help='a Python with the cryptography package')
    p.add_argument('--check', action='store_true', help='report only; exit 10 when renewal is due')
    args = p.parse_args()
    ledger = load_ledger(args.state_dir)
    generation = ledger['approval']['generation']
    expires = parse_time(ledger['approval']['expiresAt'])
    remaining = (expires - now()).total_seconds()
    due = remaining <= args.renew_before
    log('approval', generation=generation, expiresAt=ledger['approval']['expiresAt'],
        remainingDays=round(remaining / DAY, 2), renewBeforeDays=round(args.renew_before / DAY, 2), due=due)
    if not due:
        return 0
    if args.check:
        return 10
    changed = {c: r for c, r in intermediate_revisions(ledger, args.kubeconfig).items() if r[0] != r[1]}
    if changed:
        log('refused: a SPIRE intermediate has a new revision since the approval evidence; see LOCAL_ISSUER_PROFILE.md',
            revisions={c: {'approved': r[0], 'live': r[1]} for c, r in changed.items()})
        return 20
    argv = advance_argv(ledger, args)
    log('advancing', toGeneration=generation + 1)
    result = subprocess.run(argv, text=True, capture_output=True, timeout=1800)
    for stream, text in (('stdout', result.stdout), ('stderr', result.stderr)):
        if 'PRIVATE KEY' in text:
            text = '(suppressed: private material in output)'
        if text.strip():
            log('advance ' + stream, text=text[-4000:])
    if result.returncode:
        log('advance failed', exit=result.returncode)
        return result.returncode
    after = load_ledger(args.state_dir)['approval']
    if after['generation'] != generation + 1:
        log('advance reported success but the ledger did not move', generation=after['generation'])
        return 1
    log('renewed', generation=after['generation'], expiresAt=after['expiresAt'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
