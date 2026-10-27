#!/usr/bin/env python3
"""Retire one root pin from one kind node's ztunnel issuer pins, keeping every other field (administrator step).

The pins file is the administrator's authority, outside the Kubernetes API: the Cilium agent and ztunnel read it at
startup, and the CMTC node agent never creates it or removes a pin. ztunnel from fork commit `feat/root-pin-retirement`
on continues its checkpoint when a root pin is retired, if the recovered approval still chains to a remaining pin;
an older ztunnel refuses the checkpoint at its next start, so the ztunnel image moves first.

Refuses unless kube-system has the cluster's pinned UID, the pins file is root-owned 0644 with one link and the
expected fields and identity, the retired pin is present, and at least one other pin remains. The old file is kept on
the node outside the pins directory (never overwritten) and in the evidence directory; the new file is written to a
temporary name in the same directory and renamed over pins.json, so a reader sees the old or the new file.

Usage: retire_root_pin.py --cluster cmtc-b --node cmtc-b-worker --retire SHA256 --keep NAME --evidence DIR
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

KUBECONFIG = '/private/tmp/cmtc-a-b-20261024.kubeconfig'
KUBE_SYSTEM_UID = {'cmtc-a': 'bb7182c7-de95-4e70-816a-a1400d755794', 'cmtc-b': 'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
FIELDS = {'cluster', 'node', 'sourceNamespace', 'sourceName', 'sourceUID', 'outputNamespace', 'outputName', 'outputUID',
          'rootPins', 'minimumGeneration', 'minimumSequence', 'approvalDigestAtMinimum', 'publicationDigestAtMinimum'}
DIR = '/etc/cmtc/ztunnel-issuer-pins'


def node_sh(node: str, script: str, body: str | None = None) -> str:
    r = subprocess.run(['docker', 'exec', '-i', node, 'sh', '-ec', script], input=body, text=True,
                       capture_output=True, timeout=60)
    if r.returncode:
        sys.exit(f'{node}: node command failed ({r.returncode}): {r.stderr.strip()[:800]}')
    return r.stdout


def retired(pins: dict, pin: str) -> dict:
    """pins without pin; refuses an absent pin or the last one."""
    roots = pins['rootPins']
    if pin not in roots:
        raise ValueError(f'{pin} is not pinned: {roots}')
    remaining = [p for p in roots if p != pin]
    if not remaining:
        raise ValueError('refusing to retire the last root pin')
    return dict(pins, rootPins=sorted(remaining))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cluster', choices=KUBE_SYSTEM_UID, required=True)
    ap.add_argument('--node', required=True)
    ap.add_argument('--retire', required=True, help='SHA-256 of the root certificate to retire, 64 lowercase hex')
    ap.add_argument('--keep', required=True, help='file name under /etc/cmtc for the old pins file, e.g. '
                                                    'ztunnel-issuer-pins-before-root-retirement.json')
    ap.add_argument('--evidence', required=True)
    a = ap.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', a.retire) or not re.fullmatch(r'[A-Za-z0-9._-]+\.json', a.keep):
        sys.exit('--retire must be 64 lowercase hex characters and --keep a plain .json file name')
    uid = subprocess.run(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + a.cluster, 'get', 'ns',
                          'kube-system', '-o', 'jsonpath={.metadata.uid}'], text=True, capture_output=True,
                         timeout=30).stdout
    if uid != KUBE_SYSTEM_UID[a.cluster] or not a.node.startswith(a.cluster + '-'):
        sys.exit('kube-system UID or node/cluster mismatch')
    keep = f'/etc/cmtc/{a.keep}'
    raw = node_sh(a.node, f'stat -c "%u:%g %a %h" {DIR}/pins.json; cat {DIR}/pins.json')
    meta, _, body = raw.partition('\n')
    if meta != '0:0 644 1':
        sys.exit(f'{a.node}: unexpected owner/mode/links {meta!r}')
    old = json.loads(body)
    if set(old) != FIELDS or old['cluster'] != a.cluster or old['node'] != a.node:
        sys.exit(f'{a.node}: unexpected pins shape or identity')
    ev = Path(a.evidence)
    ev.mkdir(parents=True, exist_ok=True)
    if a.retire not in old['rootPins']:
        (ev / f'{a.node}-pins-after.json').write_text(body)
        print(json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'event': 'already-retired',
                          'cluster': a.cluster, 'node': a.node, 'rootPins': old['rootPins']}))
        return
    try:
        new = retired(old, a.retire)
    except ValueError as e:
        sys.exit(f'{a.node}: {e}')
    (ev / f'{a.node}-pins-before.json').write_text(body)
    # set -C: never overwrite an existing kept copy or temporary file. pins.json has no final newline.
    node_sh(a.node, f'set -C; cat {DIR}/pins.json > {keep}; chmod 0644 {keep}; umask 022; '
                    f'cat > {DIR}/.pins.json.retire; chown 0:0 {DIR}/.pins.json.retire; '
                    f'chmod 0644 {DIR}/.pins.json.retire; mv -f {DIR}/.pins.json.retire {DIR}/pins.json',
            json.dumps(new))
    after = node_sh(a.node, f'stat -c "%u:%g %a" {DIR}/pins.json; cat {DIR}/pins.json; echo; ls -A {DIR}')
    meta, body_after, listing = after.split('\n', 2)
    if meta != '0:0 644' or json.loads(body_after) != new or listing.split() != ['pins.json']:
        sys.exit(f'{a.node}: readback differs: {meta!r} {listing.split()}')
    (ev / f'{a.node}-pins-after.json').write_text(body_after)
    print(json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'event': 'root-pin-retired', 'cluster': a.cluster,
                      'node': a.node, 'retired': a.retire, 'rootPins': new['rootPins'], 'kept': keep}))


if __name__ == '__main__':
    main()
