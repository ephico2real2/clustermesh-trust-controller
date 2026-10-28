#!/usr/bin/env python3
"""Give each running ztunnel Pod its exact SPIRE delegate entry.

rebootstrap.py replaced every ztunnel Pod but did not register the new Pods. SPIRE's
DelegatedIdentity API then refuses the caller (`No identity issued` with the ztunnel
Pod's own selectors), so ztunnel has no workload certificates. This step reuses
`register_delegate` from the rollout tool, which binds the entry to the Pod UID.
Entries of deleted Pods are kept; their pod-uid selector matches no Pod.

Usage: register_proxies.py LEDGER
"""
import json
import pathlib
import sys
import uuid

sys.path.insert(0, '/private/tmp/cmtc-opus-final-20261025/review')
from rollout_ztunnel import PINS, Cluster, register_delegate  # noqa: E402


def main():
    ledger = pathlib.Path(sys.argv[1])
    for name in ('cmtc-a', 'cmtc-b'):
        c = Cluster(name, ledger)
        assert c.get('get', 'ns', 'kube-system')['metadata']['uid'] == PINS[name], 'wrong cluster'
        for pod in c.get('-n', 'kube-system', 'get', 'pods', '-l', 'app=ztunnel-cilium')['items']:
            if pod['metadata'].get('deletionTimestamp'):
                continue
            entry_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'cmtc-live-activation:' + name + ':' + pod['metadata']['uid']))
            shown = c.spire('entry', 'show', '-entryID', entry_id, '-output', 'json')
            if shown.returncode == 0 and json.loads(shown.stdout).get('entries'):
                c.record({'event': 'delegate-present', 'cluster': name, 'pod': pod['metadata']['name'], 'entryID': entry_id})
                continue
            register_delegate(c, pod)


if __name__ == '__main__':
    main()
