#!/usr/bin/env python3
"""Replace the node ztunnel Pods of one kind cluster, one node at a time, after Helm set the new image.

The ztunnel DaemonSet is OnDelete: `scripts/lab/cilium_adopt.py upgrade` changes its template and no Pod. This tool
replaces each Pod (worker first) and gives the new Pod its exact SPIRE delegate entry, bound to the new Pod UID:
SPIRE authorizes ztunnel's Delegated Identity calls only through that entry, so without it ztunnel gets no workload
certificates. A node is done only when the new Pod is Ready, runs the image digest the template names, and logged a
durable issuer-profile commit; then the replaced Pod's delegate entry is deleted. Checkpoints, pins and bootstrap
markers are never touched, and the template is never patched (Helm owns it).

Refuses unless kube-system has the cluster's pinned UID, the DaemonSet is OnDelete with the istio-proxy container and
hostPID, and its template image is exactly --image (a digest reference).

Usage: replace_ztunnel.py --kubeconfig K --cluster cmtc-b --image ghcr.io/...@sha256:... --ledger L [--node N]
"""
import argparse
import json
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

KUBE_SYSTEM_UID = {'cmtc-a': 'bb7182c7-de95-4e70-816a-a1400d755794', 'cmtc-b': 'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
SPIRE_CLI = ['-n', 'cilium-spire', 'exec', 'spire-server-0', '-c', 'register-agent-node', '--',
             '/bin/timeout', '-s', 'KILL', '12', '/spire-cli/opt/spire/bin/spire-server']
SPIRE_SOCKET = ['-socketPath', '/tmp/spire-server/private/api.sock']
DURABLE_COMMIT = 'native profile durably committed before ACK'
DIGEST_REF = re.compile(r'[a-z0-9./-]+@sha256:[0-9a-f]{64}')


def delegate_entry(cluster: str, pod: dict) -> tuple[str, list[str], list[str]]:
    """The entry ID, `spire-server entry create` arguments and selectors for one ztunnel Pod.

    The ID scheme is the one every lab delegate entry has used since 2026-10-25, so a rerun is idempotent and the
    entry of a replaced Pod can be found again from its UID.
    """
    m, s = pod['metadata'], pod['spec']
    selectors = ['k8s:ns:kube-system', 'k8s:sa:' + s['serviceAccountName'], 'k8s:pod-uid:' + m['uid'],
                 'k8s:node-name:' + s['nodeName']]
    entry_id = entry_id_for(cluster, m['uid'])
    args = ['entry', 'create', '-entryID', entry_id,
            '-parentID', f'spiffe://{cluster}.mesh.example/ns/cilium-spire/sa/spire-agent',
            '-spiffeID', f'spiffe://{cluster}.mesh.example/ztunnel-proxy', '-x509SVIDTTL', '120']
    for sel in selectors:
        args += ['-selector', sel]
    return entry_id, args, selectors


def entry_id_for(cluster: str, pod_uid: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'cmtc-live-activation:{cluster}:{pod_uid}'))


def check_template(ds: dict, image: str) -> None:
    """Raises ValueError unless the DaemonSet is the OnDelete ztunnel template naming exactly `image`."""
    spec = ds['spec']
    pod = spec['template']['spec']
    container = pod['containers'][0]
    if spec['updateStrategy']['type'] != 'OnDelete' or container['name'] != 'istio-proxy':
        raise ValueError('unexpected DaemonSet shape: want OnDelete with container istio-proxy')
    if not pod.get('hostPID'):
        raise ValueError('hostPID missing from the template')
    if container['image'] != image:
        raise ValueError(f'template image is {container["image"]}, not {image}; run cilium_adopt.py upgrade first')


def runs_image(pod: dict, image: str) -> bool:
    """Whether the Pod's first container runs the digest `image` names (status imageID, as the kubelet reports it)."""
    statuses = pod['status'].get('containerStatuses') or []
    return bool(statuses) and statuses[0].get('imageID', '').endswith('@' + image.split('@', 1)[1])


def node_order(nodes: list[str]) -> list[str]:
    """Workers first: the control-plane node also carries the API server's path."""
    return sorted(nodes, key=lambda n: (0 if '-worker' in n else 1, n))


class Cluster:
    def __init__(self, kubeconfig: str, name: str, ledger: Path):
        self.name, self.ledger = name, ledger
        self.base = ['kubectl', '--kubeconfig', kubeconfig, '--context', 'kind-' + name]

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        r = subprocess.run(self.base + list(args), text=True, capture_output=True, timeout=180)
        if 'PRIVATE KEY' in r.stdout + r.stderr:
            raise SystemExit('private key material in kubectl output; aborting')
        if check and r.returncode:
            raise SystemExit(f'{self.name}: kubectl {" ".join(args[:4])} failed: {r.stderr[:2000]}')
        return r

    def get(self, *args: str) -> dict:
        return json.loads(self.run(*args, '-o', 'json').stdout)

    def spire(self, *args: str) -> subprocess.CompletedProcess:
        return self.run(*SPIRE_CLI, *args, *SPIRE_SOCKET, check=False)

    def proxies(self) -> list[dict]:
        return self.get('-n', 'kube-system', 'get', 'pods', '-l', 'app=ztunnel-cilium')['items']

    def record(self, event: dict) -> None:
        event['at'] = datetime.now(timezone.utc).isoformat()
        with self.ledger.open('a') as f:
            f.write(json.dumps(event) + '\n')
        print(json.dumps(event), flush=True)


def show_entry(c: Cluster, entry_id: str) -> list[dict]:
    r = c.spire('entry', 'show', '-entryID', entry_id, '-output', 'json')
    if r.returncode:
        return []
    return json.loads(r.stdout).get('entries') or []


def register_delegate(c: Cluster, pod: dict) -> None:
    entry_id, args, selectors = delegate_entry(c.name, pod)
    r = c.spire(*args)
    if r.returncode and 'AlreadyExists' not in r.stdout + r.stderr:
        raise SystemExit(f'{c.name}: delegate entry create failed: {r.stderr[:1500]}{r.stdout[:1500]}')
    entries = show_entry(c, entry_id)
    if len(entries) != 1 or sorted(x['type'] + ':' + x['value'] for x in entries[0]['selectors']) != sorted(selectors):
        raise SystemExit(f'{c.name}: delegate entry readback mismatch for {entry_id}')
    c.record({'event': 'delegate-registered', 'cluster': c.name, 'pod': pod['metadata']['name'],
              'podUID': pod['metadata']['uid'], 'node': pod['spec']['nodeName'], 'entryID': entry_id,
              'selectors': selectors})


def delete_delegate(c: Cluster, pod_uid: str) -> None:
    """Deletes the replaced Pod's delegate entry, after checking it is bound to that Pod UID only."""
    entry_id = entry_id_for(c.name, pod_uid)
    entries = show_entry(c, entry_id)
    if not entries:
        c.record({'event': 'delegate-absent', 'cluster': c.name, 'podUID': pod_uid, 'entryID': entry_id})
        return
    if 'pod-uid:' + pod_uid not in [x['value'] for x in entries[0]['selectors']]:
        raise SystemExit(f'{c.name}: entry {entry_id} is not bound to Pod UID {pod_uid}; not deleting it')
    r = c.spire('entry', 'delete', '-entryID', entry_id)
    if r.returncode or show_entry(c, entry_id):
        raise SystemExit(f'{c.name}: delegate entry delete failed for {entry_id}: {r.stderr[:1500]}')
    c.record({'event': 'delegate-deleted', 'cluster': c.name, 'podUID': pod_uid, 'entryID': entry_id})


def replace_node(c: Cluster, node: str, image: str, timeout: int) -> None:
    pods = [p for p in c.proxies() if p['spec'].get('nodeName') == node]
    if len(pods) != 1:
        raise SystemExit(f'{c.name}: expected one ztunnel Pod on {node}, found {len(pods)}')
    old = pods[0]
    old_uid = old['metadata']['uid']
    c.run('-n', 'kube-system', 'delete', 'pod', old['metadata']['name'], '--wait=true', '--timeout=120s')
    c.record({'event': 'proxy-deleted', 'cluster': c.name, 'node': node, 'pod': old['metadata']['name'],
              'podUID': old_uid})
    deadline = time.time() + timeout
    new = None
    while new is None and time.time() < deadline:
        new = next((p for p in c.proxies() if p['spec'].get('nodeName') == node and p['metadata']['uid'] != old_uid),
                   None)
        if new is None:
            time.sleep(1)
    if new is None:
        raise SystemExit(f'{c.name}: no replacement ztunnel Pod on {node} within {timeout}s')
    register_delegate(c, new)
    name = new['metadata']['name']
    while True:
        pod = c.get('-n', 'kube-system', 'get', 'pod', name)
        if any(x['type'] == 'Ready' and x['status'] == 'True' for x in pod['status'].get('conditions', [])):
            break
        if time.time() > deadline:
            logs = c.run('-n', 'kube-system', 'logs', name, '--tail=60', check=False).stdout
            raise SystemExit(f'{c.name}: {name} not Ready within {timeout}s; last logs:\n{logs[-4000:]}')
        time.sleep(2)
    if not runs_image(pod, image):
        raise SystemExit(f'{c.name}: {name} runs {pod["status"]["containerStatuses"][0].get("imageID")}, not {image}')
    while DURABLE_COMMIT not in c.run('-n', 'kube-system', 'logs', name, check=False).stdout:
        if time.time() > deadline:
            raise SystemExit(f'{c.name}: {name} logged no durable issuer-profile commit within {timeout}s')
        time.sleep(2)
    c.record({'event': 'proxy-ready', 'cluster': c.name, 'node': node, 'pod': name, 'podUID': new['metadata']['uid'],
              'imageID': pod['status']['containerStatuses'][0]['imageID'], 'durableProfileCommit': True})
    delete_delegate(c, old_uid)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--kubeconfig', required=True)
    ap.add_argument('--cluster', choices=KUBE_SYSTEM_UID, required=True)
    ap.add_argument('--image', required=True, help='the digest reference the DaemonSet template names')
    ap.add_argument('--ledger', required=True, help='JSON-lines file; one line is appended per step')
    ap.add_argument('--node', help="replace only this node's ztunnel Pod")
    ap.add_argument('--timeout', type=int, default=240, help='seconds per node')
    a = ap.parse_args()
    if not DIGEST_REF.fullmatch(a.image):
        raise SystemExit('--image must be a digest reference: <repository>@sha256:<64 hex>')
    c = Cluster(a.kubeconfig, a.cluster, Path(a.ledger))
    if c.get('get', 'ns', 'kube-system')['metadata']['uid'] != KUBE_SYSTEM_UID[a.cluster]:
        raise SystemExit('kube-system UID mismatch; refusing to change anything')
    try:
        check_template(c.get('-n', 'kube-system', 'get', 'ds', 'ztunnel-cilium'), a.image)
    except ValueError as e:
        raise SystemExit(f'{a.cluster}: {e}')
    nodes = sorted(p['spec']['nodeName'] for p in c.proxies())
    if a.node:
        if a.node not in nodes:
            raise SystemExit(f'{a.cluster}: no ztunnel Pod on node {a.node}; they run on {nodes}')
        nodes = [a.node]
    for node in node_order(nodes):
        replace_node(c, node, a.image, a.timeout)
    c.record({'event': 'nodes-replaced', 'cluster': a.cluster, 'image': a.image, 'nodes': node_order(nodes)})


if __name__ == '__main__':
    main()
