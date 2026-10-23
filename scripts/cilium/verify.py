#!/usr/bin/env python3
"""Require the pinned image specifications, ready binaries and runtime image IDs."""
import json
import pathlib
import subprocess

root = pathlib.Path('artifacts')
lock = json.loads((root/'cilium-images.lock.json').read_text())
checks = [('agent', 'ds/cilium', 'k8s-app=cilium', 'cilium-agent'),
          ('operator-generic', 'deployment/cilium-operator', 'name=cilium-operator', 'cilium-operator'),
          ('clustermesh-apiserver', 'deployment/clustermesh-apiserver', 'k8s-app=clustermesh-apiserver', 'apiserver')]
results = []
for cluster in ('cmtc-a', 'cmtc-b'):
    base = ['kubectl', '--context', 'kind-'+cluster, '-n', 'kube-system']
    components = {}
    for role, workload, selector, container in checks:
        subprocess.run(base+['rollout', 'status', workload, '--timeout=5m'], check=True)
        pods = json.loads(subprocess.check_output(base+['get', 'pods', '-l', selector, '-o', 'json']))['items']
        assert pods, (cluster, role, 'no pods')
        rows = []
        for pod in pods:
            if pod['metadata'].get('deletionTimestamp'):
                continue
            containers = pod['spec']['containers']
            if role != 'clustermesh-apiserver':
                containers = [c for c in containers if c['name'] == container]
            assert containers, (cluster, role, 'missing containers')
            for spec in containers:
                expected = lock['images'][role]['image']
                assert spec['image'] == expected, (cluster, role, spec['image'], expected)
                status = next(c for c in pod['status']['containerStatuses'] if c['name'] == spec['name'])
                assert status['ready'] and 'sha256:' in status['imageID'], (cluster, role, status)
                rows.append({'pod': pod['metadata']['name'], 'container': spec['name'], 'image': spec['image'], 'imageID': status['imageID']})
                if role == 'agent':
                    version = subprocess.check_output(base+['exec', pod['metadata']['name'], '-c', container, '--', 'cilium-dbg', 'version'], text=True)
                    assert lock['source_sha'][:8] in version, (cluster, version)
                    rows[-1]['version'] = version.strip()
        assert rows, (cluster, role, 'no current pods')
        components[role] = rows
    results.append({'cluster': cluster, 'source_sha': lock['source_sha'], 'components': components})
(root/'cilium-image-verification.json').write_text(json.dumps(results, indent=2)+'\n')
print('PASS: both clusters run the pinned fork components and exact agent source version')
