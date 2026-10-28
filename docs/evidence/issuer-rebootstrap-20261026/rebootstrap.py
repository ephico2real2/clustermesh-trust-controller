#!/usr/bin/env python3
"""One-time ztunnel issuer-checkpoint re-bootstrap onto approval generation 2.

Operator-authorized exception (2026-10-26T00:20Z) to the never-reset rule. SPIRE
activated a new X509 CA at 23:55Z; the generation-1 approval pinned only the old CA,
and the checkpoint origin binds the approval object UID, so no reset-free path exists.

Nothing is deleted. On each node the generation-1 pins and checkpoint files move to
dated `*.g1-preserved-<ts>` directories. Every API write is a JSON-patch CAS with a
UID test. Run per cluster: `rebootstrap.py CLUSTER OUT_DIR`.

Known omission (found at 03:04Z by the matrix): this script does not register the
exact SPIRE delegate entry of each replacement ztunnel Pod. Without it ztunnel gets
no workload certificates. Run register_proxies.py after it.
"""
import datetime as dt
import json
import pathlib
import subprocess
import sys
import time

KUBECONFIG = '/private/tmp/cmtc-a-b-20261024.kubeconfig'
DOCKER = ['docker', '--context', 'colima-cmtc-cilium', 'exec', '-i']
NS = 'cmtc-system'
G1, G2, OUT = 'cmtc-issuer-approval-g1', 'cmtc-issuer-approval-g2', 'cmtc-issuer-publication'
CILIUM_ROLE = 'cilium-ztunnel-issuer-profile'
BOOTSTRAP_ENV = 'ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP'
EXPECTED = {
    'cmtc-a': {'kubeSystem': 'bb7182c7-de95-4e70-816a-a1400d755794', 'ztunnelDS': 'ef360844-5235-4c69-8970-abbf16e78ad0',
               'root': '0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c'},
    'cmtc-b': {'kubeSystem': 'f2687af6-bd96-45a3-98a2-d1397a3ee244', 'ztunnelDS': 'cc87de23-8236-420c-b261-9fcd74bab242',
               'root': '0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c'},
}
AGENT_IMAGE = 'localhost/cilium:dev-overlay-6090aa6eff'
RESTART_AGENT = '/private/tmp/cmtc-opus-final-20261025/review/restart_node_pod.py'
STAMP = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def log(out, msg):
    line = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds') + ' ' + msg
    print(line, flush=True)
    with open(out / 'operations.log', 'a') as f:
        f.write(line + '\n')


def kubectl(cluster, *args, stdin=None):
    r = subprocess.run(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + cluster, *args],
                       input=stdin, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f'kubectl {" ".join(args[:4])} failed: {r.stderr.strip()[-400:]}')
    return r.stdout


def get(cluster, *args):
    return json.loads(kubectl(cluster, *args, '-o', 'json'))


def node_sh(node, script, stdin=''):
    r = subprocess.run(DOCKER + [node, 'sh', '-ec', script], input=stdin, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f'{node}: node step failed ({r.returncode}): {r.stderr.strip()[-400:]}')
    return r.stdout


def cas_patch(cluster, kind, name, namespace, obj, ops):
    full = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']}] + ops
    kubectl(cluster, '-n', namespace, 'patch', kind, name, '--type=json', '-p', json.dumps(full))


def set_bootstrap(cluster, value, out):
    ds = get(cluster, '-n', 'kube-system', 'get', 'ds', 'ztunnel-cilium')
    assert ds['metadata']['uid'] == EXPECTED[cluster]['ztunnelDS'], 'ztunnel DaemonSet replaced'
    assert ds['spec']['updateStrategy']['type'] == 'OnDelete', 'template change would roll Pods'
    env = ds['spec']['template']['spec']['containers'][0]['env']
    [index] = [i for i, e in enumerate(env) if e['name'] == BOOTSTRAP_ENV]
    if env[index].get('value') == value:
        return
    path = f'/spec/template/spec/containers/0/env/{index}'
    cas_patch(cluster, 'ds', 'ztunnel-cilium', 'kube-system', ds,
              [{'op': 'test', 'path': path, 'value': env[index]}, {'op': 'replace', 'path': path + '/value', 'value': value}])
    again = get(cluster, '-n', 'kube-system', 'get', 'ds', 'ztunnel-cilium')
    assert again['spec']['template']['spec']['containers'][0]['env'][index] == {'name': BOOTSTRAP_ENV, 'value': value}
    log(out, f'{cluster}: ztunnel template {BOOTSTRAP_ENV}={value}')


def set_cilium_role(cluster, names, out):
    role = get(cluster, '-n', NS, 'get', 'role', CILIUM_ROLE)
    assert role['metadata'].get('labels', {}).get('app.kubernetes.io/managed-by') == 'cmtc-local-qualification'
    desired = [{'apiGroups': [''], 'resources': ['configmaps'], 'resourceNames': names, 'verbs': ['get']}]
    if role['rules'] == desired:
        return
    cas_patch(cluster, 'role', CILIUM_ROLE, NS, role,
              [{'op': 'test', 'path': '/rules', 'value': role['rules']}, {'op': 'replace', 'path': '/rules', 'value': desired}])
    assert get(cluster, '-n', NS, 'get', 'role', CILIUM_ROLE)['rules'] == desired
    log(out, f'{cluster}: Cilium issuer Role reads {names}')


def current_pins(cluster, node):
    source = get(cluster, '-n', NS, 'get', 'cm', G2)
    output = get(cluster, '-n', NS, 'get', 'cm', OUT)
    p = json.loads(output['data']['profile.json'])
    assert p['state'] == 'published' and p['reason'] == 'Validated' and p['acceptedGeneration'] == 2
    assert p['source']['name'] == G2 and p['source']['uid'] == source['metadata']['uid'] == p['expectedSourceUID']
    assert dt.datetime.fromisoformat(p['validUntil'].replace('Z', '+00:00')) > dt.datetime.now(dt.timezone.utc)
    assert EXPECTED[cluster]['root'] in [r['sha256'] for r in p['approval']['roots']]
    return {'cluster': cluster, 'node': node, 'sourceNamespace': NS, 'sourceName': G2, 'sourceUID': source['metadata']['uid'],
            'outputNamespace': NS, 'outputName': OUT, 'outputUID': output['metadata']['uid'], 'rootPins': [EXPECTED[cluster]['root']],
            'minimumGeneration': str(p['acceptedGeneration']), 'minimumSequence': str(p['sequence']),
            'approvalDigestAtMinimum': p['approvalDigest'], 'publicationDigestAtMinimum': p['digest']}


def node_pins(node):
    return json.loads(node_sh(node, 'cat /etc/cmtc/ztunnel-issuer-pins/pins.json'))


def install_pins(node, pins, out):
    (out / f'pins-{node}.json').write_text(json.dumps(pins, indent=1) + '\n')
    node_sh(node, f'''
P=/etc/cmtc/ztunnel-issuer-pins; K=/etc/cmtc/ztunnel-issuer-pins.g1-preserved-{STAMP}
[ -f "$P/pins.json" ] && [ ! -L "$P/pins.json" ] && [ ! -e "$K" ]
grep -q '"{G1}"' "$P/pins.json"
install -d -m 0755 "$K"; cp -p "$P/pins.json" "$K/pins.json"
(umask 022; cat > "$P/pins.json.next"); chown 0:0 "$P/pins.json.next"; chmod 0644 "$P/pins.json.next"
mv -f "$P/pins.json.next" "$P/pins.json"
grep -q '"{G2}"' "$P/pins.json"
''', stdin=json.dumps(pins))
    log(out, f'{node}: g1 pins preserved in pins.g1-preserved-{STAMP}; g2 pins installed (min sequence {pins["minimumSequence"]})')


def ztunnel_pod(cluster, node):
    pods = get(cluster, '-n', 'kube-system', 'get', 'pods', '-l', 'app=ztunnel-cilium', '--field-selector', 'spec.nodeName=' + node)['items']
    return [p for p in pods if not p['metadata'].get('deletionTimestamp')]


def delete_exact(cluster, pod, out):
    options = out / f'delete-{pod["metadata"]["name"]}.json'
    options.write_text(json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': pod['metadata']['uid']}}))
    kubectl(cluster, 'delete', '--raw', f'/api/v1/namespaces/kube-system/pods/{pod["metadata"]["name"]}', '-f', str(options))
    for _ in range(120):
        live = get(cluster, '-n', 'kube-system', 'get', 'pods', '-l', 'app=ztunnel-cilium')['items']
        if all(p['metadata']['uid'] != pod['metadata']['uid'] for p in live):
            return
        time.sleep(1)
    raise RuntimeError(f'{pod["metadata"]["name"]} did not terminate')


def agent_accepts(cluster, node, out, window=45):
    """The agent verifies the publication against its pins on every ztunnel poll (15 s)."""
    [pod] = get(cluster, '-n', 'kube-system', 'get', 'pods', '-l', 'k8s-app=cilium', '--field-selector', 'spec.nodeName=' + node)['items']
    time.sleep(window)
    lines = [l for l in kubectl(cluster, '-n', 'kube-system', 'logs', pod['metadata']['name'], '-c', 'cilium-agent',
                                f'--since={window}s').splitlines() if 'Issuer-profile' in l]
    (out / f'agent-issuer-log-{node}.txt').write_text('\n'.join(lines) + '\n')
    refused = [l for l in lines if 'API observation unavailable' in l]
    log(out, f'{node}: agent issuer-profile lines in {window}s: {len(lines)}, own verification failures: {len(refused)}')
    return bool(lines) and not refused


def checkpoint_files(node):
    return node_sh(node, 'ls -A /var/lib/cmtc/ztunnel-issuer-checkpoint').split()


def wait_ready(cluster, node, image, timeout=480):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pods = ztunnel_pod(cluster, node)
        if len(pods) == 1:
            p = pods[0]
            cs = p.get('status', {}).get('containerStatuses', [])
            if p['spec']['containers'][0]['image'] == image and cs and all(c.get('ready') for c in cs):
                return p
        time.sleep(2)
    raise RuntimeError(f'{node}: ztunnel not Ready within {timeout}s')


def checkpoint(node):
    raw = node_sh(node, 'cat /var/lib/cmtc/ztunnel-issuer-checkpoint/profile-state.json')
    state = json.loads(raw)['state']
    return {'sourceUID': state['origin']['source_uid'], 'sourceName': state['origin']['source_name'],
            'generation': state['floors']['logical_generation'], 'sequence': state['floors']['sequence'],
            'observation': state['observation']}


def pod_mode(pod):
    env = {e['name']: e.get('value') for e in pod['spec']['containers'][0]['env']}
    return env[BOOTSTRAP_ENV]


def rebootstrap_node(cluster, node, image, out):
    """Each step checks the live state first, so a stopped run resumes without repeating a step."""
    pins = current_pins(cluster, node)
    if node_pins(node)['sourceName'] == G2:
        log(out, f'{node}: g2 pins already installed')
    else:
        install_pins(node, pins, out)
    pins = node_pins(node)
    files = checkpoint_files(node)
    if 'profile-state.json' in files and checkpoint(node)['sourceName'] == G2:
        log(out, f'{node}: checkpoint already bootstrapped from g2: {checkpoint(node)}')
        return
    if '.profile-state.initialized' in files and 'profile-state.json' not in files:
        raise RuntimeError(f'{node}: marker without state ({files}); stop, this needs the operator')
    if not agent_accepts(cluster, node, out, window=20):
        r = subprocess.run([sys.executable, RESTART_AGENT, cluster, 'kube-system', 'k8s-app=cilium', 'cilium', node, AGENT_IMAGE, str(out)],
                           capture_output=True, text=True)
        (out / f'agent-restart-{node}.txt').write_text(r.stdout + r.stderr)
        if r.returncode:
            raise RuntimeError(f'{node}: agent restart failed: {r.stderr.strip()[-400:]}')
        log(out, f'{node}: Cilium agent replaced and Ready on {AGENT_IMAGE}')
        if not agent_accepts(cluster, node, out):
            raise RuntimeError(f'{node}: agent does not accept the g2 publication; ztunnel not touched')
    if 'profile-state.json' in files:
        # Stop the process that holds the g1 state. Its replacement runs in bootstrap
        # mode and exits at open while any g1 file is present (state.rs ProfileProvider::open).
        for old in ztunnel_pod(cluster, node):
            if pod_mode(old) == 'false':
                (out / f'ztunnel-old-{node}.json').write_text(json.dumps(old, indent=1))
                delete_exact(cluster, old, out)
                log(out, f'{node}: ztunnel {old["metadata"]["name"]} (existing-checkpoint mode) terminated')
        moved = node_sh(node, f'''
C=/var/lib/cmtc/ztunnel-issuer-checkpoint; K=/var/lib/cmtc/ztunnel-issuer-checkpoint.g1-preserved-{STAMP}
[ -d "$C" ] && [ ! -L "$C" ] && [ ! -e "$K" ]
grep -q '"{G1}"' "$C/profile-state.json"
install -d -m 0700 "$K"
for f in .profile-state.initialized profile-state.json .profile-state.pending; do
  if [ -e "$C/$f" ]; then mv "$C/$f" "$K/$f"; echo "moved $f"; fi
done
left=$(ls -A "$C")
[ -z "$left" ] || [ "$left" = .profile-state.lock ]
echo "left: ${{left:-<empty>}}"
''')
        log(out, f'{node}: g1 checkpoint preserved in checkpoint.g1-preserved-{STAMP}: ' + moved.strip().replace('\n', '; '))
    # Never delete the bootstrap-mode Pod here: once it writes the marker, a kill before
    # its first state commit leaves a store that neither open mode accepts. The kubelet
    # restarts the exited container in place (back-off at most 300 s).
    ready = wait_ready(cluster, node, image)
    for _ in range(60):
        if 'profile-state.json' in checkpoint_files(node):
            break
        time.sleep(2)
    cp = checkpoint(node)
    assert cp['sourceUID'] == pins['sourceUID'] and cp['generation'] == 2, cp
    log(out, f'{node}: ztunnel {ready["metadata"]["name"]} Ready; checkpoint {cp}')


def restart_from_checkpoint(cluster, node, image, out):
    before = checkpoint(node)
    [p] = ztunnel_pod(cluster, node)
    delete_exact(cluster, p, out)
    ready = wait_ready(cluster, node, image)
    env = {e['name']: e.get('value') for e in ready['spec']['containers'][0]['env']}
    assert env[BOOTSTRAP_ENV] == 'false', env[BOOTSTRAP_ENV]
    time.sleep(10)
    after = checkpoint(node)
    assert after['sourceUID'] == before['sourceUID'] and after['sequence'] >= before['sequence'], (before, after)
    log(out, f'{node}: restart from existing checkpoint Ready ({ready["metadata"]["name"]}); sequence {before["sequence"]} -> {after["sequence"]}')


def main():
    cluster, out = sys.argv[1], pathlib.Path(sys.argv[2])
    assert cluster in EXPECTED
    out.mkdir(parents=True, exist_ok=True)
    assert get(cluster, 'get', 'ns', 'kube-system')['metadata']['uid'] == EXPECTED[cluster]['kubeSystem'], 'wrong cluster'
    image = get(cluster, '-n', 'kube-system', 'get', 'ds', 'ztunnel-cilium')['spec']['template']['spec']['containers'][0]['image']
    nodes = [cluster + '-worker', cluster + '-control-plane']
    set_cilium_role(cluster, [G1, G2, OUT], out)
    set_bootstrap(cluster, 'true', out)
    for node in nodes:
        rebootstrap_node(cluster, node, image, out)
    set_bootstrap(cluster, 'false', out)
    for node in nodes:
        restart_from_checkpoint(cluster, node, image, out)
    set_cilium_role(cluster, [G2, OUT], out)
    log(out, f'{cluster}: re-bootstrap complete')


if __name__ == '__main__':
    main()
