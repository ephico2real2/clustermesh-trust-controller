#!/usr/bin/env python3
"""Qualify authenticated-only TCP in the isolated CMTC fixture; retain all results."""
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kubeconfig', required=True)
parser.add_argument('--source', required=True, help='Exact deployed Cilium agent source SHA')
parser.add_argument('--proxy-source', help='Exact strict-profile proxy SHA; verify both nodes through their admin API')
parser.add_argument('--expect-dynamic-mtls', choices=['present', 'absent'], default='present',
                    help='Require the native dynamic rule, or prove the proxy works with an empty policy cache')
parser.add_argument('--out', default='artifacts/mtls-spike/authenticated-only')
parser.add_argument('--restart-tests', action='store_true')
args = parser.parse_args()
if not re.fullmatch('[0-9a-f]{40}', args.source):
    parser.error('--source must be an exact commit SHA')
if args.proxy_source and not re.fullmatch('[0-9a-f]{40}', args.proxy_source):
    parser.error('--proxy-source must be an exact commit SHA')
if args.expect_dynamic_mtls == 'absent' and not args.proxy_source:
    parser.error('An absent-policy trial requires --proxy-source and its immutable authentication floor')
out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
if (out / 'commands.ndjson').exists():
    parser.error('Use a fresh output directory; prior evidence will not be overwritten')
kube = ['kubectl', '--kubeconfig', args.kubeconfig]
lock = threading.Lock()
owned = []
summary = {'source': args.source, 'proxySource': args.proxy_source, 'expectedDynamicMtls': args.expect_dynamic_mtls, 'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'stages': [], 'restartTrials': [], 'fullFailClosedProtection': False}
fixture_id = str(uuid.uuid4())
fixture_verified = False

def emit(message):
    with lock:
        print(message, flush=True)
        with (out / 'check.txt').open('a') as stream:
            stream.write(message + '\n')

def command(cmd, stdin=None, check=True, timeout=45):
    start = time.monotonic()
    try:
        result = subprocess.run(cmd, input=stdin, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'argv': cmd, 'exitCode': None, 'elapsedSeconds': time.monotonic() - start, 'timeoutSeconds': timeout, 'error': str(error)}
        with lock:
            with (out / 'commands.ndjson').open('a') as stream:
                stream.write(json.dumps(record) + '\n')
        raise
    record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'argv': cmd, 'exitCode': result.returncode, 'elapsedSeconds': time.monotonic() - start, 'stdout': result.stdout, 'stderr': result.stderr}
    with lock:
        with (out / 'commands.ndjson').open('a') as stream:
            stream.write(json.dumps(record) + '\n')
    if check and result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}): {cmd}: {result.stderr}')
    return result

def kubectl(*cmd, **kwargs):
    return command(kube + list(cmd), **kwargs)

def get_json(*cmd):
    return json.loads(kubectl(*cmd, '-o', 'json').stdout)

def save_summary():
    (out / 'results.json').write_text(json.dumps(summary, indent=2) + '\n')

def create(kind, name, namespace, spec):
    previous = kubectl('-n', namespace, 'get', kind, name, '--ignore-not-found', '-o', 'name')
    if previous.stdout.strip():
        raise RuntimeError(f'Refusing to replace {kind}/{namespace}/{name}')
    spec['metadata'] = {'name': name, 'namespace': namespace, **spec.get('metadata', {})}
    spec['metadata'].setdefault('annotations', {})['security.cmtc.io/fixture-id'] = fixture_id
    kubectl('apply', '-f', '-', stdin=json.dumps(spec))
    owned.append((kind, name, namespace))
    (out / f'{kind}-{name}.json').write_text(json.dumps(spec, indent=2) + '\n')

ports = [80, 8080, 9443]

def check_proxy_state(stage):
    if not args.proxy_source:
        return
    observed = []
    for node in ['cmtc-mtls-control-plane', 'cmtc-mtls-worker']:
        dump = json.loads(command(['docker', 'exec', node, 'curl', '--fail', '--silent', '--show-error',
                                  '--max-time', '5', 'http://127.0.0.1:15000/config_dump']).stdout)
        if dump['version']['gitRevision'] != args.proxy_source or dump['version']['buildStatus'] != 'Clean':
            raise RuntimeError(f'{node}: unexpected proxy source/build status')
        if dump['config'].get('requireInboundMtls') is not True:
            raise RuntimeError(f'{node}: immutable inbound authentication is not enabled')
        policies = dump['policies']
        if args.expect_dynamic_mtls == 'absent':
            if policies or dump['staticConfig']['policies']:
                raise RuntimeError(f'{node}: policy cache is not empty during absent-policy trial')
        elif not any(p['name'] == 'cilium_require_mtls' and p['action'] == 'Deny' for p in policies):
            raise RuntimeError(f'{node}: expected dynamic authentication rule is missing')
        observed.append({'node': node, 'version': dump['version'], 'requireInboundMtls': True,
                         'policies': policies, 'staticPolicies': dump['staticConfig']['policies'],
                         'workloadState': dump['workloadState']})
    (out / f'proxy-state-{stage}.json').write_text(json.dumps(observed, indent=2) + '\n')
    emit(f'PASS {stage}: exact strict proxy source on both nodes; dynamic policy={args.expect_dynamic_mtls}')

def run_probe(case):
    if 'node' in case:
        result = command(['docker', 'exec', case['node'], 'curl', '--include', '--silent', '--show-error', '--max-time', '2', case['url']], check=False, timeout=8)
    else:
        result = kubectl('-n', case['namespace'], 'exec', case['pod'], '--', 'wget', '-T', '2', '-S', '-O', '-', case['url'], check=False)
    text = result.stdout + result.stderr
    status = re.findall(r'HTTP/\S+\s+(\d{3})', text)
    success = result.returncode == 0 and '200' in status and 'CMTC-authenticated-only' in text
    rejected = result.returncode != 0 and not status and 'CMTC-authenticated-only' not in text
    return {**case, 'exitCode': result.returncode, 'httpStatus': status, 'success': success, 'rejected': rejected, 'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}

def check_stage(name, cases):
    check_proxy_state(name + '-before')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        observations = list(pool.map(run_probe, cases))
    failed = []
    for result in observations:
        passed = result['success'] if result['enrolled'] else result['rejected']
        emit(f"{'PASS' if passed else 'FAIL'} {name}: {'ALLOW mTLS' if result['enrolled'] else 'DENY unauthenticated'} {result['case']} port={result['port']} HTTP={','.join(result['httpStatus']) or 'none'} exit={result['exitCode']}")
        if not passed:
            failed.append(result)
    summary['stages'].append({'name': name, 'observations': observations, 'passed': not failed})
    save_summary()
    if failed:
        raise RuntimeError(f'{name}: {len(failed)} unexpected traffic results')
    check_proxy_state(name + '-after')

try:
    current = kubectl('config', 'current-context').stdout.strip()
    if current != 'kind-cmtc-mtls':
        raise RuntimeError(f'Refusing non-fixture context {current}')
    fixture_verified = True
    config = get_json('-n', 'kube-system', 'get', 'cm', 'cilium-config')['data']
    expected_flag = 'true' if args.expect_dynamic_mtls == 'present' else 'false'
    if config.get('ztunnel-require-mtls') != expected_flag:
        raise RuntimeError(f'Expected agent ztunnel-require-mtls={expected_flag}')
    if get_json('get', 'ns', 'mtls-spike')['metadata'].get('labels', {}).get('io.cilium/mtls-enabled') != 'true':
        raise RuntimeError('The isolated fixture namespace is not enrolled')
    for namespace in ['mtls-spike', 'mtls-plaintext-control']:
        for kind in ['cnp', 'networkpolicy']:
            if get_json('-n', namespace, 'get', kind)['items']:
                raise RuntimeError(f'Network policy would confound the experiment: {namespace}/{kind}')
    if get_json('get', 'ccnp')['items']:
        raise RuntimeError('CCNP would confound the experiment')
    agents = get_json('-n', 'kube-system', 'get', 'pods', '-l', 'k8s-app=cilium')['items']
    images = []
    for pod in agents:
        version = kubectl('-n', 'kube-system', 'exec', pod['metadata']['name'], '--', '/usr/bin/cilium-agent', '--version').stdout.strip()
        if args.source[:10] not in version:
            raise RuntimeError(f"Unexpected agent version: {pod['metadata']['name']}: {version}")
        images.append({'pod': pod['metadata']['name'], 'node': pod['spec']['nodeName'], 'version': version, 'images': pod['status'].get('containerStatuses', [])})
    (out / 'agent-image-versions.json').write_text(json.dumps(images, indent=2) + '\n')
    check_proxy_state('preflight')
    emit(f'PASS preflight: context={current}, exact agent source={args.source}, dynamic authenticated-only={expected_flag}, no CNP/CCNP/KNP')
    create('cm', 'auth-only-nginx', 'mtls-spike', {'apiVersion': 'v1', 'kind': 'ConfigMap', 'data': {'nginx.conf': 'events {}\nhttp { server { listen 80; listen 8080; listen 9443; location / { return 200 "CMTC-authenticated-only\\n"; } } }\n'}})
    tolerations = [{'key': 'node-role.kubernetes.io/control-plane', 'operator': 'Exists', 'effect': 'NoSchedule'}]
    create('pod', 'auth-only-server', 'mtls-spike', {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'labels': {'app': 'cmtc-auth-only-server'}}, 'spec': {'nodeSelector': {'kubernetes.io/hostname': 'cmtc-mtls-control-plane'}, 'tolerations': tolerations, 'serviceAccountName': 'server', 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'volumes': [{'name': 'config', 'configMap': {'name': 'auth-only-nginx'}}], 'containers': [{'name': 'nginx', 'image': 'nginx:1.27-alpine', 'volumeMounts': [{'name': 'config', 'mountPath': '/etc/nginx/nginx.conf', 'subPath': 'nginx.conf', 'readOnly': True}], 'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '64Mi'}}}]}})
    create('svc', 'auth-only-server', 'mtls-spike', {'apiVersion': 'v1', 'kind': 'Service', 'spec': {'selector': {'app': 'cmtc-auth-only-server'}, 'ports': [{'name': f'p{port}', 'port': port, 'targetPort': port} for port in ports] + [{'name': 'mapped8080', 'port': 18080, 'targetPort': 8080}]}})
    for suffix, node in [('worker', 'cmtc-mtls-worker'), ('server-node', 'cmtc-mtls-control-plane')]:
        create('pod', 'auth-only-' + suffix, 'mtls-plaintext-control', {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'labels': {'app': 'cmtc-auth-only-control'}}, 'spec': {'nodeSelector': {'kubernetes.io/hostname': node}, 'tolerations': tolerations, 'automountServiceAccountToken': False, 'restartPolicy': 'Never', 'containers': [{'name': 'probe', 'image': 'alpine:3.20', 'command': ['sleep', '900'], 'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '32Mi'}}}]}})
    for namespace, pod in [('mtls-spike', 'auth-only-server'), ('mtls-plaintext-control', 'auth-only-worker'), ('mtls-plaintext-control', 'auth-only-server-node')]:
        kubectl('-n', namespace, 'wait', 'pod/' + pod, '--for=condition=Ready', '--timeout=35s')
    server = get_json('-n', 'mtls-spike', 'get', 'pod', 'auth-only-server')
    server_ip = str(ipaddress.ip_address(server['status']['podIP']))
    summary['serverPodIP'] = server_ip
    summary['serverNode'] = server['spec']['nodeName']
    cases = []
    for port in ports:
        for name, namespace, pod, host, enrolled in [('enrolled-pod-ip', 'mtls-spike', 'client', server_ip, True), ('enrolled-service', 'mtls-spike', 'client', 'auth-only-server.mtls-spike', True), ('unenrolled-cross-node', 'mtls-plaintext-control', 'auth-only-worker', server_ip, False), ('unenrolled-same-node', 'mtls-plaintext-control', 'auth-only-server-node', server_ip, False)]:
            cases.append({'case': name, 'namespace': namespace, 'pod': pod, 'port': port, 'url': f'http://{host}:{port}/', 'enrolled': enrolled})
        for node in ['cmtc-mtls-control-plane', 'cmtc-mtls-worker']:
            cases.append({'case': 'host-' + node, 'node': node, 'port': port, 'url': f'http://{server_ip}:{port}/', 'enrolled': False})
    cases.append({'case': 'enrolled-service-mapped', 'namespace': 'mtls-spike', 'pod': 'client', 'port': 18080, 'url': 'http://auth-only-server.mtls-spike:18080/', 'enrolled': True})
    warmup = next(case for case in cases if case['enrolled'])
    for attempt in range(20):
        if run_probe(warmup)['success']:
            break
        time.sleep(2)
    else:
        raise RuntimeError('Enrolled positive path did not become ready')
    check_stage('steady', cases)
    if args.restart_tests:
        negative = [case for case in cases if not case['enrolled']]
        for component in ['ztunnel-cilium', 'cilium']:
            stop = threading.Event()
            sampled = []
            probe_errors = []
            def monitor(case):
                try:
                    while not stop.is_set():
                        result = run_probe(case)
                        with lock:
                            sampled.append(result)
                        time.sleep(0.03)
                except Exception as error:
                    with lock:
                        probe_errors.append(str(error))
            # One probe per source, rotating through the representative ports in
            # the stage checks. Concurrent live probes cover the whole restart.
            watched = [case for case in negative if case['port'] == 8080]
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(monitor, case) for case in watched]
                try:
                    time.sleep(2)
                    pods = get_json('-n', 'kube-system', 'get', 'pods', '--field-selector', 'spec.nodeName=cmtc-mtls-control-plane')['items']
                    victim = next(pod for pod in pods if pod['metadata']['name'].startswith(component + '-') and (component != 'cilium' or pod['metadata'].get('labels', {}).get('k8s-app') == 'cilium'))
                    kubectl('-n', 'kube-system', 'delete', 'pod', victim['metadata']['name'], '--wait=false')
                    deadline = time.monotonic() + 150
                    while time.monotonic() < deadline:
                        pods = get_json('-n', 'kube-system', 'get', 'pods', '--field-selector', 'spec.nodeName=cmtc-mtls-control-plane')['items']
                        ready = [pod for pod in pods if pod['metadata']['uid'] != victim['metadata']['uid'] and pod['metadata']['name'].startswith(component + '-') and (component != 'cilium' or pod['metadata'].get('labels', {}).get('k8s-app') == 'cilium') and any(c['type'] == 'Ready' and c['status'] == 'True' for c in pod['status'].get('conditions', []))]
                        if ready and run_probe(warmup)['success']:
                            break
                        time.sleep(1)
                    else:
                        raise RuntimeError(component + ' did not recover')
                    time.sleep(3)
                finally:
                    stop.set()
                    for future in futures:
                        future.result()
            failures = [sample for sample in sampled if not sample['rejected']]
            trial = {'component': component, 'samples': len(sampled), 'unexpectedHTTP': len(failures), 'probeErrors': probe_errors, 'observations': sampled}
            summary['restartTrials'].append(trial)
            save_summary()
            emit(f"{'PASS' if not failures and not probe_errors else 'FAIL'} restart {component}: {len(sampled)} unauthenticated probes; unexpected HTTP={len(failures)}; probe errors={len(probe_errors)}")
            if failures or probe_errors:
                raise RuntimeError(component + ' restart admission check failed')
            check_stage('after-' + component + '-restart', cases)
    summary['runtimeTrialPassed'] = True
except Exception as error:
    summary['runtimeTrialPassed'] = False
    summary['error'] = str(error)
    emit('FAIL: ' + str(error))
finally:
    # Preserve native component logs even when a traffic assertion fails.
    pods = kubectl('-n', 'kube-system', 'get', 'pods', '-o', 'json', check=False) if fixture_verified else None
    if pods is not None and pods.returncode == 0:
        for pod in json.loads(pods.stdout)['items']:
            name = pod['metadata']['name']
            if name.startswith('ztunnel-cilium-') or pod['metadata'].get('labels', {}).get('k8s-app') == 'cilium':
                log = kubectl('-n', 'kube-system', 'logs', name, '--tail=1000', check=False)
                (out / (name + '.log')).write_text(log.stdout + log.stderr)
    cleanup = []
    for kind, name, namespace in reversed(owned):
        result = kubectl('-n', namespace, 'delete', kind, name, '--ignore-not-found', '--wait=false', check=False)
        cleanup.append({'kind': kind, 'name': name, 'namespace': namespace, 'exitCode': result.returncode})
    summary['cleanup'] = cleanup
    save_summary()
    emit('Evidence retained in ' + str(out))
raise SystemExit(0 if summary.get('runtimeTrialPassed') else 1)
