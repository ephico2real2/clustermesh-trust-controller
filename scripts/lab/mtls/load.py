#!/usr/bin/env python3
"""Generate bounded local cross-node mTLS and rejected plaintext traffic."""
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--proxy-source', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.proxy_source):
        parser.error('--proxy-source must be an exact commit SHA')
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'commands.ndjson').exists():
        parser.error('Use a fresh evidence directory')
    kube = ['kubectl', '--kubeconfig', args.kubeconfig]
    suffix = uuid.uuid4().hex[:8]
    owned = []
    result = {'proxySource': args.proxy_source, 'passed': False, 'fullFailClosedProtection': False}

    def run(argv, stdin=None, timeout=240):
        started = time.monotonic()
        process = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=timeout)
        record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'argv': argv,
                  'exitCode': process.returncode, 'elapsedSeconds': time.monotonic() - started,
                  'stdout': process.stdout, 'stderr': process.stderr}
        with (out / 'commands.ndjson').open('a') as stream:
            stream.write(json.dumps(record) + '\n')
        if process.returncode:
            raise RuntimeError(f'{argv}: {process.stderr}')
        return process.stdout

    def get(*argv):
        return json.loads(run(kube + list(argv) + ['-o', 'json']))

    def create(namespace, name, spec):
        spec['metadata'] = {'name': name, 'namespace': namespace,
                            'annotations': {'security.cmtc.io/fixture-id': suffix}}
        run(kube + ['create', '-f', '-'], stdin=json.dumps(spec))
        owned.append((namespace, name))
        (out / (name + '.json')).write_text(json.dumps(spec, indent=2) + '\n')

    try:
        assert run(kube + ['config', 'current-context']).strip() == 'kind-cmtc-mtls', 'Wrong fixture'
        for node in ['cmtc-mtls-control-plane', 'cmtc-mtls-worker']:
            dump = json.loads(run(['docker', 'exec', node, 'curl', '-fsS', 'http://127.0.0.1:15000/config_dump']))
            assert dump['version']['gitRevision'] == args.proxy_source
            assert dump['config']['requireInboundMtls'] is True
        pods = get('-n', 'mtls-spike', 'get', 'pods', '-l', 'app=mtls-server')['items']
        server = next(p for p in pods if p['status']['phase'] == 'Running')
        assert server['spec']['nodeName'] == 'cmtc-mtls-control-plane'
        server_ip = str(ipaddress.ip_address(server['status']['podIP']))
        result['server'] = {'uid': server['metadata']['uid'], 'ip': server_ip, 'node': server['spec']['nodeName']}
        result['fromMs'] = int(time.time() * 1000) - 15000
        for path, target in [('service', 'server.mtls-spike'), ('pod', server_ip)]:
            name = 'strict-load-' + path + '-' + suffix
            create('mtls-spike', name, {'apiVersion': 'batch/v1', 'kind': 'Job', 'spec': {
                'backoffLimit': 0, 'activeDeadlineSeconds': 240,
                'template': {'spec': {'serviceAccountName': 'client', 'automountServiceAccountToken': False,
                    'nodeSelector': {'kubernetes.io/hostname': 'cmtc-mtls-worker'}, 'restartPolicy': 'Never',
                    'volumes': [{'name': 'results', 'emptyDir': {}}],
                    'initContainers': [{'name': 'fortio', 'image': 'fortio/fortio:1.75.3',
                        'args': ['load', '-qps', '20', '-c', '2', '-n', '3000', '-keepalive=false',
                                 '-uniform', '-json', '/results/fortio.json', f'http://{target}/'],
                        'volumeMounts': [{'name': 'results', 'mountPath': '/results'}],
                        'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'}, 'limits': {'memory': '128Mi'}}}],
                    'containers': [{'name': 'results', 'image': 'alpine:3.20', 'command': ['cat', '/results/fortio.json'],
                        'volumeMounts': [{'name': 'results', 'mountPath': '/results', 'readOnly': True}],
                        'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '32Mi'}}}]}}}})
        name = 'strict-deny-load-' + suffix
        script = f'''set -u
for i in $(seq 1 600); do
 wget -T 1 -S -O - http://{server_ip}/ > /tmp/output 2>&1
 probe_rc=$?
 if [ "$probe_rc" -eq 0 ] || grep -q 'HTTP/' /tmp/output; then
  echo "FAIL attempt=$i exit=$probe_rc"; cat /tmp/output; exit 1
 fi
 echo "DENY attempt=$i HTTP=none exit=$probe_rc"
 sleep 0.2
done
echo 'PASS: 600 unauthenticated attempts rejected without HTTP response'
'''
        create('mtls-plaintext-control', name, {'apiVersion': 'batch/v1', 'kind': 'Job', 'spec': {
            'backoffLimit': 0, 'activeDeadlineSeconds': 240,
            'template': {'spec': {'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                'nodeSelector': {'kubernetes.io/hostname': 'cmtc-mtls-worker'},
                'containers': [{'name': 'probe', 'image': 'alpine:3.20', 'command': ['sh', '-c', script],
                    'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'memory': '32Mi'}}}]}}}})
        # Independent Jobs run concurrently; all must finish before validation.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda job: run(kube + ['-n', job[0], 'wait', 'job/' + job[1],
                                                  '--for=condition=Complete', '--timeout=230s']), owned))
        loads = []
        for namespace, name in owned:
            if namespace == 'mtls-spike':
                data = json.loads(run(kube + ['-n', namespace, 'logs', 'job/' + name, '-c', 'results']))
                (out / (name + '-fortio.json')).write_text(json.dumps(data, indent=2) + '\n')
                measured = data['DurationHistogram']['Count']
                if measured != 3000 or data['RetCodes'] != {'200': 3000}:
                    raise RuntimeError(f'{name}: expected 3,000 HTTP 200; measured={measured}, codes={data["RetCodes"]}')
                if data['ActualDuration'] < 120 * 1e9:
                    raise RuntimeError(f'{name}: insufficient measurement duration')
                loads.append({'job': name, 'requests': 3000, 'http200': 3000,
                              'durationSeconds': data['ActualDuration'] / 1e9, 'actualQps': data['ActualQPS']})
            else:
                log = run(kube + ['-n', namespace, 'logs', 'job/' + name])
                (out / (name + '.log')).write_text(log)
                assert len(re.findall(r'^DENY attempt=', log, flags=re.M)) == 600
                result['rejectedAttempts'] = 600
            placement = get('-n', namespace, 'get', 'pods', '-l', 'job-name=' + name)
            (out / (name + '-placement.json')).write_text(json.dumps(placement, indent=2) + '\n')
        result['loads'] = loads
        result['toMs'] = int(time.time() * 1000)
        result['passed'] = True
        print('PASS: 6,000/6,000 HTTP 200 across Service and Pod IP; 600 unenrolled attempts rejected', flush=True)
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
        print('FAIL: ' + result['error'], flush=True)
    finally:
        result['jobs'] = owned
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    # Preserve only the uniquely named completed Jobs for inspectable evidence.
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
