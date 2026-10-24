#!/usr/bin/env python3
"""Remove dynamic authentication in the owned fixture, qualify, then restore it."""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--proxy-source', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    for revision in [args.source, args.proxy_source]:
        if not re.fullmatch('[0-9a-f]{40}', revision):
            parser.error('Source revisions must be exact commit SHAs')
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'commands.ndjson').exists():
        parser.error('Use a fresh evidence directory')
    kube = ['kubectl', '--kubeconfig', args.kubeconfig, '-n', 'kube-system']
    result = {'source': args.source, 'proxySource': args.proxy_source,
              'fullFailClosedProtection': False, 'trialPassed': False, 'restored': False}
    changed = False

    def run(argv, *, check=True, timeout=180):
        started = time.monotonic()
        observed = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record = {'at': observed, 'argv': argv, 'exitCode': None}
        try:
            process = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
            record = {'at': observed, 'argv': argv, 'exitCode': process.returncode,
                      'stdout': process.stdout, 'stderr': process.stderr}
        except subprocess.TimeoutExpired:
            record = {'at': observed, 'argv': argv, 'exitCode': None, 'timeoutSeconds': timeout}
            raise
        except OSError as error:
            record['error'] = str(error)
            raise
        finally:
            record['elapsedSeconds'] = time.monotonic() - started
            with (out / 'commands.ndjson').open('a') as stream:
                stream.write(json.dumps(record) + '\n')
        if check and process.returncode:
            raise RuntimeError(f'Command failed ({process.returncode}): {argv}: {process.stderr}')
        return process

    def get(kind, name):
        return json.loads(run(kube + ['get', kind, name, '-o', 'json']).stdout)

    def set_flag(expected, desired):
        config = get('cm', 'cilium-config')
        patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': config['metadata']['resourceVersion']},
                 {'op': 'test', 'path': '/data/ztunnel-require-mtls', 'value': expected},
                 {'op': 'replace', 'path': '/data/ztunnel-require-mtls', 'value': desired}]
        run(kube + ['patch', 'cm', 'cilium-config', '--type=json', '-p', json.dumps(patch)])

    def restart():
        # Restart proxies after agents to discard cached dynamic policies. The
        # immutable proxy-mtls command is preserved throughout both rollouts.
        for daemonset in ['cilium', 'ztunnel-cilium']:
            run(kube + ['rollout', 'restart', 'ds/' + daemonset])
            run(kube + ['rollout', 'status', 'ds/' + daemonset, '--timeout=150s'])

    def verify_proxy(stage, dynamic):
        observations = []
        for node in ['cmtc-mtls-control-plane', 'cmtc-mtls-worker']:
            # DaemonSet readiness can precede the admin listener and policy
            # convergence. Bound this separate observation, logging each attempt.
            started = time.monotonic()
            deadline = started + 30
            attempts = 0
            while True:
                attempts += 1
                response = run(['docker', 'exec', node, 'curl', '-fsS', '--max-time', '2',
                                'http://127.0.0.1:15000/config_dump'], check=False, timeout=5)
                reason = f'Admin API unavailable: curl exit {response.returncode}'
                if response.returncode == 0:
                    dump = json.loads(response.stdout)
                    # A wrong binary or disabled floor is a hard failure, not a
                    # transient readiness condition to conceal with retries.
                    assert dump['version']['gitRevision'] == args.proxy_source, 'Wrong proxy source'
                    assert dump['config'].get('requireInboundMtls') is True, 'Proxy authentication floor disabled'
                    converged = (any(p['name'] == 'cilium_require_mtls' for p in dump['policies'])
                                 if dynamic else dump['policies'] == [] and dump['staticConfig']['policies'] == [])
                    if converged:
                        break
                    reason = 'Dynamic rule not restored' if dynamic else 'Policy cache is not empty'
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f'{node}: {reason} after {attempts} attempts')
                time.sleep(min(0.5, remaining))
            observations.append({'node': node, 'version': dump['version'],
                                 'requireInboundMtls': True, 'policies': dump['policies'],
                                 'attempts': attempts, 'elapsedSeconds': time.monotonic() - started})
        (out / f'proxy-{stage}.json').write_text(json.dumps(observations, indent=2) + '\n')

    try:
        assert run(kube + ['config', 'current-context']).stdout.strip() == 'kind-cmtc-mtls', 'Wrong fixture context'
        config = get('cm', 'cilium-config')
        assert config['data'].get('ztunnel-require-mtls') == 'true', 'Expected original dynamic authentication'
        daemonset = get('ds', 'ztunnel-cilium')
        proxy = next(c for c in daemonset['spec']['template']['spec']['containers'] if c['name'] == 'istio-proxy')
        assert proxy['args'][0] == 'proxy-mtls', 'Strict proxy command required before fault injection'
        verify_proxy('before', True)
        set_flag('true', 'false')
        changed = True
        restart()
        verify_proxy('absent', False)
        trial = run([sys.executable, str(Path(__file__).with_name('qualify.py')),
                     '--kubeconfig', args.kubeconfig, '--source', args.source,
                     '--proxy-source', args.proxy_source, '--expect-dynamic-mtls', 'absent',
                     '--restart-tests', '--out', str(out / 'traffic')], timeout=600)
        print(trial.stdout, flush=True)
        result['trialPassed'] = True
    except Exception as error:
        result['error'] = str(error)
        print('FAIL: ' + str(error), flush=True)
    finally:
        if changed:
            try:
                set_flag('false', 'true')
                restart()
                verify_proxy('restored', True)
                result['restored'] = True
            except Exception as error:
                result['restorationError'] = str(error)
                print('RESTORATION FAILED: ' + str(error), flush=True)
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['trialPassed'] and result['restored'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
