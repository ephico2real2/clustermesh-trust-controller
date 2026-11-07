#!/usr/bin/env python3
"""Sample every ztunnel's workload certificates for a window, then match its HBONE teardown errors against the notAfter times.
Read-only: kubectl port-forward to the ztunnel admin port, and kubectl logs. Usage: measure.py OUT SECONDS"""
import json, os, signal, subprocess, sys, time, urllib.request, datetime as dt
OUT, SECONDS = sys.argv[1], int(sys.argv[2])
KC = ['kubectl', '--kubeconfig', '/private/tmp/cmtc-a-b-20261024.kubeconfig']
PODS = {('cmtc-a', 'ztunnel-cilium-4gbdb'): 15601, ('cmtc-a', 'ztunnel-cilium-lbchw'): 15602,
        ('cmtc-b', 'ztunnel-cilium-q6l85'): 15603, ('cmtc-b', 'ztunnel-cilium-vbt5v'): 15604}
start = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
pf = [subprocess.Popen(KC + ['--context', f'kind-{c}', '-n', 'kube-system', 'port-forward', f'pod/{p}', f'{port}:15000'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for (c, p), port in PODS.items()]
time.sleep(3)
seen = {}
end = time.time() + SECONDS
try:
    while time.time() < end:
        for (c, p), port in PODS.items():
            try:
                d = json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/config_dump', timeout=5))
            except Exception as e:
                print('read failed', c, p, e, flush=True); continue
            for x in d.get('certificates', []):
                for cert in (x.get('certChain') or [])[:1]:
                    seen.setdefault(cert['expirationTime'][:19], set()).add((c, p, x['identity'].split('/')[-1]))
        time.sleep(20)
finally:
    for q in pf: q.send_signal(signal.SIGTERM)
result = {'start': start, 'end': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'pods': {}}
for (c, p) in PODS:
    log = subprocess.run(KC + ['--context', f'kind-{c}', '-n', 'kube-system', 'logs', p, f'--since-time={start}'], capture_output=True, text=True).stdout
    open(os.path.join(OUT, f'{p}.log'), 'w').write(log)
    errs = [l.split()[0] for l in log.splitlines() if 'Error in HBONE connection handshake' in l and 'expired or changed' in l]
    access = [l for l in log.splitlines() if '\terror\taccess\t' in l and 'expired or changed' in l]
    matched = [e for e in errs if e[:19] in seen and e[20:21] == '0']
    result['pods'][p] = {'errors': len(errs), 'matched_notAfter': len(matched), 'failed_access_lines': len(access),
                         'unmatched': [e for e in errs if e not in matched]}
result['notAfter'] = {k: sorted(map(list, v)) for k, v in sorted(seen.items())}
span = (dt.datetime.strptime(result['end'], '%Y-%m-%dT%H:%M:%SZ') - dt.datetime.strptime(start, '%Y-%m-%dT%H:%M:%SZ')).total_seconds()
result['chance_of_a_random_second_matching'] = round(len(seen) / max(span + 130, 1), 3)
json.dump(result, open(os.path.join(OUT, 'result.json'), 'w'), indent=1)
print(json.dumps({k: v for k, v in result.items() if k != 'notAfter'}, indent=1))
print('distinct notAfter seconds', len(seen))
