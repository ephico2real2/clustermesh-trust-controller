#!/usr/bin/env python3
"""Rotation drill: renew one mesh credential under per-second probes, both directions, every scope (issue #47, P3).

One drill is one credential (R1-R6 of #47) or one negative case, on one cluster, with the probe traffic of both
clusters running once per second in every scope for the whole window, and the Cilium agent and ztunnel events of
both clusters captured as they happen. Nothing runs against a cluster without --execute, and nothing runs at all
without the kube-system UID pins of both clusters.

  R1  ztunnel-origin-reader            cmctl renew        the Cilium agents' direct-origin client certificate
  R2  ztunnel-membership-writer        cmctl renew        the agents' membership writer client certificate
  R3  cmtc-ztunnel-ads-server          cmctl renew        the agents' xDS server certificate that ztunnel verifies
  R4  clustermesh-apiserver-*-cert     cmctl renew x4     admin, local, remote, then the server (key kept)
  R5  SPIRE X.509 CA                   local_authority.py rotate
  R6  workload X509-SVID               no command: one SVID lifetime (130 s) is observed under probes
  neg-ca        ztunnel-origin-reader reissued by a throwaway self-signed CA, then put back (fail closed, recover)
  neg-pin       a wrong server pin in ztunnel-origin-config for the peer, then put back (fail closed, recover)
  neg-peer-down the peer's clustermesh-apiserver node port dropped on this cluster's nodes for --down-seconds

Verdicts (summary.json, exit 1 on any failed one): every allowed path 0 failed probes, every denied path 0 HTTP
answers, and for R1-R6 no `event=withdrawn` on any agent. For a negative drill the withdrawal must happen, the
cross-cluster path into this cluster must fail closed (curl 56, never HTTP 200) and must recover after the revert.

The two negative drills that change Helm-managed objects (neg-ca patches Certificate ztunnel-origin-reader, neg-pin
patches ConfigMap ztunnel-origin-config) put the object's data back byte for byte and then require the drift check
`scripts/lab/cilium_adopt.py plan` to report 0; they refuse to run without --allow-helm-object-change.

Usage:
  rotation_drill.py plan --out DIR                              print the plan and the current certificates (read-only)
  rotation_drill.py preflight --out DIR                         the read-only checks every drill runs first
  rotation_drill.py drill R1 --cluster cmtc-a --out DIR --execute [--seconds 150] [--lead 20]
  rotation_drill.py drill neg-peer-down --cluster cmtc-a --out DIR --down-seconds 120 --execute

Requires: kubectl, cmctl (R1-R4, neg-ca), docker (neg-peer-down, through the kind nodes' Docker context), the live
mTLS fixture Pods of both clusters (scripts/evidence/live_mtls_fixture.py) and the kubeconfig below. Runs unchanged
on Linux and macOS: the node side uses only busybox sh, date +%s and curl; the host stamps every probe line.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time

KUBECONFIG = '/private/tmp/cmtc-a-b-20261024.kubeconfig'
PINS = {'cmtc-a': 'bb7182c7-de95-4e70-816a-a1400d755794', 'cmtc-b': 'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
DOCKER_CONTEXT = os.environ.get('DOCKER_CONTEXT', 'colima-cmtc-cilium')
NS, NEG = 'cmtc-live-mtls', 'cmtc-live-mtls-unauth'
NODE_PORT = 32379
REPO = pathlib.Path(__file__).resolve().parents[2]
LOCAL_AUTHORITY = REPO / 'scripts/lab/spire/local_authority.py'
DRILL_MANAGER = 'cmtc-rotation-drill'

CERTIFICATE_DRILLS = {
    'R1': ['ztunnel-origin-reader'],
    'R2': ['ztunnel-membership-writer'],
    'R3': ['cmtc-ztunnel-ads-server'],
    'R4': ['clustermesh-apiserver-admin-cert', 'clustermesh-apiserver-local-cert',
           'clustermesh-apiserver-remote-cert', 'clustermesh-apiserver-server-cert'],
}
DRILLS = list(CERTIFICATE_DRILLS) + ['R5', 'R6', 'neg-ca', 'neg-pin', 'neg-peer-down']
# Agent lines that tell the origin story; the ztunnel filter keeps certificate, xDS and issuer-profile lines and
# drops the `Fetching PID` flood (#47, P4).
AGENT_EVENTS = re.compile(r'event=withdrawn|event=projected|refresh-origin-transport|restart-origin-watch|'
                          r'load-config|connect-origin|validate-origin|origin config|Closing ztunnel xDS stream|'
                          r'Creating etcd client|source membership was withdrawn|snapshot is invalid|lease expired')
ZTUNNEL_EVENTS = re.compile(r'certificate|Stream established|xds|XDS|stage=|identity|issuer|rotat|expired|'
                            r'handshake|unauthorized|Unauthorized', re.I)
ZTUNNEL_NOISE = re.compile(r'Fetching PID')
# One curl per second per path, inside the client Pod; the host stamps each line as it arrives.
LOOP = ('end=$(( $(date +%s) + $2 )); i=0; '
        'while [ "$(date +%s)" -lt "$end" ]; do i=$((i+1)); '
        'r=$(curl -sS -o /dev/null -w "%{http_code} %{time_total}" --connect-timeout 1 --max-time 2 "$1" 2>/dev/null); '
        'echo "$i $? $r"; sleep 1; done; echo "END $i"')


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso(t=None):
    return (t or now()).isoformat()


def clock(stamp):
    """An ISO UTC stamp as HH:MM:SS.mmmZ for the README tables."""
    if not stamp:
        return '-'
    return dt.datetime.fromisoformat(stamp).astimezone(dt.timezone.utc).strftime('%H:%M:%S.%f')[:-3] + 'Z'


def run(args, check=True, text_input=None, timeout=300):
    r = subprocess.run(args, capture_output=True, text=True, input=text_input, timeout=timeout)
    require('PRIVATE KEY' not in r.stdout + r.stderr, 'private material in a command output; refusing to continue')
    if check:
        require(r.returncode == 0, f'{" ".join(args[:6])}: exit {r.returncode}: {r.stderr.strip()[:800]}')
    return r


def kubectl(cluster, *args, check=True, text_input=None):
    return run(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + cluster, *args], check=check, text_input=text_input)


def get_json(cluster, *args):
    return json.loads(kubectl(cluster, *args, '-o', 'json').stdout)


def peer_of(cluster):
    return 'cmtc-b' if cluster == 'cmtc-a' else 'cmtc-a'


def global_name(cluster):
    return f'server-{cluster}.{NS}.svc.cluster.local'


def pod_name(short):
    return f'server-{short}.{NS}.svc.cluster.local'


class Lab:
    """Read-only facts about both clusters, pinned to the kube-system UIDs."""

    def __init__(self):
        for cluster, uid in PINS.items():
            got = get_json(cluster, 'get', 'ns', 'kube-system')['metadata']['uid']
            require(got == uid, f'{cluster}: kube-system UID {got} is not the pinned {uid}')

    def certificates(self, cluster):
        rows = {}
        for item in get_json(cluster, '-n', 'kube-system', 'get', 'certificates')['items']:
            status = item.get('status', {})
            rows[item['metadata']['name']] = {
                'revision': status.get('revision'), 'notBefore': status.get('notBefore'),
                'notAfter': status.get('notAfter'), 'renewalTime': status.get('renewalTime'),
                'issuerRef': item['spec'].get('issuerRef', {}).get('name'),
                'ready': next((c['status'] for c in status.get('conditions', []) if c['type'] == 'Ready'), None),
            }
        return rows

    def pods(self, cluster, namespace, selector=None):
        args = ['-n', namespace, 'get', 'pods'] + (['-l', selector] if selector else [])
        return {p['metadata']['name']: p for p in get_json(cluster, *args)['items']}

    def agents(self, cluster):
        return self.pods(cluster, 'kube-system', 'k8s-app=cilium')

    def ztunnels(self, cluster):
        return self.pods(cluster, 'kube-system', 'app=ztunnel-cilium')

    def fixture(self, cluster):
        pods = self.pods(cluster, NS)
        require({'client-worker', 'client-control-plane', 'server-worker', 'server-control-plane'} <= set(pods),
                f'{cluster}: the live mTLS fixture Pods are missing in {NS}')
        require('unregistered-worker' in self.pods(cluster, NEG), f'{cluster}: unregistered-worker is missing in {NEG}')
        require(all(p['status'].get('podIP') for p in pods.values()), f'{cluster}: a fixture Pod has no IP')
        return pods

    def node_ips(self, cluster):
        return {n['metadata']['name']: next(a['address'] for a in n['status']['addresses'] if a['type'] == 'InternalIP')
                for n in get_json(cluster, 'get', 'nodes')['items']}


def probe_paths(lab):
    """Every scope in both directions: (name, client cluster, namespace, client Pod, URL, expect)."""
    pods = {c: lab.fixture(c) for c in PINS}
    paths = []
    for c in PINS:
        peer = peer_of(c)
        ip = lambda cluster, pod: pods[cluster][pod]['status']['podIP']
        paths += [
            (f'{c}-same', c, NS, 'client-worker', f'http://{ip(c, "server-worker")}:80/', 'allow'),
            (f'{c}-crossnode', c, NS, 'client-worker', f'http://{ip(c, "server-control-plane")}:80/', 'allow'),
            (f'{c}-crosscluster', c, NS, 'client-worker', f'http://{ip(peer, "server-worker")}:80/', 'allow'),
            (f'{c}-global-local', c, NS, 'client-worker', f'http://{global_name(c)}:80/', 'allow'),
            (f'{c}-global-remote', c, NS, 'client-worker', f'http://{global_name(peer)}:80/', 'allow'),
            (f'{c}-name', c, NS, 'client-worker', f'http://{pod_name("control-plane")}:80/', 'allow'),
            (f'{c}-denied', c, NEG, 'unregistered-worker', f'http://{ip(c, "server-worker")}:80/', 'deny'),
        ]
    return paths


class TrafficWatch:
    """One in-Pod curl loop per path for `seconds`, one request per second, host-stamped rows in traffic.jsonl."""

    def __init__(self, out, paths, seconds):
        self.out, self.paths, self.seconds = out, paths, seconds
        self.rows, self.lock, self.threads, self.ended = [], threading.Lock(), [], {}
        self.sink = open(out / 'traffic.jsonl', 'a')

    def start(self):
        self.sink.write(json.dumps({'event': 'start', 'at': iso(), 'seconds': self.seconds,
                                    'paths': {p[0]: f'{p[1]}/{p[3]} -> {p[4]} {p[5]}' for p in self.paths}}) + '\n')
        for path in self.paths:
            t = threading.Thread(target=self._run, args=(path,), daemon=True)
            t.start()
            self.threads.append(t)

    def _run(self, path):
        name, cluster, ns, client, url, _ = path
        cmd = ['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + cluster, '-n', ns, 'exec', client,
               '--', 'sh', '-c', LOOP, 'sh', url, str(self.seconds)]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) as p:
            for line in p.stdout:
                at = iso()
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == 'END':
                    self.ended[name] = int(parts[1])
                    continue
                row = {'path': name, 'seq': int(parts[0]), 'at': at, 'curlRC': int(parts[1]),
                       'http': parts[2] if len(parts) > 2 else '', 'timeTotal': float(parts[3]) if len(parts) > 3 else None}
                with self.lock:
                    self.rows.append(row)
                    self.sink.write(json.dumps(row) + '\n')
                    self.sink.flush()
            err = p.stderr.read()
        if p.returncode or name not in self.ended:
            with self.lock:
                self.sink.write(json.dumps({'path': name, 'execExit': p.returncode, 'stderr': err[-400:]}) + '\n')

    def wait(self):
        for t in self.threads:
            t.join()
        self.sink.write(json.dumps({'event': 'end', 'at': iso(), 'ended': self.ended}) + '\n')
        self.sink.close()

    def summary(self):
        result = {}
        for name, _, _, _, _, expect in self.paths:
            own = [r for r in self.rows if r['path'] == name]
            good = (lambda r: r['curlRC'] == 0 and r['http'] == '200') if expect == 'allow' else \
                   (lambda r: r['curlRC'] != 0 and r['http'] in ('', '000'))
            bad = [r for r in own if not good(r)]
            longest, current = None, []
            for r in own + [None]:
                if r is not None and not good(r):
                    current.append(r)
                    continue
                if current and (longest is None or len(current) > len(longest['rows'])):
                    i = own.index(current[0])
                    longest = {'rows': current, 'lastGoodBefore': own[i - 1]['at'] if i else None,
                               'firstGoodAfter': r['at'] if r else None}
                current = []
            entry = {'expect': expect, 'requests': len(own), 'failures': len(bad),
                     'http200': sum(1 for r in own if r['http'] == '200'),
                     'first': own[0]['at'] if own else None, 'last': own[-1]['at'] if own else None,
                     'ended': self.ended.get(name)}
            if longest:
                entry['longestFailureRun'] = {
                    'count': len(longest['rows']), 'firstFailure': longest['rows'][0]['at'],
                    'lastFailure': longest['rows'][-1]['at'], 'lastGoodBefore': longest['lastGoodBefore'],
                    'firstGoodAfter': longest['firstGoodAfter'],
                    'codes': sorted({f"{r['curlRC']}/{r['http']}" for r in longest['rows']})}
            result[name] = entry
        return result


class LogFollower:
    """`kubectl logs -f` of one container, raw to one file and the matching lines to another, host-stamped."""

    def __init__(self, out, cluster, pod, container, keep, drop=None):
        self.cluster, self.pod, self.container, self.keep, self.drop = cluster, pod, container, keep, drop
        base = out / f'{cluster}-{pod}-{container}'
        self.raw = open(str(base) + '.log', 'a')
        self.events = open(str(base) + '.events', 'a')
        self.count = 0
        self.process = None

    def start(self):
        cmd = ['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + self.cluster, '-n', 'kube-system',
               'logs', '-f', self.pod, '-c', self.container, '--timestamps', '--since=2s']
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self):
        for line in self.process.stdout:
            self.raw.write(line)
            if self.keep.search(line) and not (self.drop and self.drop.search(line)):
                self.count += 1
                self.events.write(f'{iso()} {line}')
                self.events.flush()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.thread.join(timeout=10)
        self.raw.close()
        self.events.close()

    def lines(self):
        with open(self.events.name) as f:
            return f.read().splitlines()


def ztunnel_certificates(cluster, pod):
    """The public certificates ztunnel holds (its config dump, port 15000), without any key: serial, validity, subject."""
    import socket
    import urllib.request
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        local = s.getsockname()[1]
    pf = subprocess.Popen(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + cluster, '-n', 'kube-system',
                           'port-forward', '--address', '127.0.0.1', 'pod/' + pod, f'{local}:15000'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        body = None
        for _ in range(60):
            require(pf.poll() is None, f'{cluster}/{pod}: port-forward exited')
            try:
                body = urllib.request.urlopen(f'http://127.0.0.1:{local}/config_dump', timeout=2).read()
                break
            except OSError:
                time.sleep(0.25)
        require(body is not None, f'{cluster}/{pod}: config dump unavailable')
        require(b'PRIVATE KEY' not in body, 'private material in a ztunnel config dump; refusing to continue')
        dump = json.loads(body)
    finally:
        pf.terminate()
        try:
            pf.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pf.kill()
    certificates = []
    for cert in dump.get('certificates', []):
        chain = cert.get('certChain', [])
        certificates.append({'identity': cert.get('identity'), 'state': cert.get('state'),
                             'leaf': {k: chain[0].get(k) for k in ('serialNumber', 'validFrom', 'expirationTime')} if chain else None,
                             'chainLength': len(chain)})
    return certificates


def spire_authorities(cluster):
    r = run([sys.executable, str(LOCAL_AUTHORITY), '--kube-system-uid', PINS[cluster], cluster, 'show'], check=False)
    return {'exit': r.returncode, 'stdout': r.stdout[-4000:], 'stderr': r.stderr[-1000:]}


class Drill:
    def __init__(self, args):
        self.args = args
        self.cluster = args.cluster
        self.peer = peer_of(self.cluster) if self.cluster else None
        self.out = pathlib.Path(args.out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.lab = Lab()
        self.record = {'drill': args.drill, 'cluster': self.cluster, 'startedAt': iso(), 'execute': args.execute,
                       'seconds': args.seconds, 'lead': args.lead}

    def save(self, name, obj):
        (self.out / name).write_text(json.dumps(obj, indent=1, sort_keys=True) + '\n')

    # ---- read-only parts -------------------------------------------------------------------------------------
    def preflight(self):
        facts = {'clusters': {}, 'tools': {}}
        for tool in ('kubectl', 'cmctl', 'docker'):
            facts['tools'][tool] = shutil.which(tool)
        for c in PINS:
            fixture = self.lab.fixture(c)
            facts['clusters'][c] = {
                'kubeSystemUID': PINS[c],
                'agents': {n: p['status']['containerStatuses'][0].get('state', {}).get('running', {}).get('startedAt')
                           for n, p in self.lab.agents(c).items()},
                'ztunnels': sorted(self.lab.ztunnels(c)),
                'fixture': {n: [p['status']['podIP'], p['spec']['nodeName']] for n, p in fixture.items()},
                'certificates': self.lab.certificates(c),
            }
        self.save('preflight.json', facts)
        return facts

    def plan(self):
        facts = self.preflight()
        print(json.dumps({'drills': DRILLS, 'certificateDrills': CERTIFICATE_DRILLS,
                          'paths': [p[0] for p in probe_paths(self.lab)],
                          'certificates': {c: facts['clusters'][c]['certificates'] for c in PINS}}, indent=1))

    # ---- the events ------------------------------------------------------------------------------------------
    def event_command(self, drill):
        """The command of a drill as a list of argv lists, run in order with a pause between them."""
        if drill in CERTIFICATE_DRILLS:
            require(shutil.which('cmctl'), 'cmctl is not installed')
            return [['cmctl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + self.cluster, 'renew', '-n', 'kube-system', name]
                    for name in CERTIFICATE_DRILLS[drill]]
        if drill == 'R5':
            return [[sys.executable, str(LOCAL_AUTHORITY), '--kube-system-uid', PINS[self.cluster], '--ledger',
                     str(self.out / 'spire-ledger.json'), self.cluster, 'rotate']]
        if drill == 'R6':
            return []
        return None  # the negative drills are methods, not single commands

    def run_event(self, drill, record):
        commands = self.event_command(drill)
        if commands is not None:
            results = []
            for i, cmd in enumerate(commands):
                started = iso()
                r = run(cmd, check=False, timeout=600)
                results.append({'command': cmd, 'startedAt': started, 'endedAt': iso(), 'exit': r.returncode,
                                'stdout': r.stdout[-3000:], 'stderr': r.stderr[-1500:]})
                if r.returncode != 0:
                    break
                if i + 1 < len(commands):
                    time.sleep(self.args.between)
            record['event'] = results
            return
        getattr(self, 'negative_' + drill.replace('neg-', '').replace('-', '_'))(record)

    def negative_ca(self, record):
        """Reissue ztunnel-origin-reader from a throwaway self-signed CA, hold, then put the issuerRef back."""
        require(self.args.allow_helm_object_change, 'neg-ca patches the Helm-managed Certificate; pass --allow-helm-object-change')
        name, ns = 'ztunnel-origin-reader', 'kube-system'
        original = get_json(self.cluster, '-n', ns, 'get', 'certificate', name)
        self.save('neg-ca-certificate-before.json', original)
        issuer_ref = original['spec']['issuerRef']
        throwaway = f'{DRILL_MANAGER}-ca'
        objects = {'apiVersion': 'v1', 'kind': 'List', 'items': [
            {'apiVersion': 'cert-manager.io/v1', 'kind': 'Issuer', 'metadata': {'name': throwaway + '-selfsigned', 'namespace': ns},
             'spec': {'selfSigned': {}}},
            {'apiVersion': 'cert-manager.io/v1', 'kind': 'Certificate', 'metadata': {'name': throwaway, 'namespace': ns},
             'spec': {'isCA': True, 'commonName': 'cmtc rotation drill unapproved CA', 'secretName': throwaway,
                      'privateKey': {'algorithm': 'ECDSA', 'size': 256}, 'duration': '2h',
                      'issuerRef': {'name': throwaway + '-selfsigned', 'kind': 'Issuer', 'group': 'cert-manager.io'}}},
            {'apiVersion': 'cert-manager.io/v1', 'kind': 'Issuer', 'metadata': {'name': throwaway, 'namespace': ns},
             'spec': {'ca': {'secretName': throwaway}}},
        ]}
        steps = []
        try:
            kubectl(self.cluster, 'apply', '-f', '-', text_input=json.dumps(objects))
            kubectl(self.cluster, '-n', ns, 'wait', '--for=condition=Ready', 'certificate/' + throwaway, '--timeout=120s')
            steps.append({'at': iso(), 'step': 'throwaway CA ready'})
            patch = json.dumps({'spec': {'issuerRef': {'name': throwaway, 'kind': 'Issuer', 'group': 'cert-manager.io'}}})
            kubectl(self.cluster, '-n', ns, 'patch', 'certificate', name, '--type=merge', f'--field-manager={DRILL_MANAGER}', '-p', patch)
            steps.append({'at': iso(), 'step': 'issuerRef -> throwaway CA'})
            time.sleep(self.args.hold)
        finally:
            patch = json.dumps({'spec': {'issuerRef': issuer_ref}})
            kubectl(self.cluster, '-n', ns, 'patch', 'certificate', name, '--type=merge', f'--field-manager={DRILL_MANAGER}', '-p', patch)
            steps.append({'at': iso(), 'step': 'issuerRef restored'})
            kubectl(self.cluster, 'delete', '-f', '-', '--ignore-not-found', text_input=json.dumps(objects))
            kubectl(self.cluster, '-n', ns, 'delete', 'secret', throwaway, '--ignore-not-found')
            steps.append({'at': iso(), 'step': 'throwaway CA removed'})
        after = get_json(self.cluster, '-n', ns, 'get', 'certificate', name)
        steps.append({'at': iso(), 'specRestored': after['spec'] == original['spec'], 'revision': after.get('status', {}).get('revision')})
        record['event'] = steps

    def negative_pin(self, record):
        """Put a wrong server pin for the peer into ztunnel-origin-config, hold, then put the data back byte for byte."""
        require(self.args.allow_helm_object_change, 'neg-pin patches the Helm-managed ConfigMap; pass --allow-helm-object-change')
        ns, cm = 'kube-system', 'ztunnel-origin-config'
        original = get_json(self.cluster, '-n', ns, 'get', 'configmap', cm)
        self.save('neg-pin-configmap-before.json', original)
        data = original['data']
        require(self.peer in data, f'{cm} has no entry for {self.peer}')
        wrong = re.sub(r'spki-sha256:\s*\[[^\]]*\]', 'spki-sha256: ["' + '0' * 64 + '"]', data[self.peer])
        require(wrong != data[self.peer], f'{cm}/{self.peer}: no spki-sha256 pin found to replace')
        steps = []
        try:
            kubectl(self.cluster, '-n', ns, 'patch', 'configmap', cm, '--type=merge', f'--field-manager={DRILL_MANAGER}',
                    '-p', json.dumps({'data': {self.peer: wrong}}))
            steps.append({'at': iso(), 'step': 'wrong pin applied'})
            time.sleep(self.args.hold)
        finally:
            kubectl(self.cluster, '-n', ns, 'patch', 'configmap', cm, '--type=merge', f'--field-manager={DRILL_MANAGER}',
                    '-p', json.dumps({'data': {self.peer: data[self.peer]}}))
            steps.append({'at': iso(), 'step': 'pin restored'})
        after = get_json(self.cluster, '-n', ns, 'get', 'configmap', cm)
        steps.append({'at': iso(), 'dataRestored': after['data'] == data})
        record['event'] = steps

    def negative_peer_down(self, record):
        """Drop this cluster's traffic to the peer's clustermesh-apiserver node port for --down-seconds, then lift it."""
        require(shutil.which('docker'), 'docker is not installed')
        peer_ips = self.lab.node_ips(self.peer)
        nodes = sorted(self.lab.node_ips(self.cluster))
        rules = [['iptables', '-w', '5', '-I', 'OUTPUT', '-p', 'tcp', '--dport', str(NODE_PORT), '-d', ip, '-j', 'DROP'] for ip in peer_ips.values()]
        steps = []

        def iptables(node, rule, insert=True):
            argv = list(rule)
            argv[3] = '-I' if insert else '-D'
            return run(['docker', '--context', DOCKER_CONTEXT, 'exec', node, *argv], check=False)

        try:
            for node in nodes:
                for rule in rules:
                    r = iptables(node, rule)
                    steps.append({'at': iso(), 'node': node, 'rule': ' '.join(rule), 'exit': r.returncode, 'stderr': r.stderr[-200:]})
                    require(r.returncode == 0, f'{node}: iptables insert failed: {r.stderr}')
            time.sleep(self.args.down_seconds)
        finally:
            for node in nodes:
                for rule in rules:
                    r = iptables(node, rule, insert=False)
                    steps.append({'at': iso(), 'node': node, 'rule': ' '.join(rule).replace(' -I ', ' -D '), 'exit': r.returncode, 'stderr': r.stderr[-200:]})
            leftovers = {}
            for node in nodes:
                r = run(['docker', '--context', DOCKER_CONTEXT, 'exec', node, 'iptables', '-w', '5', '-S', 'OUTPUT'], check=False)
                leftovers[node] = [l for l in r.stdout.splitlines() if str(NODE_PORT) in l and 'DROP' in l]
            steps.append({'at': iso(), 'leftoverDropRules': leftovers})
        record['event'] = steps

    def requirements(self, drill):
        """Everything a drill needs, checked before any probe or event starts."""
        if drill in CERTIFICATE_DRILLS or drill == 'neg-ca':
            require(shutil.which('cmctl'), 'cmctl is not installed')
        if drill == 'neg-peer-down':
            require(shutil.which('docker'), 'docker is not installed')
            run(['docker', '--context', DOCKER_CONTEXT, 'info', '--format', '{{.ServerVersion}}'])
        if drill in ('neg-ca', 'neg-pin'):
            require(self.args.allow_helm_object_change,
                    f'{drill} patches a Helm-managed object and needs the drift check afterwards; pass --allow-helm-object-change')
        if drill == 'R5':
            require(LOCAL_AUTHORITY.exists(), f'{LOCAL_AUTHORITY} is missing')

    # ---- the drill -------------------------------------------------------------------------------------------
    def drill(self):
        drill = self.args.drill
        require(drill in DRILLS, f'unknown drill {drill}; one of {DRILLS}')
        require(self.cluster in PINS, '--cluster is required: cmtc-a or cmtc-b')
        record = dict(self.record)
        record['before'] = {'preflight': self.preflight()}
        if drill in ('R5', 'R6'):
            record['before']['spire'] = {c: spire_authorities(c) for c in PINS}
        if drill in ('R3', 'R6'):
            record['before']['ztunnelCertificates'] = {f'{c}/{p}': ztunnel_certificates(c, p) for c in PINS for p in self.lab.ztunnels(c)}
        paths = probe_paths(self.lab)
        commands = self.event_command(drill)
        self.requirements(drill)
        plan = {'drill': drill, 'cluster': self.cluster, 'paths': [p[0] for p in paths],
                'event': commands if commands is not None else f'method negative_{drill[4:].replace("-", "_")}',
                'seconds': self.args.seconds, 'lead': self.args.lead}
        self.save('plan.json', plan)
        if not self.args.execute:
            print(json.dumps(plan, indent=1))
            print('dry run: nothing was changed; pass --execute to run the drill', file=sys.stderr)
            return 0

        (self.out / 'logs').mkdir(exist_ok=True)
        followers = []
        for c in PINS:
            for pod in self.lab.agents(c):
                followers.append(LogFollower(self.out / 'logs', c, pod, 'cilium-agent', AGENT_EVENTS))
            for pod in self.lab.ztunnels(c):
                followers.append(LogFollower(self.out / 'logs', c, pod, 'istio-proxy', ZTUNNEL_EVENTS, ZTUNNEL_NOISE))
        for f in followers:
            f.start()
        watch = TrafficWatch(self.out, paths, self.args.seconds)
        watch.start()
        time.sleep(self.args.lead)
        record['eventStartedAt'] = iso()
        try:
            self.run_event(drill, record)
        except Exception as e:  # the watch and the record must still be written
            record['eventError'] = repr(e)
        record['eventEndedAt'] = iso()
        watch.wait()
        time.sleep(3)
        for f in followers:
            f.stop()

        record['traffic'] = watch.summary()
        record['after'] = {'certificates': {c: self.lab.certificates(c) for c in PINS}}
        if drill in ('R5', 'R6'):
            record['after']['spire'] = {c: spire_authorities(c) for c in PINS}
        if drill in ('R3', 'R6'):
            record['after']['ztunnelCertificates'] = {f'{c}/{p}': ztunnel_certificates(c, p) for c in PINS for p in self.lab.ztunnels(c)}
        record['agentEvents'] = {}
        for f in followers:
            lines = f.lines()
            counts = {key: sum(1 for l in lines if key in l) for key in
                      ('event=withdrawn', 'event=projected', 'refresh-origin-transport', 'restart-origin-watch', 'Stream established')}
            record['agentEvents'][f'{f.cluster}/{f.pod}/{f.container}'] = {'lines': len(lines), **counts}
        record['verdicts'] = self.verdicts(drill, record)
        record['endedAt'] = iso()
        self.save('summary.json', record)
        self.write_readme(record)
        failed = [k for k, v in record['verdicts'].items() if not v['pass']]
        print(json.dumps({'drill': drill, 'cluster': self.cluster, 'verdicts': record['verdicts'], 'out': str(self.out)}, indent=1))
        return 1 if failed or 'eventError' in record else 0

    def verdicts(self, drill, record):
        traffic, events = record['traffic'], record['agentEvents']
        withdrawn = {k: v['event=withdrawn'] for k, v in events.items() if k.endswith('/cilium-agent')}
        verdicts = {}
        allowed = {k: v for k, v in traffic.items() if v['expect'] == 'allow'}
        denied = {k: v for k, v in traffic.items() if v['expect'] == 'deny'}
        verdicts['denied paths never answered'] = {'pass': all(v['http200'] == 0 for v in denied.values()),
                                                   'http200': {k: v['http200'] for k, v in denied.items()}}
        verdicts['every path probed for the whole window'] = {
            'pass': all(v['requests'] >= self.args.seconds * 0.5 and v['ended'] is not None for v in traffic.values()),
            'requests': {k: v['requests'] for k, v in traffic.items()}}
        if drill in CERTIFICATE_DRILLS:
            before = record['before']['preflight']['clusters'][self.cluster]['certificates']
            after = record['after']['certificates'][self.cluster]
            verdicts['certificates renewed'] = {
                'pass': all((after.get(n, {}).get('revision') or 0) > (before.get(n, {}).get('revision') or 0) and after.get(n, {}).get('ready') == 'True'
                            for n in CERTIFICATE_DRILLS[drill]),
                'revisions': {n: [before.get(n, {}).get('revision'), after.get(n, {}).get('revision')] for n in CERTIFICATE_DRILLS[drill]}}
        if drill.startswith('R'):
            verdicts['0 failed allowed probes'] = {'pass': all(v['failures'] == 0 for v in allowed.values()),
                                                  'failures': {k: v['failures'] for k, v in allowed.items()}}
            verdicts['no withdrawal on any agent'] = {'pass': all(n == 0 for n in withdrawn.values()), 'withdrawn': withdrawn}
            if drill == 'R5':
                verdicts['SPIRE rotate exit 0'] = {'pass': all(e['exit'] == 0 for e in record.get('event', [])), 'event': record.get('event')}
            if drill == 'R6':
                before = record['before'].get('ztunnelCertificates', {})
                after = record['after'].get('ztunnelCertificates', {})
                changed = {k: [c.get('leaf', {}).get('serialNumber') for c in before.get(k, [])] != [c.get('leaf', {}).get('serialNumber') for c in after.get(k, [])] for k in after}
                verdicts['every ztunnel renewed its workload certificates'] = {'pass': bool(changed) and all(changed.values()), 'changed': changed}
        else:
            into = traffic.get(f'{self.peer}-crosscluster', {})
            others = {k: v for k, v in allowed.items() if k != f'{self.peer}-crosscluster'}
            verdicts['this cluster withdrew the peer'] = {
                'pass': any(n > 0 for k, n in withdrawn.items() if k.startswith(self.cluster + '/')), 'withdrawn': withdrawn}
            verdicts['the path into this cluster failed closed and recovered'] = {
                'pass': into.get('failures', 0) > 0 and into.get('longestFailureRun', {}).get('firstGoodAfter') is not None
                        and all(c.split('/')[1] in ('000', '') for c in into.get('longestFailureRun', {}).get('codes', [])),
                'path': into}
            verdicts['every other allowed path 0 failed'] = {'pass': all(v['failures'] == 0 for v in others.values()),
                                                             'failures': {k: v['failures'] for k, v in others.items()}}
            if drill in ('neg-ca', 'neg-pin'):
                restored = record.get('event', [{}])[-1]
                verdicts['the Helm-managed object was put back'] = {'pass': bool(restored.get('specRestored') or restored.get('dataRestored')), 'event': restored}
            if drill == 'neg-peer-down':
                left = record.get('event', [{}])[-1].get('leftoverDropRules', {'?': ['unknown']})
                verdicts['no DROP rule left on the nodes'] = {'pass': all(not v for v in left.values()), 'leftover': left}
        return verdicts

    def write_readme(self, record):
        lines = [f'# Rotation drill {record["drill"]} on {record["cluster"]}, {record["startedAt"][:19]}Z', '',
                 'State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,',
                 '`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).', '',
                 f'Event: {clock(record.get("eventStartedAt"))} to {clock(record.get("eventEndedAt"))}. Probe window: {record["seconds"]} s, one probe per second per path.', '',
                 '| Path | Expect | Requests | Failures | Longest failure run | Codes |', '|---|---|---|---|---|---|']
        for name, t in record['traffic'].items():
            lfr = t.get('longestFailureRun')
            span = f'{clock(lfr["firstFailure"])}-{clock(lfr["lastFailure"])} ({lfr["count"]})' if lfr else '-'
            lines.append(f'| `{name}` | {t["expect"]} | {t["requests"]} | {t["failures"]} | {span} | {", ".join(lfr["codes"]) if lfr else "-"} |')
        lines += ['', '| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |', '|---|---|---|---|---|---|']
        for key, e in record['agentEvents'].items():
            lines.append(f'| `{key}` | {e["lines"]} | {e["event=withdrawn"]} | {e["event=projected"]} | {e["refresh-origin-transport"]} | {e["restart-origin-watch"]} |')
        lines += ['', '| Verdict | Result |', '|---|---|']
        for name, v in record['verdicts'].items():
            lines.append(f'| {name} | {"pass" if v["pass"] else "FAIL"} |')
        if 'eventError' in record:
            lines += ['', f'Event error: `{record["eventError"]}`']
        (self.out / 'README.md').write_text('\n'.join(lines) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('plan', 'preflight'):
        sub.add_parser(name).add_argument('--out', required=True, help='record directory (new or empty)')
    d = sub.add_parser('drill')
    d.add_argument('drill', choices=DRILLS)
    d.add_argument('--out', required=True, help='record directory (new or empty)')
    d.add_argument('--cluster', required=True, choices=sorted(PINS), help='the cluster whose credential is renewed')
    d.add_argument('--seconds', type=int, default=150, help='probe window (default 150)')
    d.add_argument('--lead', type=int, default=20, help='seconds of probes before the event (default 20)')
    d.add_argument('--between', type=int, default=10, help='seconds between the commands of a multi-command drill (R4)')
    d.add_argument('--hold', type=int, default=60, help='seconds a negative change stays applied (neg-ca, neg-pin)')
    d.add_argument('--down-seconds', type=int, default=120, help='seconds the peer node port is dropped (neg-peer-down)')
    d.add_argument('--allow-helm-object-change', action='store_true', help='required by neg-ca and neg-pin')
    d.add_argument('--execute', action='store_true', help='without it the drill is a dry run')
    args = parser.parse_args()
    if args.command != 'drill':
        args.drill, args.cluster, args.execute, args.seconds, args.lead = None, None, False, None, None
    try:
        drill = Drill(args)
        if args.command == 'plan':
            drill.plan()
            return 0
        if args.command == 'preflight':
            print(json.dumps(drill.preflight(), indent=1))
            return 0
        return drill.drill()
    except Refusal as e:
        print('refused: ' + str(e), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
