#!/usr/bin/env python3
"""DNS probes from enrolled Pods on one lab cluster (operational harness, not product code).

Successor of the review harness dns-fix/runners/dns_probes.py. It adds DNS over TCP (RFC 7766), a parsed answer for
every TCP query, the full name of the kubernetes Service (BusyBox nslookup does not apply the search list, so the short
name returns NXDOMAIN on enrolled and unenrolled Pods alike), and TCP/53 to non-resolvers on the negative side.

positive: from both enrolled clients, over UDP (nslookup) and TCP: the kubernetes Service and both Global Service
          names must resolve to their ClusterIPs; then curl each Global Service by ClusterIP on 80, 8080 and 31337 and
          the reply must name the serving cluster. Both unenrolled Pods repeat the TCP queries as the control: they
          show the resolver answers TCP, so an enrolled failure is the mesh path.
negative: from enrolled client-worker, with `cilium-dbg monitor --type drop` on its node's agent: DNS over UDP and
          over TCP to a server Pod (not a resolver) and to 1.1.1.1; TCP to a CoreDNS Pod on 8080 and 9153; plaintext
          UDP to a server Pod on 80, 8080 and 31337. Every probe must fail; its drop lines are kept.

Every kubectl call is preceded by a kube-system UID check. Results go to OUT/<cluster>-<mode>-<stamp>.json.
Usage: dns_probes.py --cluster cmtc-a --out DIR {positive,negative}
"""
import argparse
import ipaddress
import json
import re
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

KUBECONFIG = '/private/tmp/cmtc-a-b-20261024.kubeconfig'
PINS = {'cmtc-a': 'bb7182c7-de95-4e70-816a-a1400d755794', 'cmtc-b': 'f2687af6-bd96-45a3-98a2-d1397a3ee244'}
NS = 'cmtc-live-mtls'
NEG = NS + '-unauth'
PORTS = (80, 8080, 31337)
CLIENTS = ('client-worker', 'client-control-plane')
CONTROLS = ('unregistered-worker', 'unregistered-control-plane')
KUBERNETES = 'kubernetes.default.svc.cluster.local'
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}


def now():
    return datetime.now(timezone.utc).isoformat()


def dns_query(name, qid):
    """One recursive A query for name, with the two-byte length prefix DNS over TCP requires (RFC 7766 section 8)."""
    labels = b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.rstrip('.').split('.'))
    message = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', 1, 1)
    return struct.pack('!H', len(message)) + message


def printf_octal(data):
    """data as a printf format of octal escapes only, so no byte can be read as a % directive or a shell character."""
    return ''.join(f'\\{b:03o}' for b in data)


def _skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def parse_dns_reply(data, qid):
    """Parse one length-prefixed DNS over TCP reply. Returns the rcode and the A addresses, or the reason it is not
    a reply to qid. Every reason names what was received, so a failed row explains itself."""
    if len(data) < 2:
        return {'answered': False, 'reason': f'{len(data)} bytes received'}
    (size,) = struct.unpack('!H', data[:2])
    msg = data[2:2 + size]
    if size < 12 or len(msg) < size:
        return {'answered': False, 'reason': f'length prefix {size}, {len(data) - 2} bytes followed'}
    rid, flags, qd, an = struct.unpack('!HHHH', msg[:8])
    if rid != qid or not flags & 0x8000:
        return {'answered': False, 'reason': f'not a reply to query {qid:#06x}: id {rid:#06x}, flags {flags:#06x}'}
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    addresses = []
    for _ in range(an):
        i = _skip_name(msg, i)
        rtype, _, _, rdlen = struct.unpack('!HHIH', msg[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            addresses.append(str(ipaddress.IPv4Address(msg[i:i + 4])))
        i += rdlen
    rcode = flags & 0xF
    return {'answered': True, 'rcode': RCODES.get(rcode, str(rcode)), 'addresses': addresses}


class Cluster:
    def __init__(self, name):
        self.name = name

    def kubectl(self, *args, check=True, timeout=120):
        r = subprocess.run(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + self.name, *args],
                           capture_output=True, text=True, timeout=timeout)
        if 'PRIVATE KEY' in r.stdout + r.stderr:
            raise RuntimeError('private material in output')
        if check and r.returncode != 0:
            raise RuntimeError(f'kubectl {args[:5]}: {r.stderr[:2000]}')
        return r

    def get(self, *args):
        return json.loads(self.kubectl(*args, '-o', 'json').stdout)

    def exec_sh(self, ns, pod, script, *argv):
        """Run script in the Pod. Returns the script's exit status, never kubectl's."""
        wrapped = script + '; r=$?; printf "\\nCMTC_RC=%s\\n" "$r"; exit 0'
        r = self.kubectl('-n', ns, 'exec', pod, '--', 'sh', '-c', wrapped, 'sh', *argv, check=False, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f'exec in {ns}/{pod} failed (not a traffic result): {r.stderr[:500]}')
        m = re.search(r'CMTC_RC=(\d+)', r.stdout)
        if not m:
            raise RuntimeError('missing completion marker')
        return int(m[1]), r.stdout, r.stderr

    def nslookup(self, pod, name, server=None):
        rc, out, err = self.exec_sh(NS, pod, 'timeout 12 nslookup "$@"', name, *([server] if server else []))
        # The server's own line is "Address: ip:53"; answer lines carry the bare address.
        addresses = re.findall(r'^Address:\s*([0-9.]+)\s*$', out, re.M)
        return {'at': now(), 'context': 'kind-' + self.name, 'client': pod, 'probe': 'dns-udp', 'name': name,
                'server': server, 'rc': rc, 'resolved': rc == 0 and 'Name:' in out, 'addresses': addresses,
                'stdout': out, 'stderr': err}

    def tcp_dns(self, ns, pod, name, server):
        qid = time.time_ns() & 0xFFFF
        script = 'printf "$1" | timeout 8 nc -w 5 "$2" 53 | od -An -tx1 -v'
        rc, out, err = self.exec_sh(ns, pod, script, printf_octal(dns_query(name, qid)), server)
        hexed = out.split('CMTC_RC=')[0]
        reply = bytes.fromhex(''.join(re.findall(r'\b[0-9a-f]{2}\b', hexed)))
        return dict({'at': now(), 'context': 'kind-' + self.name, 'client': f'{ns}/{pod}', 'probe': 'dns-tcp',
                     'name': name, 'server': server, 'queryID': qid, 'rc': rc, 'replyBytes': len(reply),
                     'stderr': err}, **parse_dns_reply(reply, qid))

    def curl(self, pod, url, expected):
        rc, out, err = self.exec_sh(NS, pod, 'curl -sS -i --connect-timeout 3 --max-time 6 "$1"', url)
        http200 = bool(re.search(r'^HTTP/\S+ 200 ', out, re.M))
        ok = rc == 0 and http200 and (expected is None or f'"cluster": "{expected}"' in out)
        return {'at': now(), 'context': 'kind-' + self.name, 'client': pod, 'probe': 'curl', 'url': url,
                'curlRC': rc, 'http200': http200, 'expectedCluster': expected, 'positiveMatch': ok,
                'stdout': out, 'stderr': err}

    def udp_send(self, pod, ip, port):
        # BusyBox nc: the send succeeds locally whatever happens on the wire, so the proof is the drop line.
        rc, out, err = self.exec_sh(NS, pod, 'printf "cmtc-plaintext-probe" | timeout 4 nc -u -w1 "$1" "$2"',
                                    ip, str(port))
        return {'at': now(), 'context': 'kind-' + self.name, 'client': pod, 'probe': 'udp', 'dst': f'{ip}:{port}',
                'rc': rc, 'reply': out.split('CMTC_RC=')[0].strip(), 'stdout': out, 'stderr': err}

    def agent_on(self, node):
        pods = self.get('-n', 'kube-system', 'get', 'pods', '-l', 'k8s-app=cilium',
                        '--field-selector', 'spec.nodeName=' + node)['items']
        if len(pods) != 1:
            raise RuntimeError(f'{len(pods)} Cilium agents on {node}')
        return pods[0]['metadata']['name']


def positive(c, out, stamp):
    svcs = {s['metadata']['name']: s['spec']['clusterIP'] for s in c.get('-n', NS, 'get', 'svc')['items']}
    want = {KUBERNETES: c.get('-n', 'default', 'get', 'svc', 'kubernetes')['spec']['clusterIP']}
    for dest in PINS:
        want[f'server-{dest}.{NS}.svc.cluster.local'] = svcs['server-' + dest]
    resolver = c.get('-n', 'kube-system', 'get', 'svc', 'kube-dns')['spec']['clusterIP']
    rows = []
    for pod in CLIENTS:
        for name, addr in want.items():
            rows.append(dict(c.nslookup(pod, name), role='enrolled', expectedAddress=addr))
            rows.append(dict(c.tcp_dns(NS, pod, name, resolver), role='enrolled', expectedAddress=addr))
        for dest in PINS:
            for port in PORTS:
                rows.append(dict(c.curl(pod, f'http://{svcs["server-" + dest]}:{port}/?cmtc={time.time_ns()}', dest),
                                 role='enrolled'))
    for pod in CONTROLS:
        rows.append(dict(c.tcp_dns(NEG, pod, KUBERNETES, resolver), role='control', expectedAddress=want[KUBERNETES]))
    for r in rows:
        if r['probe'] == 'dns-udp':
            r['match'] = r['resolved'] and r['expectedAddress'] in r['addresses']
        elif r['probe'] == 'dns-tcp':
            r['match'] = r['answered'] and r['rcode'] == 'NOERROR' and r['expectedAddress'] in r['addresses']
        else:
            r['match'] = r['positiveMatch']
    path = out / f'{c.name}-positive-{stamp}.json'
    path.write_text(json.dumps(rows, indent=2) + '\n')
    tally = {}
    for r in rows:
        key = f"{r['role']} {r['probe']}"
        ok, n = tally.get(key, (0, 0))
        tally[key] = (ok + r['match'], n + 1)
    print(json.dumps({'context': c.name, 'file': str(path), 'resolver': resolver,
                      'passed': {k: f'{ok}/{n}' for k, (ok, n) in tally.items()}}))
    for r in rows:
        if r['probe'] != 'curl':
            seen = ','.join(r.get('addresses', [])) or r.get('reason') or r.get('rcode') or f"rc={r['rc']}"
            print(f"  {r['client']:42} {r['probe']:7} {r['name']:45} {'OK ' if r['match'] else 'FAIL'} {seen}")
    return all(r['match'] for r in rows)


def negative(c, out, stamp):
    pods = {p['metadata']['name']: p for p in c.get('-n', NS, 'get', 'pods')['items']}
    client = pods['client-worker']
    node, client_ip = client['spec']['nodeName'], client['status']['podIP']
    server_ip = pods['server-control-plane']['status']['podIP']
    coredns_ip = c.get('-n', 'kube-system', 'get', 'pods', '-l', 'k8s-app=kube-dns')['items'][0]['status']['podIP']
    agent = c.agent_on(node)
    mon_path = out / f'{c.name}-negative-{stamp}-monitor-{node}.txt'
    with open(mon_path, 'w') as mon_out:
        mon = subprocess.Popen(['kubectl', '--kubeconfig', KUBECONFIG, '--context', 'kind-' + c.name,
                                '-n', 'kube-system', 'exec', agent, '-c', 'cilium-agent', '--', 'timeout', '110',
                                'cilium-dbg', 'monitor', '--type', 'drop', '--type', 'policy-verdict'],
                               stdout=mon_out, stderr=subprocess.STDOUT, text=True)
        time.sleep(4)
        rows = [
            dict(c.nslookup('client-worker', KUBERNETES, server_ip), case='DNS over UDP to a server Pod (not a resolver)'),
            dict(c.nslookup('client-worker', KUBERNETES, '1.1.1.1'), case='DNS over UDP to 1.1.1.1 (world)'),
            dict(c.tcp_dns(NS, 'client-worker', KUBERNETES, server_ip), case='DNS over TCP to a server Pod (not a resolver)'),
            dict(c.tcp_dns(NS, 'client-worker', KUBERNETES, '1.1.1.1'), case='DNS over TCP to 1.1.1.1 (world)'),
            dict(c.curl('client-worker', f'http://{coredns_ip}:8080/health', None), case='TCP to CoreDNS on 8080'),
            dict(c.curl('client-worker', f'http://{coredns_ip}:9153/metrics', None), case='TCP to CoreDNS on 9153'),
        ]
        for port in PORTS:
            rows.append(dict(c.udp_send('client-worker', server_ip, port), case=f'plaintext UDP to a server Pod on {port}'))
        mon.wait(timeout=150)
    monitor = mon_path.read_text()
    for r in rows:
        if r['probe'] == 'dns-udp':
            r['failed'], dst = not r['resolved'], (r['server'], 53, 'udp')
        elif r['probe'] == 'dns-tcp':
            r['failed'], dst = not r['answered'], (r['server'], 53, 'tcp')
        elif r['probe'] == 'curl':
            host, port = r['url'].split('/')[2].split(':')
            r['failed'], dst = not r['http200'], (host, int(port), 'tcp')
        else:
            ip, port = r['dst'].split(':')
            r['failed'], dst = 'cmtc' not in r['reply'], (ip, int(port), 'udp')
        pat = re.compile(rf'drop .*{re.escape(client_ip)}:\d+ -> {re.escape(dst[0])}:{dst[1]} {dst[2]}')
        r['dropLines'] = [line for line in monitor.splitlines() if pat.search(line)]
    path = out / f'{c.name}-negative-{stamp}.json'
    path.write_text(json.dumps({'client': 'client-worker', 'clientIP': client_ip, 'node': node, 'agent': agent,
                                'monitor': str(mon_path), 'rows': rows}, indent=2) + '\n')
    print(json.dumps({'context': c.name, 'file': str(path), 'monitor': str(mon_path),
                      'failedAsRequired': f"{sum(r['failed'] for r in rows)}/{len(rows)}",
                      'withDropLine': f"{sum(bool(r['dropLines']) for r in rows)}/{len(rows)}"}))
    for r in rows:
        print(f"  {r['case']:46} failed={r['failed']} drop={r['dropLines'][0].strip() if r['dropLines'] else 'NONE'}")
    return all(r['failed'] for r in rows)


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('mode', choices=['positive', 'negative'])
    a.add_argument('--cluster', choices=list(PINS), required=True)
    a.add_argument('--out', required=True)
    x = a.parse_args()
    c = Cluster(x.cluster)
    uid = c.get('get', 'ns', 'kube-system')['metadata']['uid']
    if uid != PINS[x.cluster]:
        raise SystemExit(f'{x.cluster}: kube-system UID {uid} does not match the pin')
    out = Path(x.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    ok = positive(c, out, stamp) if x.mode == 'positive' else negative(c, out, stamp)
    raise SystemExit(0 if ok else 1)


if __name__ == '__main__':
    main()
