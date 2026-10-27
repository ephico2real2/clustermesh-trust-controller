#!/usr/bin/env python3
"""Write the Cilium values of one cluster of a CMTC lab environment.

The shared settings are files under config/lab/cilium/. This writes what belongs to one cluster:

- its constants, derived from the environment file (config/lab/environments/<env>.yaml) with the names of
  MESH_PKI.md: cluster name and ID, API server host, ClusterMesh and Hubble issuer, whether it runs the Hubble Relay
  and UI (the control cluster only), SPIRE trust domain and delegated socket, and the mesh clusters that ztunnel
  reaches over HBONE only;
- its instance data, which exists only once the lab runs: the mesh trust bundle, the ClusterMesh peer addresses,
  and the server-key pins of the remote clustermesh-apiservers that ztunnel's direct-origin reader verifies.

  --fresh      compute the instance data: the root from --root, node addresses from kind, each peer's pin from its
               server certificate. For a new lab.
  --from-live  read it back from the running lab, for a Helm adoption that must change nothing: the trust bundle and
               origin peers from their ConfigMaps, the ClusterMesh peers from the release values (cilium_release.py
               check compares the rendered cilium-clustermesh Secret with the live one).

Only public material is read: certificates, never a private key.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

import yaml

NODE_PORT = 32379
NAME = re.compile(r'^[a-z][a-z0-9-]{0,30}[a-z0-9]$')


def load_environment(path: pathlib.Path) -> dict:
    env = yaml.safe_load(path.read_text())
    names = [c['name'] for c in env['clusters']]
    ids = [c['id'] for c in env['clusters']]
    if len(set(names)) != len(names) or len(set(ids)) != len(ids):
        raise SystemExit(f'{path}: cluster names and IDs must be unique')
    for name in names:
        if not NAME.match(name):
            raise SystemExit(f'{path}: cluster name {name!r} is not a DNS label')
    if env['controlCluster'] not in names:
        raise SystemExit(f'{path}: controlCluster {env["controlCluster"]!r} is not a cluster')
    return env


class Lab:
    def __init__(self, env: dict, kubeconfig: str | None):
        self.env = env
        self.kubeconfig = kubeconfig

    def kubectl(self, cluster: str, *args: str) -> str:
        cmd = ['kubectl', '--context', f'kind-{cluster}'] + (['--kubeconfig', self.kubeconfig] if self.kubeconfig else [])
        return subprocess.run(cmd + list(args), check=True, text=True, capture_output=True).stdout

    def helm_values(self, cluster: str) -> dict:
        cmd = ['helm', '--kube-context', f'kind-{cluster}', '-n', 'kube-system', 'get', 'values', 'cilium', '-o', 'json']
        if self.kubeconfig:
            cmd += ['--kubeconfig', self.kubeconfig]
        return json.loads(subprocess.run(cmd, check=True, text=True, capture_output=True).stdout)

    def server_cert(self, cluster: str) -> str:
        # jsonpath selects tls.crt only; the Secret's key never leaves the API server.
        data = self.kubectl(cluster, '-n', 'kube-system', 'get', 'secret', 'clustermesh-apiserver-server-cert',
                            '-o', 'jsonpath={.data.tls\\.crt}')
        return base64.b64decode(data).decode()

    def node_ips(self, cluster: str) -> list[str]:
        script = pathlib.Path(__file__).with_name('kind-node-ips.py')
        environ = dict(os.environ, DOCKER_CONTEXT=self.env['dockerContext'])
        out = subprocess.run([sys.executable, str(script), cluster], check=True, text=True, capture_output=True,
                             env=environ).stdout
        return json.loads(out)


def spki_sha256(cert_pem: str) -> str:
    """SHA-256 of the certificate's DER SubjectPublicKeyInfo, the form ztunnel-origin-config pins."""
    pub = subprocess.run(['openssl', 'x509', '-pubkey', '-noout'], input=cert_pem, check=True, text=True,
                         capture_output=True).stdout
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pub.encode(), check=True,
                         capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


def constants(env: dict, cluster: str) -> dict:
    me = next(c for c in env['clusters'] if c['name'] == cluster)
    # The Hubble Relay (and the UI behind it) runs in the control cluster only: its peer service lists every node of
    # the ClusterMesh, so one Relay observes both clusters, and it verifies each agent against the mesh root.
    control = cluster == env['controlCluster']
    return {
        'cluster': {'name': cluster, 'id': me['id']},
        'k8sServiceHost': f'{cluster}-control-plane',
        'clustermesh': {'apiserver': {'tls': {'auto': {'certManagerIssuerRef': {
            'name': f'{cluster}-clustermesh-intermediate'}}}}},
        'hubble': {'tls': {'auto': {'certManagerIssuerRef': {'name': f'{cluster}-clustermesh-intermediate'}}},
                   'relay': {'enabled': control}, 'ui': {'enabled': control}},
        'encryption': {'ztunnel': {
            'spire': {'trustDomain': f'{cluster}.mesh.example',
                      'delegatedSocketPath': f'/run/cmtc-spire/{cluster}/delegated/delegated.sock'},
            'mesh': {'clusters': [{'clusterId': c['name'], 'trustDomain': f'{c["name"]}.mesh.example',
                                   'podCidrs': [c['podCIDR']], 'serviceCidrs': [c['serviceCIDR']]}
                                  for c in env['clusters']]}}},
    }


def fresh(lab: Lab, cluster: str, root: pathlib.Path) -> dict:
    clusters = lab.env['clusters']
    return {
        'tls': {'caBundle': {'content': root.read_text()}},
        'clustermesh': {'config': {'clusters': [
            {'name': c['name'], 'ips': lab.node_ips(c['name']), 'port': NODE_PORT} for c in clusters]}},
        'encryption': {'ztunnel': {'remoteWorkloadMembership': {'peers': [
            {'name': c['name'], 'clusterID': c['id'], 'port': NODE_PORT, 'ips': lab.node_ips(c['name']),
             'spkiSha256': [spki_sha256(lab.server_cert(c['name']))]} for c in clusters if c['name'] != cluster]}}},
    }


def from_live(lab: Lab, cluster: str) -> dict:
    bundle = json.loads(lab.kubectl(cluster, '-n', 'kube-system', 'get', 'cm', 'cmtc-public-root', '-o', 'json'))
    origin = json.loads(lab.kubectl(cluster, '-n', 'kube-system', 'get', 'cm', 'ztunnel-origin-config', '-o', 'json'))
    peers = []
    for name, text in sorted(origin['data'].items()):
        cfg = yaml.safe_load(text)
        aliases = [a for a in cfg['cilium-host-aliases'] if a['hostname'] == f'{name}.mesh.cilium.io']
        endpoint = cfg['endpoints'][0]
        if len(aliases) != 1 or not endpoint.startswith(f'https://{name}.mesh.cilium.io:'):
            raise SystemExit(f'ztunnel-origin-config {name}: unexpected endpoint or host aliases')
        pins = cfg['cilium-remote-peer']['spki-sha256']
        current = spki_sha256(lab.server_cert(name))
        if current not in pins:
            raise SystemExit(f'ztunnel-origin-config {name}: no pin matches the peer server key {current}')
        peers.append({'name': name, 'clusterID': cfg['cilium-remote-peer']['cluster-id'],
                      'port': int(endpoint.rsplit(':', 1)[1]), 'ips': aliases[0]['ips'], 'spkiSha256': pins})
    return {
        'tls': {'caBundle': {'content': bundle['data']['ca.crt']}},
        'clustermesh': {'config': {'clusters': lab.helm_values(cluster)['clustermesh']['config']['clusters']}},
        'encryption': {'ztunnel': {'remoteWorkloadMembership': {'peers': peers}}},
    }


def merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for key, value in extra.items():
        out[key] = merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('environment', type=pathlib.Path)
    ap.add_argument('cluster')
    ap.add_argument('out', type=pathlib.Path)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--fresh', action='store_true')
    mode.add_argument('--from-live', action='store_true')
    mode.add_argument('--constants-only', action='store_true', help='no instance data (first install)')
    ap.add_argument('--without-ztunnel', action='store_true',
                    help='leave out the ztunnel constants (encryption.*): the chart refuses them while encryption is '
                         'off, as on a lab before its strict layer (scripts/lab/up.sh)')
    ap.add_argument('--root', type=pathlib.Path, help='mesh root certificate (PEM), with --fresh')
    ap.add_argument('--kubeconfig')
    args = ap.parse_args()
    env = load_environment(args.environment)
    if args.cluster not in {c['name'] for c in env['clusters']}:
        ap.error(f'{args.cluster} is not a cluster of {args.environment}')
    if args.fresh and not args.root:
        ap.error('--fresh needs --root')
    lab = Lab(env, args.kubeconfig)
    values = constants(env, args.cluster)
    if args.fresh:
        values = merge(values, fresh(lab, args.cluster, args.root))
    elif args.from_live:
        values = merge(values, from_live(lab, args.cluster))
    if args.without_ztunnel:
        del values['encryption']
    if 'PRIVATE KEY' in json.dumps(values):
        raise SystemExit('refusing to write values that contain a private key')
    args.out.write_text(json.dumps(values, indent=2) + '\n')


if __name__ == '__main__':
    main()
