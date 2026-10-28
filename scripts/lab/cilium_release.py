#!/usr/bin/env python3
"""Render and check the Cilium Helm release of one CMTC lab cluster from the repository's values.

The values files, in order (later files win):
  config/lab/cilium/base.yaml       shared settings
  <image values>                    the image lock, rendered by scripts/cilium/prepare.sh
  config/lab/cilium/ztunnel.yaml    strict workload mTLS, with --strict
  <environment extraCiliumValues>   deliberate differences of that environment
  <cluster values>                  scripts/lab/cilium_cluster_values.py

Subcommands:
  files     print the helm -f arguments
  render    print the manifest (helm template)
  check     compare the render with the live cluster; exit 1 on any difference. Differences are set fields that
            differ, extra live entries in data maps, keyed lists and args, and list order (an order change in a pod
            template rolls every Pod). Fields the API server fills in are ignored. Secrets are compared, never
            printed. It also lists release objects the render drops (helm would delete them) and rendered objects
            that exist outside the release (the upgrade takes them over).

The one-time Helm adoption of a lab created before these files (plan, transfer, restore-owners, upgrade) is
cilium_adopt.py.
"""
import argparse
import json
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
RELEASE, NAMESPACE = 'cilium', 'kube-system'


class Cluster:
    def __init__(self, name: str, kubeconfig: str | None):
        self.name, self.kubeconfig = name, kubeconfig

    def kubectl(self, *args: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
        cmd = ['kubectl', '--context', f'kind-{self.name}'] + (['--kubeconfig', self.kubeconfig] if self.kubeconfig else [])
        r = subprocess.run(cmd + list(args), text=True, capture_output=True, input=input)
        if check and r.returncode:
            raise SystemExit(f'kubectl {" ".join(args[:3])}: {r.stderr.strip()}')
        return r

    def helm(self, *args: str) -> str:
        cmd = ['helm', '--kube-context', f'kind-{self.name}', '-n', NAMESPACE] + list(args)
        if self.kubeconfig:
            cmd += ['--kubeconfig', self.kubeconfig]
        return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout

    def get(self, obj: dict, managed_fields: bool = False) -> dict | None:
        ns = obj['metadata'].get('namespace')
        r = self.kubectl('get', obj['kind'], obj['metadata']['name'], '-o', 'json', *(['-n', ns] if ns else []),
                         *(['--show-managed-fields'] if managed_fields else []), check=False)
        if r.returncode == 0:
            return json.loads(r.stdout)
        if 'NotFound' in r.stderr:
            return None
        raise SystemExit(f'kubectl get {obj["kind"]}/{obj["metadata"]["name"]}: {r.stderr.strip()}')


def values_files(args) -> list[str]:
    env = yaml.safe_load(pathlib.Path(args.environment).read_text())
    files = [str(ROOT / 'config/lab/cilium/base.yaml'), args.image_values]
    if args.strict:
        files.append(str(ROOT / 'config/lab/cilium/ztunnel.yaml'))
    files += [str(ROOT / f) for f in env.get('extraCiliumValues', [])]
    files.append(args.cluster_values)
    for f in files:
        if not pathlib.Path(f).is_file():
            raise SystemExit(f'missing values file {f}')
    return files


def render(args) -> str:
    # --is-upgrade: every subcommand works on an existing release, so templates see .Release.IsUpgrade as helm
    # upgrade does.
    cmd = ['helm', 'template', RELEASE, args.chart, '-n', NAMESPACE, '--is-upgrade']
    for f in values_files(args):
        cmd += ['-f', f]
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout


def objects(manifest: str) -> list[dict]:
    # PyYAML reads YAML 1.1 as Kubernetes does (defaultMode: 0400 is 256).
    return [d for d in yaml.safe_load_all(manifest) if d]


def ident(o: dict) -> str:
    """Kind with API group, namespace and name: two objects with the same kind and name stay apart."""
    group = o['apiVersion'].rpartition('/')[0]
    ns = o['metadata'].get('namespace')
    return f'{o["kind"]}{"." + group if group else ""}/{ns + "/" if ns else ""}{o["metadata"]["name"]}'


DEFAULTS = (0, False, '', None, {}, [])


def keyed(items) -> dict | None:
    if items and all(isinstance(x, dict) and 'name' in x for x in items):
        return {x['name']: x for x in items}
    return None


def compare(want, got, path: str, out: list) -> None:
    if isinstance(want, dict):
        if not isinstance(got, dict):
            out.append(('type', path, want, got))
            return
        for k, v in want.items():
            if k not in got:
                if v not in DEFAULTS:
                    out.append(('missing-live', f'{path}.{k}', v, None))
                continue
            compare(v, got[k], f'{path}.{k}', out)
        if path.endswith('.data'):
            out += [('extra-live', f'{path}.{k}', None, got[k]) for k in got if k not in want]
    elif isinstance(want, list):
        kw, kg = keyed(want), keyed(got if isinstance(got, list) else [])
        if kw is not None and kg is not None:
            for n, v in kw.items():
                if n in kg:
                    compare(v, kg[n], f'{path}[{n}]', out)
                else:
                    out.append(('missing-live', f'{path}[{n}]', v, None))
            out += [('extra-live', f'{path}[{n}]', None, kg[n]) for n in kg if n not in kw]
            if [n for n in kw if n in kg] != [n for n in kg if n in kw]:
                out.append(('order', path, list(kw), list(kg)))
        elif not (isinstance(got, list) and len(want) == len(got)):
            out.append(('list', path, want, got))
        else:
            for i, (w, g) in enumerate(zip(want, got)):
                compare(w, g, f'{path}[{i}]', out)
    elif want != got and str(want) != str(got):
        # str() equates a quantity rendered as 1 with the API server's "1".
        out.append(('value', path, want, got))


def check(args, cluster: Cluster) -> int:
    rendered = objects(render(args))
    released = {ident(o) for o in objects(cluster.helm('get', 'manifest', RELEASE))}
    differences, adopt = 0, []
    for o in rendered:
        live = cluster.get(o)
        name = ident(o)
        if live is None:
            print(f'{name}: not in the cluster (helm upgrade creates it)')
            continue
        if name not in released:
            adopt.append(name)
        if o['kind'] == 'Secret':
            same = live.get('data', {}) == o.get('data', {})
            if not same:
                differences += 1
                print(f'{name}: data differs (keys: {sorted(set(live.get("data", {})) ^ set(o.get("data", {}))) or "same"})')
            continue
        found: list = []
        compare({k: v for k, v in o.items() if k not in ('metadata', 'status')}, live, '', found)
        for kind, path, want, got in found:
            differences += 1
            print(f'{name}: {kind:12} {path}\n    render={json.dumps(want)[:300]}\n    live  ={json.dumps(got)[:300]}')
    dropped = sorted(released - {ident(o) for o in rendered})
    for name in dropped:
        print(f'{name}: in the release, not rendered (helm upgrade deletes it)')
    for name in adopt:
        print(f'{name}: exists outside the release (the upgrade takes it over)')
    print(f'{cluster.name}: {differences} difference(s), {len(dropped)} to delete, {len(adopt)} to take over')
    return 1 if differences or dropped else 0


def parser(doc: str, commands: list[str]) -> argparse.ArgumentParser:
    """The arguments that cilium_release.py and cilium_adopt.py share."""
    ap = argparse.ArgumentParser(description=doc.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=doc)
    ap.add_argument('command', choices=commands)
    ap.add_argument('environment', help='config/lab/environments/<env>.yaml')
    ap.add_argument('cluster')
    ap.add_argument('--chart', default=None, help='chart directory (default: .tmp/cilium-chart-path)')
    ap.add_argument('--image-values', default=str(ROOT / '.tmp/cilium-image-values.json'))
    ap.add_argument('--cluster-values', required=True, help='output of cilium_cluster_values.py')
    ap.add_argument('--strict', action='store_true', help='add the strict workload mTLS layer (ztunnel.yaml)')
    ap.add_argument('--kubeconfig')
    return ap


def default_chart(args) -> None:
    if args.chart is None:
        args.chart = (ROOT / '.tmp/cilium-chart-path').read_text().strip()


def main() -> None:
    args = parser(__doc__, ['files', 'render', 'check']).parse_args()
    default_chart(args)
    cluster = Cluster(args.cluster, args.kubeconfig)
    if args.command == 'files':
        print(' '.join(f'-f {f}' for f in values_files(args)))
    elif args.command == 'render':
        sys.stdout.write(render(args))
    else:
        sys.exit(check(args, cluster))


if __name__ == '__main__':
    main()
