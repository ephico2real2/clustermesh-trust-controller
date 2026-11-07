#!/usr/bin/env python3
"""The one-time Helm adoption of the CMTC objects that were applied by hand before the cmtc release existed.

The labs run CMTC from kubectl apply and kubectl patch (no `cmtc` release). Under server-side apply, helm removes only
fields it owned, and a field that a kubectl manager also owns makes every later upgrade that changes it conflict. This
gives helm those fields first, with the field-transfer functions of cilium_adopt.py, so `helm upgrade --install
--take-ownership` adopts the objects without --force-conflicts.

Subcommands (the render is `helm template cmtc charts/cmtc -n cmtc-system -f VALUES --set ...`):
  plan      a server-side dry-run apply of the render as field manager helm, with the release metadata Helm adds,
            compared with live; exit 1 on a conflict or an object of another release. Lists the kubectl managers'
            entries that are left.
  transfer  give helm the fields that kubectl patch, edit and client-side apply own in the rendered objects; writes
            metadata.managedFields only (with a backup of the first managedFields in --backup-dir) and stops if
            anything else changed. Restore with cilium_adopt.py's restore-owners semantics: the backup holds the
            original entries.
Secrets are never read or printed: the chart renders none.

Usage: cmtc_adopt.py plan|transfer CLUSTER VALUES [--set KEY=VALUE ...] [--backup-dir DIR] [--kubeconfig FILE]
"""
import argparse
import json
import pathlib
import subprocess
import sys

from cilium_adopt import FIELD_MANAGER, KUBECTL_MANAGERS, changes, comparable, field_paths, json_stream, \
    kubectl_owned, transferred, write_managed_fields
from cilium_release import ROOT, Cluster, ident, objects

RELEASE, NAMESPACE = 'cmtc', 'cmtc-system'


def render(args) -> list[dict]:
    cmd = ['helm', 'template', RELEASE, str(ROOT / 'charts/cmtc'), '-n', NAMESPACE, '-f', args.values]
    for s in args.set or []:
        cmd += ['--set', s]
    rendered = objects(subprocess.run(cmd, check=True, text=True, capture_output=True).stdout)
    if any(o['kind'] == 'Secret' for o in rendered):
        raise SystemExit('the render holds a Secret; this tool never reads Secrets')
    return rendered


def with_release_metadata(o: dict) -> dict:
    """The object as Helm applies it: helm template omits this metadata."""
    o = json.loads(json.dumps(o))
    meta = o.setdefault('metadata', {})
    meta['annotations'] = dict(meta.get('annotations') or {}, **{'meta.helm.sh/release-name': RELEASE,
                                                                  'meta.helm.sh/release-namespace': NAMESPACE})
    meta['labels'] = dict(meta.get('labels') or {}, **{'app.kubernetes.io/managed-by': 'Helm'})
    return o


def foreign_release(obj: dict) -> str | None:
    notes = obj['metadata'].get('annotations') or {}
    name, ns = notes.get('meta.helm.sh/release-name'), notes.get('meta.helm.sh/release-namespace')
    return f'{name}/{ns}' if (name or ns) and (name, ns) != (RELEASE, NAMESPACE) else None


def plan(args, cluster: Cluster) -> int:
    rendered = render(args)
    manifest = ''.join('---\n' + json.dumps(with_release_metadata(o)) + '\n' for o in rendered)
    r = cluster.kubectl('apply', '--server-side', f'--field-manager={FIELD_MANAGER}', '--dry-run=server',
                        '--show-managed-fields', '-o', 'json', '-f', '-', check=False, input=manifest)
    if r.returncode:
        print(r.stderr.strip())
        print(f'{cluster.name}: the apply would fail (conflicts above); helm upgrade stops on the same conflicts')
        return 1
    changed, kept, refused = 0, 0, 0
    for after in json_stream(r.stdout):
        name, live = ident(after), cluster.get(after)
        if live is None:
            changed += 1
            print(f'{name}: created')
            continue
        if foreign_release(live):
            refused += 1
            print(f'{name}: owned by release {foreign_release(live)}')
        found: list = []
        changes(comparable(live), comparable(after), '', found)
        for path, before, now in found:
            changed += 1
            print(f'{name}: {path}\n    live ={json.dumps(before)[:300]}\n    after={json.dumps(now)[:300]}')
        for m in kubectl_owned(after):
            kept += 1
            print(f'{name}: {m["manager"]} still owns {len(field_paths(m.get("fieldsV1", {})))} field(s) (transfer)')
    print(f'{cluster.name}: {changed} change(s); {kept} kubectl manager entr(ies) left; {refused} refusal(s)')
    return 1 if refused else 0


def transfer(args, cluster: Cluster) -> int:
    backup = pathlib.Path(args.backup_dir)
    backup.mkdir(parents=True, exist_ok=True)
    for o in render(args):
        live = cluster.get(o, managed_fields=True)
        if live is None:
            continue
        name, meta = ident(o), live['metadata']
        if foreign_release(live):
            raise SystemExit(f'{name}: owned by release {foreign_release(live)}')
        saved = backup / f'{cluster.name}.{o["kind"]}.{meta["name"]}.json'
        # The first backup is the state before any transfer; it is kept, never overwritten.
        earlier = [m for m in json.loads(saved.read_text())['managedFields']
                   if m['manager'] in KUBECTL_MANAGERS and not m.get('subresource')] if saved.exists() else []
        entries = transferred(live, earlier)
        if entries == meta.get('managedFields', []):
            continue
        if not saved.exists():
            saved.write_text(json.dumps({'kind': o['kind'], 'name': meta['name'], 'namespace': meta.get('namespace'),
                                         'managedFields': meta['managedFields']}, indent=1) + '\n')
        write_managed_fields(cluster, live, entries)
        print(f'{name}: fields of {", ".join(m["manager"] for m in kubectl_owned(live))} given to {FIELD_MANAGER} '
              f'(first managedFields in {saved})')
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', choices=['plan', 'transfer'])
    ap.add_argument('cluster', help='cmtc-a or cmtc-b (context kind-<cluster>)')
    ap.add_argument('values', help='config/lab/cmtc/values-<cluster>.yaml')
    ap.add_argument('--set', action='append', help='helm --set, repeated')
    ap.add_argument('--backup-dir', help='transfer: where the first managedFields are kept')
    ap.add_argument('--kubeconfig')
    args = ap.parse_args()
    if args.command == 'transfer' and not args.backup_dir:
        ap.error('transfer needs --backup-dir')
    cluster = Cluster(args.cluster, args.kubeconfig)
    sys.exit({'plan': plan, 'transfer': transfer}[args.command](args, cluster))


if __name__ == '__main__':
    main()
