#!/usr/bin/env python3
"""The one-time Helm adoption tool for labs created before the values files existed (still needed for kind-cmtc-b).

It uses the values files of cilium_release.py, in the same order, and takes the same arguments.

Subcommands:
  plan      what helm upgrade would change: a server-side dry-run apply of the render as field manager helm, with
            the release metadata Helm adds, compared with live, plus the release objects the render drops (deleted).
            helm upgrade --dry-run=server cannot show this: it does not send the apply, so it reports neither the
            changes nor the conflicts. Exit 1 on a conflict, a Helm hook (not covered), or an object that another
            release owns (--take-ownership would take it). Also lists fields that kubectl managers still own.
  transfer  give helm the fields that kubectl patch, edit and client-side apply own in the rendered objects. Under
            server-side apply, helm removes only fields it owned; a field that a kubectl manager also owns stays
            when the values drop it. Writes metadata.managedFields only, and stops if anything else changed. The
            first managedFields of each object are kept in --backup-dir and merged again on every run, so a repeated
            transfer is lossless and a no-op once done. Refuses an object outside the release whose render differs
            from live, or that another release owns.
  restore-owners  put back helm's and the kubectl managers' entries from the backup; other managers keep theirs.
  upgrade   helm upgrade with these files, server-side, taking over the objects outside the release. Runs plan first
            and refuses on its refusals, or while a kubectl manager owns a field. Without --force-conflicts: a
            conflict means another manager changed a field, and the upgrade stops on it. A failed upgrade can leave
            some objects applied; run the same upgrade again. Never helm rollback to a revision rendered before the
            port: helm now owns the formerly hand-made fields, so that rollback removes them.
"""
import copy
import datetime
import hashlib
import json
import pathlib
import sys

from cilium_release import NAMESPACE, RELEASE, Cluster, compare, default_chart, ident, objects, parser, render, values_files

FIELD_MANAGER = 'helm'
# Field managers of hand-made changes. Controllers (kube-controller-manager, cert-manager) and kubectl-rollout
# (restartedAt, never rendered) keep their fields.
KUBECTL_MANAGERS = ('kubectl-patch', 'kubectl-client-side-apply', 'kubectl-edit', 'kubectl-label', 'kubectl-annotate',
                    'kubectl-set')
# Fields the API server maintains: they stay unowned, as on objects Helm created.
SERVER_MAINTAINED = (('f:metadata', 'f:annotations', 'f:deprecated.daemonset.template.generation'),)


def with_release_metadata(o: dict) -> dict:
    """The object as Helm applies it: helm get manifest and helm template omit this metadata."""
    o = copy.deepcopy(o)
    meta = o.setdefault('metadata', {})
    meta['annotations'] = dict(meta.get('annotations') or {}, **{'meta.helm.sh/release-name': RELEASE,
                                                                  'meta.helm.sh/release-namespace': NAMESPACE})
    meta['labels'] = dict(meta.get('labels') or {}, **{'app.kubernetes.io/managed-by': 'Helm'})
    return o


def json_stream(text: str) -> list[dict]:
    """kubectl -o json prints one object, a List, or several objects one after another."""
    decoder, pos, out = json.JSONDecoder(), 0, []
    while text[pos:].strip():
        pos = len(text) - len(text[pos:].lstrip())
        obj, end = decoder.raw_decode(text, pos)
        pos = end
        out += obj['items'] if obj.get('kind') == 'List' else [obj]
    return out


def kubectl_owned(obj: dict) -> list[dict]:
    return [m for m in obj['metadata'].get('managedFields', [])
            if m['manager'] in KUBECTL_MANAGERS and not m.get('subresource')]


def field_paths(tree: dict, prefix: tuple = ()) -> list[tuple]:
    out = []
    for key, sub in tree.items():
        if key == '.':
            continue
        out += field_paths(sub, prefix + (key,)) if sub else [prefix + (key,)]
    return out


def list_key(items: list) -> str | None:
    """The key that server-side apply merges a list of objects on, when it is unique."""
    for key in ('name', 'mountPath', 'containerPort'):
        if items and all(isinstance(x, dict) and key in x for x in items) and \
                len({json.dumps(x[key]) for x in items}) == len(items):
            return key
    return None


def changes(want, got, path: str, out: list) -> None:
    """Every difference between two objects; lists of named entries are compared by name, then by order."""
    if isinstance(want, dict) and isinstance(got, dict):
        for k in sorted(set(want) | set(got)):
            changes(want.get(k, '<absent>'), got.get(k, '<absent>'), f'{path}.{k}', out)
    elif isinstance(want, list) and isinstance(got, list) and list_key(want) and list_key(want) == list_key(got):
        key = list_key(want)
        w, g = {json.dumps(x[key]): x for x in want}, {json.dumps(x[key]): x for x in got}
        for k in list(w) + [k for k in g if k not in w]:
            changes(w.get(k, '<absent>'), g.get(k, '<absent>'), f'{path}[{key}={k}]', out)
        if [k for k in w if k in g] != [k for k in g if k in w]:
            out.append((f'{path} (order)', [k for k in w if k in g], [k for k in g if k in w]))
    elif isinstance(want, list) and isinstance(got, list) and len(want) == len(got):
        for i, (w, g) in enumerate(zip(want, got)):
            changes(w, g, f'{path}[{i}]', out)
    elif want != got:
        out.append((path, want, got))


SERVER_SET = ('managedFields', 'resourceVersion', 'generation', 'creationTimestamp', 'uid')


def comparable(o: dict) -> dict:
    """o without status and server-set metadata; a Secret's values are replaced by their SHA-256, never printed."""
    out = {k: v for k, v in o.items() if k != 'status'}
    out['metadata'] = {k: v for k, v in o['metadata'].items() if k not in SERVER_SET}
    if o['kind'] == 'Secret':
        digest = lambda v: 'sha256:' + hashlib.sha256(str(v).encode()).hexdigest()
        for field in ('data', 'stringData'):
            if field in out:
                out[field] = {k: digest(v) for k, v in out[field].items()}
        # kubectl apply copies the whole Secret, values included, into this annotation.
        notes = dict(out['metadata'].get('annotations') or {})
        if 'kubectl.kubernetes.io/last-applied-configuration' in notes:
            notes['kubectl.kubernetes.io/last-applied-configuration'] = digest(
                notes['kubectl.kubernetes.io/last-applied-configuration'])
            out['metadata']['annotations'] = notes
    return out


def foreign_release(obj: dict) -> str | None:
    """The release that owns obj when it is not this one (name or namespace differs), else None."""
    notes = obj['metadata'].get('annotations') or {}
    name, ns = notes.get('meta.helm.sh/release-name'), notes.get('meta.helm.sh/release-namespace')
    if (name or ns) and (name, ns) != (RELEASE, NAMESPACE):
        return f'{name}/{ns}'
    return None


def plan(args, cluster: Cluster) -> int:
    rendered = objects(render(args))
    hooks = [ident(o) for o in rendered if 'helm.sh/hook' in (o['metadata'].get('annotations') or {})]
    released = {ident(o) for o in objects(cluster.helm('get', 'manifest', RELEASE))}
    manifest = ''.join('---\n' + json.dumps(with_release_metadata(o)) + '\n' for o in rendered)
    r = cluster.kubectl('apply', '--server-side', f'--field-manager={FIELD_MANAGER}', '--dry-run=server',
                        '--show-managed-fields', '-o', 'json', '-f', '-', check=False, input=manifest)
    if r.returncode:
        print(r.stderr.strip())
        print(f'{cluster.name}: the apply would fail (conflicts above); helm upgrade stops on the same conflicts')
        return 1
    changed, kept, refused = 0, 0, 0
    for name in hooks:
        refused += 1
        print(f'{name}: a Helm hook; this plan does not cover hooks')
    for after in json_stream(r.stdout):
        name = ident(after)
        live = cluster.get(after)
        if live is None:
            changed += 1
            print(f'{name}: created')
            continue
        if foreign_release(live):
            refused += 1
            print(f'{name}: owned by release {foreign_release(live)}; --take-ownership would take it')
        found: list = []
        changes(comparable(live), comparable(after), '', found)
        for path, before, now in found:
            changed += 1
            # Display only: values are cut at 300 characters; the count is of every difference.
            print(f'{name}: {path}\n    live ={json.dumps(before)[:300]}\n    after={json.dumps(now)[:300]}')
        for m in kubectl_owned(after):
            kept += 1
            print(f'{name}: {m["manager"]} still owns {len(field_paths(m.get("fieldsV1", {})))} field(s) (transfer)')
    dropped = sorted(released - {ident(o) for o in rendered})
    for name in dropped:
        changed += 1
        print(f'{name}: in the release, not rendered (helm upgrade deletes it)')
    print(f'{cluster.name}: {changed} change(s), {len(dropped)} deletion(s); {kept} kubectl manager entr(ies) left; '
          f'{refused} refusal(s)')
    return 1 if refused else 0


def union(a: dict, b: dict) -> dict:
    """Union of two FieldsV1 sets (managedFields fieldsV1). The top level is a set of fields, not a field."""
    return {key: member_union(a.get(key), b.get(key)) for key in set(a) | set(b)}


def member_union(a: dict | None, b: dict | None) -> dict:
    """One field in both sets. {} marks the field itself; a field that also has fields below it carries '.'."""
    if a is None or b is None:
        return copy.deepcopy(b if a is None else a)
    out = {'.': {}} if '.' in a or '.' in b or (a == {} and b) or (b == {} and a) else {}
    for key in (set(a) | set(b)) - {'.'}:
        out[key] = member_union(a.get(key), b.get(key))
    return out


def without(tree: dict, path: tuple) -> dict:
    """tree without path; a parent that only held path goes too."""
    if not path or path[0] not in tree:
        return tree
    out = dict(tree)
    if len(path) == 1:
        del out[path[0]]
    else:
        sub = without(out[path[0]], path[1:])
        if sub or not out[path[0]]:
            out[path[0]] = sub
        else:
            del out[path[0]]
    return out


def is_helm_apply(m: dict) -> bool:
    return m['manager'] == FIELD_MANAGER and m['operation'] == 'Apply' and not m.get('subresource')


def transferred(live: dict, earlier: list[dict]) -> list[dict]:
    """managedFields with the kubectl managers' fields merged into helm's apply entry.

    earlier: kubectl manager entries from the backup of a previous transfer. Merging them again is lossless (a union),
    so a repeated transfer repairs an entry that lost fields.
    """
    entries = live['metadata'].get('managedFields', [])
    moved = kubectl_owned(live)
    if not moved and not earlier:
        return entries
    helm = next((m for m in entries if is_helm_apply(m)), None)
    fields = helm.get('fieldsV1', {}) if helm else {}
    for m in moved + earlier:
        if m['apiVersion'] != live['apiVersion']:
            raise SystemExit(f'{ident(live)}: {m["manager"]} entry is for {m["apiVersion"]}, not {live["apiVersion"]}')
        fields = union(fields, m.get('fieldsV1', {}))
    for path in SERVER_MAINTAINED:
        fields = without(fields, path)
    if helm and not moved and fields == helm.get('fieldsV1', {}):
        return entries
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    merged = {'manager': FIELD_MANAGER, 'operation': 'Apply', 'apiVersion': live['apiVersion'], 'time': now,
              'fieldsType': 'FieldsV1', 'fieldsV1': fields}
    return [m for m in entries if m is not helm and m not in moved] + [merged]


def transfer(args, cluster: Cluster) -> int:
    backup = pathlib.Path(args.backup_dir)
    backup.mkdir(parents=True, exist_ok=True)
    released = {ident(o) for o in objects(cluster.helm('get', 'manifest', RELEASE))}
    for o in objects(render(args)):
        live = cluster.get(o, managed_fields=True)
        if live is None:
            continue
        name, meta = ident(o), live['metadata']
        saved = backup / f'{cluster.name}.{o["kind"]}.{meta["name"]}.json'
        # The first backup is the state before any transfer; it is kept, never overwritten.
        earlier = [m for m in json.loads(saved.read_text())['managedFields']
                   if m['manager'] in KUBECTL_MANAGERS and not m.get('subresource')] if saved.exists() else []
        entries = transferred(live, earlier)
        if entries == meta.get('managedFields', []):
            continue
        if name not in released:
            if foreign_release(live):
                raise SystemExit(f'{name}: owned by release {foreign_release(live)}')
            found: list = []
            compare({k: v for k, v in o.items() if k not in ('metadata', 'status')}, live, '', found)
            if found or (o['kind'] == 'Secret' and live.get('data') != o.get('data')):
                raise SystemExit(f'{name}: outside the release and its render differs from live; run check')
        if not saved.exists():
            saved.write_text(json.dumps({'kind': o['kind'], 'name': meta['name'], 'namespace': meta.get('namespace'),
                                         'managedFields': meta['managedFields']}, indent=1) + '\n')
        write_managed_fields(cluster, live, entries)
        sources = [m['manager'] for m in kubectl_owned(live)] + (['the backup'] if earlier else [])
        print(f'{name}: fields of {", ".join(sources)} given to {FIELD_MANAGER} (first managedFields in {saved})')
    return 0


def write_managed_fields(cluster: Cluster, live: dict, entries: list[dict]) -> None:
    meta = live['metadata']
    ns = ['-n', meta['namespace']] if meta.get('namespace') else []
    # resourceVersion makes the write fail if the object changed since it was read.
    patch = {'metadata': {'resourceVersion': meta['resourceVersion'], 'managedFields': entries}}
    cluster.kubectl('patch', live['kind'], meta['name'], *ns, '--type=merge', '-p', json.dumps(patch))
    after = cluster.get(live, managed_fields=True)
    unchanged = lambda o: {k: v for k, v in o.items() if k != 'status'} | {
        'metadata': {k: v for k, v in o['metadata'].items() if k not in ('managedFields', 'resourceVersion')}}
    if unchanged(after) != unchanged(live):
        # A controller can also have written the object since; either way a person must look before going on.
        raise SystemExit(f'{ident(live)}: the object changed beyond managedFields; stop and inspect it')


def restore_owners(args, cluster: Cluster) -> int:
    """Put back helm's and the kubectl managers' entries from the first backup; other managers keep their current ones."""
    for saved in sorted(pathlib.Path(args.backup_dir).glob(f'{cluster.name}.*.json')):
        entry = json.loads(saved.read_text())
        obj = {'kind': entry['kind'], 'metadata': {'name': entry['name'], 'namespace': entry['namespace']}}
        live = cluster.get(obj, managed_fields=True)
        ours = lambda m: is_helm_apply(m) or (m['manager'] in KUBECTL_MANAGERS and not m.get('subresource'))
        entries = [m for m in live['metadata']['managedFields'] if not ours(m)] + \
                  [m for m in entry['managedFields'] if ours(m)]
        write_managed_fields(cluster, live, entries)
        print(f'{ident(obj)}: helm and kubectl managedFields restored from {saved}')
    return 0


def upgrade(args, cluster: Cluster) -> int:
    for o in objects(render(args)):
        live = cluster.get(o, managed_fields=True)
        if live is not None and kubectl_owned(live):
            raise SystemExit(f'{ident(o)}: kubectl managers own fields; run transfer first')
    # The plan again, just before the upgrade: no conflict, no hook, no object of another release.
    if plan(args, cluster):
        raise SystemExit(f'{cluster.name}: the plan refuses the upgrade')
    # No --rollback-on-failure: helm owns the fields that were hand-made, so a rollback to a revision rendered before
    # the port would remove them. A failed upgrade is finished by running this upgrade again with the same values.
    cmd = ['upgrade', RELEASE, args.chart, '--server-side=true', '--take-ownership', '--wait=watcher',
           '--timeout', args.timeout]
    for f in values_files(args):
        cmd += ['-f', f]
    sys.stdout.write(cluster.helm(*cmd))
    return 0


def main() -> None:
    ap = parser(__doc__, ['plan', 'transfer', 'restore-owners', 'upgrade'])
    ap.add_argument('--backup-dir', help='transfer, restore-owners: where the previous managedFields are kept')
    ap.add_argument('--timeout', default='15m', help='upgrade: helm --timeout (the agents restart one at a time)')
    args = ap.parse_args()
    if args.command in ('transfer', 'restore-owners') and not args.backup_dir:
        ap.error(f'{args.command} needs --backup-dir')
    default_chart(args)
    cluster = Cluster(args.cluster, args.kubeconfig)
    commands = {'plan': plan, 'transfer': transfer, 'restore-owners': restore_owners, 'upgrade': upgrade}
    sys.exit(commands[args.command](args, cluster))


if __name__ == '__main__':
    main()
