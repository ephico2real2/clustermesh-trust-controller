#!/usr/bin/env python3
"""Validate a development image bundle and render explicit Helm overrides."""
import json
import pathlib
import re
import sys

lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
sha = lock['source_sha']
if not re.fullmatch('[0-9a-f]{40}', sha):
    raise SystemExit('source_sha must be a full immutable Git commit')
roles = ('agent', 'operator-generic', 'clustermesh-apiserver')
# source_sha selects the chart. An image built from another fork commit names it in its own source_sha, so one
# component can move without rebuilding the others (the chart must render the same for that image).
for role in roles:
    image = lock['images'][role]['image']
    if not re.fullmatch(r'ghcr\.io/ephico2real2/[a-z0-9/_.-]+@sha256:[0-9a-f]{64}', image):
        raise SystemExit(f'{role} requires an immutable digest in your GHCR registry')
    source = lock['images'][role].get('source_sha', sha)
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise SystemExit(f'{role} source_sha must be a full immutable Git commit')
    if f'sha-{source}-' not in lock['images'][role].get('tag', f'sha-{source}-'):
        raise SystemExit(f'{role} tag does not name its source_sha')
values = {
    'image': {'override': lock['images']['agent']['image'], 'pullPolicy': 'IfNotPresent'},
    'operator': {'image': {'override': lock['images']['operator-generic']['image'], 'pullPolicy': 'IfNotPresent'}},
    'preflight': {'image': {'override': lock['images']['agent']['image']}},
    'clustermesh': {'apiserver': {'image': {'override': lock['images']['clustermesh-apiserver']['image'], 'pullPolicy': 'IfNotPresent'}}},
}
# Optional custom Hubble components do not enable them implicitly.
for role, keys in {
    'hubble-relay': ('hubble', 'relay', 'image'),
    'hubble-ui': ('hubble', 'ui', 'frontend', 'image'),
    'hubble-ui-backend': ('hubble', 'ui', 'backend', 'image'),
}.items():
    if role in lock['images']:
        image = lock['images'][role]['image']
        if not re.fullmatch(r'ghcr\.io/ephico2real2/[a-z0-9/_.-]+@sha256:[0-9a-f]{64}', image):
            raise SystemExit(f'{role} requires an immutable digest in your GHCR registry')
        target = values
        for key in keys:
            target = target.setdefault(key, {})
        target.update(override=image, pullPolicy='IfNotPresent')
pathlib.Path(sys.argv[2]).write_text(json.dumps(values, indent=2) + '\n')
print(sha)
