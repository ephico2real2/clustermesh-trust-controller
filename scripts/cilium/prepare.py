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
FORK = r'ghcr\.io/ephico2real2/[a-z0-9/_.-]+@sha256:[0-9a-f]{64}'
# The Hubble UI is not forked: its two images are upstream's, by digest, at the version the chart pins.
UPSTREAM_UI = r'quay\.io/cilium/hubble-ui(-backend)?@sha256:[0-9a-f]{64}'


def fork_image(role: str) -> str:
    """The role's immutable fork image; it names its own source_sha in its tag."""
    image = lock['images'][role]['image']
    if not re.fullmatch(FORK, image):
        raise SystemExit(f'{role} requires an immutable digest in your GHCR registry')
    source = lock['images'][role].get('source_sha', sha)
    if not re.fullmatch('[0-9a-f]{40}', source):
        raise SystemExit(f'{role} source_sha must be a full immutable Git commit')
    if f'sha-{source}-' not in lock['images'][role].get('tag', f'sha-{source}-'):
        raise SystemExit(f'{role} tag does not name its source_sha')
    return image


# source_sha selects the chart. An image built from another fork commit names it in its own source_sha, so one
# component can move without rebuilding the others (the chart must render the same for that image).
values = {
    'image': {'override': fork_image('agent'), 'pullPolicy': 'IfNotPresent'},
    'operator': {'image': {'override': fork_image('operator-generic'), 'pullPolicy': 'IfNotPresent'}},
    'preflight': {'image': {'override': fork_image('agent')}},
    'clustermesh': {'apiserver': {'image': {'override': fork_image('clustermesh-apiserver'), 'pullPolicy': 'IfNotPresent'}}},
}
# The Hubble components do not enable themselves (config/lab/cilium/base.yaml and the cluster values do). The Relay
# is a fork image like the agent, from the agent's source; an entry whose image is still empty renders no override
# (the chart's own value stays), so the lock must be filled before a cluster that runs the Relay is upgraded.
for role, keys, pattern in (
    ('hubble-relay', ('hubble', 'relay', 'image'), FORK),
    ('hubble-ui', ('hubble', 'ui', 'frontend', 'image'), UPSTREAM_UI),
    ('hubble-ui-backend', ('hubble', 'ui', 'backend', 'image'), UPSTREAM_UI),
):
    if role not in lock['images']:
        continue
    if not lock['images'][role]['image']:
        print(f'{role}: no digest in the lock yet; the chart value stays until the fork workflow publishes it', file=sys.stderr)
        continue
    image = fork_image(role) if pattern is FORK else lock['images'][role]['image']
    if not re.fullmatch(pattern, image):
        raise SystemExit(f'{role} requires an immutable digest of the upstream Hubble UI image')
    target = values
    for key in keys:
        target = target.setdefault(key, {})
    target.update(override=image, pullPolicy='IfNotPresent')
pathlib.Path(sys.argv[2]).write_text(json.dumps(values, indent=2) + '\n')
print(sha)
