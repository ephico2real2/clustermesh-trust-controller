#!/usr/bin/env python3
"""Give one imported image its content-addressed name on every kind node.

The imported manifest is read back from containerd, its SHA-256 must equal the
digest the tag points to, and its config must be the build's image ID (read
from the Podman build host). Only then is REPO@DIGEST tagged, and CRI must
resolve it to the same config ID. All nodes must agree on one digest, which
is printed. Same procedure as docs/evidence/spire-recovery/pin-imports.py.

Usage: pin_digest.py IMAGE_TAG
"""
import hashlib, json, re, subprocess, sys

NODES = ('cmtc-a-control-plane', 'cmtc-a-worker', 'cmtc-b-control-plane', 'cmtc-b-worker')


def node_run(node, *args):
    return subprocess.run(['docker', '--context', 'colima-cmtc-cilium', 'exec', node, *args],
                          capture_output=True, check=True).stdout


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    image = sys.argv[1]
    config = 'sha256:' + subprocess.run(['podman', '--connection', 'cmtc-ubuntu-build', 'image', 'inspect', '--format', '{{.Id}}', image],
                                        capture_output=True, text=True, check=True).stdout.strip()
    assert re.fullmatch('sha256:[0-9a-f]{64}', config), config
    repo = image.rsplit(':', 1)[0]
    digests = set()
    for node in NODES:
        rows = node_run(node, 'ctr', '-n', 'k8s.io', 'images', 'list', 'name==' + image).decode().splitlines()
        assert len(rows) == 2, f'{node}: {image} listed {len(rows) - 1} times'
        fields = rows[1].split()
        digest = fields[2]
        assert fields[0] == image and re.fullmatch('sha256:[0-9a-f]{64}', digest), fields
        manifest = node_run(node, 'ctr', '-n', 'k8s.io', 'content', 'get', digest)
        assert 'sha256:' + hashlib.sha256(manifest).hexdigest() == digest, f'{node}: manifest content does not hash to {digest}'
        assert json.loads(manifest)['config']['digest'] == config, f'{node}: manifest config is not {config}'
        alias = repo + '@' + digest
        node_run(node, 'ctr', '-n', 'k8s.io', 'images', 'tag', '--force', image, alias)
        cri = json.loads(node_run(node, 'crictl', 'inspecti', '-o', 'json', alias))
        assert cri['status']['id'] == config, f'{node}: CRI resolves {alias} to {cri["status"]["id"]}'
        assert cri['info']['imageSpec']['architecture'] == 'arm64'
        digests.add(digest)
        print(f'{node} {alias} config {config[7:19]} PASS', flush=True)
    assert len(digests) == 1, digests
    print('PINNED', repo + '@' + digests.pop(), 'CONFIG', config[7:])


if __name__ == '__main__':
    main()
