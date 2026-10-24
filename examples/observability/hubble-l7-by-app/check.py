#!/usr/bin/env python3
"""Verify the imported generator and reproduce the example from the selected chart."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
chart = Path(sys.argv[1])
source = json.loads((root / 'source.json').read_text())
lock = json.loads((root.parents[2] / 'config/cilium-images.lock.json').read_text())
assert source['input']['commit'] == lock['source_sha'], 'Refresh the example when advancing the image/chart pin'
for path, expected in [(root / 'l7-by-app-dashboard.py', source['generator']['sha256']),
                       (chart, source['input']['sha256']),
                       (root / 'dashboard.json', source['dashboard']['sha256'])]:
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, f'Source hash differs: {path}'
generated = json.loads(subprocess.check_output([sys.executable, str(root / 'l7-by-app-dashboard.py'), str(chart)]))
stored = json.loads((root / 'dashboard.json').read_text())
assert generated == stored, 'Regenerate dashboard.json with the pinned PoC generator'
assert stored['uid'] == 'hubble-l7-http-by-app'
print('PASS: pinned PoC generator, chart source and app dashboard reproduce exactly')
