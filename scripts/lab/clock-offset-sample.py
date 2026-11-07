#!/usr/bin/env python3
"""Sample a kind node's wall-clock offset from the host.

Each sample reads the guest clock inside the node container and brackets it
with two host reads; the offset is guest minus the host midpoint, so its error
is bounded by half the round trip, which is printed with every sample.

Usage: clock-offset-sample.py NODE SAMPLES INTERVAL_SECONDS [DOCKER_CONTEXT]
"""
import subprocess
import sys
import time
from datetime import datetime, timezone

node, samples, interval = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
docker = ["docker"] + (["--context", sys.argv[4]] if len(sys.argv) > 4 else [])
print("host_utc\tguest_minus_host_ms\trtt_ms")
for _ in range(samples):
    before = time.time()
    guest = float(subprocess.check_output(docker + ["exec", node, "date", "+%s.%N"], text=True))
    after = time.time()
    print(f"{datetime.fromtimestamp(after, timezone.utc):%H:%M:%S}\t"
          f"{(guest - (before + after) / 2) * 1000:.1f}\t{(after - before) * 1000:.1f}", flush=True)
    time.sleep(interval)
