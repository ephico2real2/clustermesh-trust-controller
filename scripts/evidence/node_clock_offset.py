#!/usr/bin/env python3
"""Measure a bound on node clock minus host clock for kind nodes, for join_probes_to_ztunnel.py --node-clock-offset.

The probe runner stamps a probe with the host clock. ztunnel and the drop capture stamp lines with the node clock
(every kind node is a container of the same VM, so all of them read the VM's clock). The two clocks differ: the Colima
VM clock is not disciplined. A join that compares them without a bound accepts or rejects a line by chance.

Each sample reads the host clock (t1), runs `date +%s.%N` in the node container (n), and reads the host clock again
(t2). The node read its clock between t1 and t2, so node minus host lies in [n - t2, n - t1]. The samples of a node are
intersected; an empty intersection means a clock moved during the sampling, and the measurement fails. The bound for
the join is the union over the nodes, and with --union over several measurements (before and after a run).

Usage:
  node_clock_offset.py [--samples N] [--out FILE] NODE...     measure; print LO:HI in seconds
  node_clock_offset.py --union FILE...                        print the union of measured bounds as LO:HI
Environment: DOCKER_CONTEXT, the Docker context that runs the kind nodes (default colima-cmtc-cilium).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def node_ns(node: str) -> int:
    context = os.environ.get("DOCKER_CONTEXT", "colima-cmtc-cilium")
    out = subprocess.run(["docker", "--context", context, "exec", node, "date", "+%s.%N"],
                         capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    seconds, _, fraction = out.partition(".")
    if not seconds.isdigit() or len(fraction) != 9 or not fraction.isdigit():
        raise ValueError(f"{node}: unexpected `date +%s.%N` output {out!r}")
    return int(seconds) * 1_000_000_000 + int(fraction)


def bound(node: str, samples: int, read_node: Callable[[str], int] = node_ns,
          host_ns: Callable[[], int] = time.time_ns) -> tuple[int, int]:
    """The intersection of the samples' intervals for node minus host, in nanoseconds."""
    lo, hi = None, None
    for _ in range(samples):
        t1 = host_ns()
        n = read_node(node)
        t2 = host_ns()
        lo = n - t2 if lo is None else max(lo, n - t2)
        hi = n - t1 if hi is None else min(hi, n - t1)
    if lo > hi:
        raise SystemExit(f"{node}: the sample intervals do not overlap; a clock moved while it was measured")
    return lo, hi


def seconds(ns: int) -> str:
    return f"{ns / 1e9:.6f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("nodes", nargs="*")
    ap.add_argument("--samples", type=int, default=8)
    ap.add_argument("--out", type=Path, help="write the measurement as JSON")
    ap.add_argument("--union", nargs="+", type=Path, metavar="FILE", help="measurements to join into one bound")
    args = ap.parse_args(argv)
    if args.union:
        bounds = [json.loads(f.read_text())["boundNs"] for f in args.union]
        print(f"{seconds(min(b[0] for b in bounds))}:{seconds(max(b[1] for b in bounds))}")
        return 0
    if not args.nodes or args.samples < 1:
        ap.error("give at least one NODE and --samples of 1 or more")
    nodes = {node: bound(node, args.samples) for node in args.nodes}
    lo, hi = min(b[0] for b in nodes.values()), max(b[1] for b in nodes.values())
    if args.out:
        args.out.write_text(json.dumps({
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "samples": args.samples,
            "meaning": "node clock minus host clock, nanoseconds", "nodesNs": nodes, "boundNs": [lo, hi]}, indent=1) + "\n")
    for node, (a, b) in nodes.items():
        print(f"{node}: node minus host in [{seconds(a)}, {seconds(b)}] s", file=sys.stderr)
    print(f"{seconds(lo)}:{seconds(hi)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
