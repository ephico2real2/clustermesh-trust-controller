#!/usr/bin/env python3
"""Read Cilium drop captures, written by capture_cilium_drops.sh, and show the drops grouped by flow and reason.

Each input file is one node's capture of `cilium-dbg monitor -n -t drop`. The node is the file name without its
extension. The monitor prints no time for an event, in any of its output forms, so the capture puts the time each
line arrived in front of it:

  2026-10-25T23:00:49.123456Z xx drop (Policy denied) flow 0xaec1c6e9 to endpoint 3569, ifindex 35, file
  bpf_lxc.c:2373, , identity 69374->93541: 10.10.1.47:50342 -> 10.10.1.76:80 tcp SYN

(one line in the file). The text form is the one parsed: it names the BPF source file of the drop, and the JSON
form (-j) gives only the file's numeric ID. The format is Cilium's DropNotify.DumpInfo (pkg/monitor/datapath_drop.go)
and GetConnectionSummary (pkg/monitor/dissect.go).

A capture must declare the time it covers with a "# coverage <ISO start> <ISO end>" line, the same header that
extract_ztunnel_logs.sh writes. A file without one is refused: a missing drop means something only inside a declared
coverage. The monitor's "CPU NN: Lost N events" lines are kept, because lost events weaken an absence.

Examples:
  scripts/evidence/cilium_drop_view.py <run-dir>/cilium-drops/*.log
  scripts/evidence/cilium_drop_view.py --json <run-dir>/cilium-drops/*.log
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ztunnel_log_view import COVERAGE, Style, clock, section, table  # noqa: E402

# The reason may itself hold parentheses ("No tunnel/encapsulation endpoint (datapath BUG!)").
DROP = re.compile(r"^(?P<at>\S+) xx drop \((?P<reason>.*?)\) flow (?P<flow>0x[0-9a-f]+) to endpoint (?P<endpoint>\d+), "
                  r"ifindex (?P<ifindex>\d+), file (?P<location>[^,]+),.*?identity (?P<src_id>\S+?)->(?P<dst_id>\S+?): "
                  r"(?P<summary>.*)$")
FLOW = re.compile(r"^(?P<src>\S+) -> (?P<dst>\S+) (?P<proto>[a-z0-9]+)\b")
LOST = re.compile(r"^(?P<at>\S+) CPU \d+: Lost (?P<count>\d+) events")
PORTED = ("tcp", "udp", "sctp")


@dataclass(frozen=True, eq=False)
class Drop:
    """One drop event of the Cilium datapath, with the time the capture received it."""
    node: str
    at: datetime
    reason: str
    location: str       # the BPF source file and line that dropped the packet, e.g. "bpf_lxc.c:1626"
    src_identity: str
    dst_identity: str
    src_ip: str
    src_port: str       # empty for a protocol without ports (ICMP) or an unparsed summary
    dst_ip: str
    dst_port: str
    proto: str
    raw: str


@dataclass(frozen=True)
class Lost:
    node: str
    at: datetime
    count: int


def _host_port(addr: str, ported: bool) -> tuple[str, str]:
    """Split "10.0.0.1:80" or "[fd00::1]:80" (Go's net.JoinHostPort); an address without a port has none."""
    if not ported:
        return addr, ""
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), port


def parse_line(raw: str, node: str) -> Drop | Lost | None:
    """Parse one captured line, or return None for any other line (a banner, a log line, a capture marker)."""
    line = raw.rstrip("\n")
    if (lost := LOST.match(line)) is not None:
        return Lost(node, datetime.fromisoformat(lost["at"]), int(lost["count"]))
    m = DROP.match(line)
    if m is None:
        return None
    flow = FLOW.match(m["summary"])
    proto, (src_ip, src_port), (dst_ip, dst_port) = "", ("", ""), ("", "")
    if flow:
        proto = flow["proto"]
        src_ip, src_port = _host_port(flow["src"], proto in PORTED)
        dst_ip, dst_port = _host_port(flow["dst"], proto in PORTED)
    return Drop(node=node, at=datetime.fromisoformat(m["at"]), reason=m["reason"], location=m["location"].strip(),
                src_identity=m["src_id"], dst_identity=m["dst_id"], src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port, proto=proto, raw=line)


def read_drops(paths: list[str]) -> tuple[list[Drop], dict[str, tuple[datetime, datetime]], list[Lost]]:
    """Return every drop, oldest first, the time each node's capture covers, and the lost-event reports."""
    drops, coverage, lost = [], {}, []
    for path in paths:
        node = Path(path).stem
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            header = COVERAGE.match(line)
            if header:
                coverage[node] = (datetime.fromisoformat(header.group(1)), datetime.fromisoformat(header.group(2)))
            elif isinstance(event := parse_line(line, node), Drop):
                drops.append(event)
            elif isinstance(event, Lost):
                lost.append(event)
        if node not in coverage:
            raise SystemExit(f"{path}: no '# coverage <start> <end>' line; capture it with capture_cilium_drops.sh")
    return sorted(drops, key=lambda d: d.at), coverage, lost


# --------------------------------------------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("captures", nargs="+", help="drop captures, one per node, named after the node")
    ap.add_argument("--json", action="store_true", help="print every drop as JSON")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = ap.parse_args(argv)

    drops, coverage, lost = read_drops(args.captures)
    if args.json:
        print(json.dumps([{"node": d.node, "at": d.at.isoformat(), "reason": d.reason, "location": d.location,
                           "src": f"{d.src_ip}:{d.src_port}", "dst": f"{d.dst_ip}:{d.dst_port}", "proto": d.proto,
                           "identities": f"{d.src_identity}->{d.dst_identity}", "raw": d.raw} for d in drops],
                         indent=2))
        return 0
    style = Style(args.color == "always" or (args.color == "auto" and sys.stdout.isatty()
                                             and "NO_COLOR" not in os.environ))
    out = [section("Coverage", "the time each node's capture declares", style)]
    width = max(map(len, coverage))
    for node, (start, end) in sorted(coverage.items()):
        lost_here = sum(x.count for x in lost if x.node == node)
        note = style.color(f"  {lost_here} event(s) lost", "red") if lost_here else ""
        out.append(f"  {style.color(node.ljust(width), bold=True)}  {start:%Y-%m-%d} {clock(start)}Z → {clock(end)}Z"
                   + note)
    groups = defaultdict(list)
    for d in drops:
        groups[(d.node, d.src_ip, f"{d.dst_ip}:{d.dst_port}" if d.dst_port else d.dst_ip, d.proto, d.reason,
                d.location)].append(d)
    rows = [[style.color(f"{clock(g[0].at)}–{clock(g[-1].at)}", "gray"), node, src, dst, proto,
             style.color(reason, "red"), location, str(len(g))]
            for (node, src, dst, proto, reason, location), g in sorted(groups.items(), key=lambda kv: kv[1][0].at)]
    out += [section("Drops", f"{len(drops)} drop(s), grouped by node, flow, reason and location", style),
            table(["TIME", "NODE", "FROM", "TO", "PROTO", "REASON", "WHERE", "COUNT"], rows, style,
                  right=frozenset({7})) if rows else "  " + style.color("none", "green")]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        sys.stderr.close()
