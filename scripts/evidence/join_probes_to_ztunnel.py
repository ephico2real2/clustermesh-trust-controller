#!/usr/bin/env python3
"""Join each fixture probe (one curl) to the ztunnel connection that carried it, and check both identities.

A traffic matrix proves outcomes only: curl got a 200, or it did not. This join adds, per probe, the connection
evidence from ztunnel's access log, parsed by ztunnel_log_view.py:

  allowed probe   the client-side (outbound) and server-side (inbound) lines of one connection to the probed
                  ip:port (dst.hbone_addr), from the client Pod IP, inside the probe's time window, over the HBONE
                  port, with the peer identity read from the client certificate equal to the client's expected
                  SPIFFE ID and the destination identity equal to the server's
  denied probe    no ztunnel line from the caller's IP inside the window, in logs that cover the window on every
                  node. This shows that no ztunnel accepted the caller; it does not show which component dropped
                  the packets. With --drops, a Cilium drop event of the same flow names it: "dropped by Cilium:
                  <reason> at <file:line>"
  failed probe    a probe whose curl failed. For a target given as a DNS name, the verdict says so, quotes curl's
                  error (curl writes "Resolving timed out" only when its timeout expires while it still resolves
                  the name), and says whether any ztunnel connection from the client to a backend on the port is
                  in the window. With --drops, it adds any Cilium drop of DNS traffic (port 53) from the client.

Inputs:
  probes          JSON files, or directories of them, written by live_mtls_fixture_runner.py: a list of rows with
                  at, context, namespace, client, url, expect, scope and curlRC. `at` is written after curl returns.
  --pods FILE     one fixture Pod per line: CLUSTER NAMESPACE NAME POD_IP NODE SERVICE_ACCOUNT [UID]; '#' comments
  --trust-domain  CLUSTER=DOMAIN for every cluster, e.g. cmtc-a=cmtc-a.mesh.example. The expected SPIFFE ID is
                  spiffe://DOMAIN/ns/NAMESPACE/sa/SERVICE_ACCOUNT. It is given, never read from the logs, so the
                  check is not circular.
  --logs FILES    ztunnel logs, one file per node, named after the node. A filtered extract must declare what it
                  covers with a "# coverage <ISO start> <ISO end>" line (see ztunnel_log_view.read_logs).
  --drops FILES   optional Cilium drop captures, one file per node, written by capture_cilium_drops.sh (parsed by
                  cilium_drop_view.py). A drop matches a probe on caller IP, destination IP:port and protocol, inside
                  the probe's window and the capture's declared coverage. Without --drops the verdicts are as above.

A probe's window ends at its `at`. It starts at `startedAt` when the row has one, else --window seconds before `at`.
Probe times are on the host clock; ztunnel lines and drops are on the node clock. --node-clock-offset LO:HI gives the
measured bound of node minus host, in seconds (node_clock_offset.py), and the window [start, at] becomes
[start + LO, at + HI] on the node clock. More than one matching connection in a window is a failure, not a guess.

Exit status: 0 when every probe is proven, or denied as expected (unanswered, or dropped by Cilium), 1 when any
probe fails, 2 for bad input.

Example:
  scripts/evidence/join_probes_to_ztunnel.py docs/evidence/g1-destination-sources/probes \\
      --pods docs/evidence/g1-destination-sources/fixture-pods.txt \\
      --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \\
      --logs docs/evidence/g1-destination-sources/ztunnel-access/*.log \\
      --since 2026-10-25T23:00:00Z --out docs/evidence/g1-destination-sources/join.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cilium_drop_view import Drop, read_drops  # noqa: E402
from ztunnel_log_view import (HBONE_PORT, Connection, Style, connections, read_logs,  # noqa: E402
                              section, short_identity, table)

PROVEN = "mTLS proven"
DENIED = "no response, no ztunnel line"
DROPPED = "dropped by Cilium"
RESULT_COLORS = {PROVEN: "green", DENIED: "teal", DROPPED: "teal"}
DNS_PORT = "53"
# curl's error without its variable tail: "Resolving timed out after 3001 milliseconds" -> "Resolving timed out".
CURL_ERROR = re.compile(r"^curl: \(\d+\) (.*?)(?: after \d+ m(?:illiseconds|s)\b.*)?$", re.M)


@dataclass(frozen=True)
class Pod:
    cluster: str
    namespace: str
    name: str
    ip: str
    node: str
    account: str


def load_pods(path: Path) -> dict[str, Pod]:
    pods = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split()
        if len(cols) < 6:
            raise SystemExit(f"{path}:{number}: expected CLUSTER NAMESPACE NAME POD_IP NODE SERVICE_ACCOUNT [UID]")
        pod = Pod(*cols[:6])
        pods[pod.ip] = pod
    return pods


def load_probes(paths: list[str]) -> list[tuple[str, dict]]:
    files = []
    for p in map(Path, paths):
        files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    return [(f.name, row) for f in files for row in json.loads(f.read_text())]


def utc(text: str) -> datetime:
    at = datetime.fromisoformat(text)
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def spiffe(trust: dict[str, str], pod: Pod) -> str:
    if pod.cluster not in trust:
        raise SystemExit(f"no --trust-domain for cluster {pod.cluster}")
    return f"spiffe://{trust[pod.cluster]}/ns/{pod.namespace}/sa/{pod.account}"


def _ip(addr: str) -> str:
    return addr.rsplit(":", 1)[0]


def _is_ip(host: str | None) -> bool:
    try:
        ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class DropLogs:
    """Cilium drop captures: the drops, each node's declared coverage, and the monitor's lost-event reports."""
    drops: list[Drop]
    coverage: dict
    lost: list

    def matching(self, src_ip: str, start: datetime, end: datetime, wanted) -> list[Drop]:
        """Drops from src_ip inside the window and inside their capture's coverage, for which wanted(drop) holds."""
        return [d for d in self.drops if d.src_ip == src_ip and start <= d.at <= end
                and self.coverage[d.node][0] <= d.at <= self.coverage[d.node][1] and wanted(d)]

    def search(self, start: datetime, end: datetime) -> str:
        """What a search that found no drop can say. Absence counts only inside declared coverage."""
        gaps = sorted(n for n, (lo, hi) in self.coverage.items() if not lo <= start or not end <= hi)
        if gaps:
            return "no matching Cilium drop; the drop captures of " + ", ".join(gaps) + " do not cover this probe"
        # A lost-event report can come after the events it counts, so every report from the window start counts.
        lost = sum(x.count for x in self.lost if start <= x.at)
        if lost:
            return f"no matching Cilium drop; the monitor reported {lost} lost event(s) from the window start on"
        return "no matching Cilium drop in the captures of " + ", ".join(sorted(self.coverage))


def causes(found: list[Drop]) -> str:
    """Each distinct drop reason and BPF source location, e.g. "Policy denied at bpf_lxc.c:2373"."""
    return "; ".join(sorted({f"{d.reason} at {d.location}" for d in found}))


def _to_target(d: Drop, target, pods: dict[str, Pod]) -> bool:
    """A TCP drop to the probed Pod, or, for a Service address or a name, to it or a fixture backend on the port."""
    if d.proto != "tcp" or d.dst_port != str(target.port or 80):
        return False
    return d.dst_ip == target.hostname if target.hostname in pods else d.dst_ip in pods or d.dst_ip == target.hostname


def curl_error(probe: dict) -> str | None:
    said = CURL_ERROR.search(probe.get("stderr") or "")
    return said.group(1) if said else None


def failed_curl(probe: dict, target, client: Pod, pods: dict[str, Pod], seen: list[Connection],
                drop_logs: DropLogs | None, start: datetime, end: datetime) -> dict:
    """The verdict for an allowed probe whose curl failed: what the logs show about it, and nothing more."""
    rc, port = probe.get("curlRC"), str(target.port or 80)
    verdict = {"result": f"FAIL: curl exit {rc}, no connection to join"}
    name = not _is_ip(target.hostname)
    if name:
        said = curl_error(probe)
        backend = any(c.app_port == port and _ip(c.hbone) in pods for c in seen)
        seen_text = (f"a ztunnel connection from the client to a backend on port {port} is in the window" if backend
                     else f"no ztunnel connection from the client to a backend on port {port} in the window")
        verdict = {"result": f"FAIL: curl exit {rc}" + (f' ("{said}")' if said else "")
                             + f"; the target is a DNS name; {seen_text}",
                   "targetName": target.hostname}
    if drop_logs is None:
        return verdict
    dns = drop_logs.matching(client.ip, start, end, lambda d: d.dst_port == DNS_PORT) if name else []
    found = drop_logs.matching(client.ip, start, end, lambda d: _to_target(d, target, pods))
    if dns:
        verdict["result"] += f"; Cilium dropped DNS traffic from the client: {causes(dns)}"
    if found:
        verdict["result"] += f"; {DROPPED}: {causes(found)}"
    if dns or found:
        verdict["drops"] = [d.raw for d in dns + found]
    else:
        verdict["dropSearch"] = drop_logs.search(start, end)
    return verdict


def judge(probe: dict, pods: dict[str, Pod], trust: dict[str, str], conns: list[Connection], records,
          coverage: dict, window: timedelta, drop_logs: DropLogs | None = None,
          offset: tuple[timedelta, timedelta] = (timedelta(0), timedelta(0))) -> dict:
    """Return the verdict for one probe, with the connection it was joined to."""
    at, target = utc(probe["at"]), urlsplit(probe["url"])
    start = utc(probe["startedAt"]) if probe.get("startedAt") else at - window
    # The window, from here on on the node clock: every offset in the measured bound must be allowed.
    start, end = start + offset[0], at + offset[1]
    # Absence of a line means something only where every node's log covers the probe's whole window.
    gaps = sorted(n for n, (lo, hi) in coverage.items() if not lo <= start or not end <= hi)
    if gaps:
        return {"result": "FAIL: the logs of " + ", ".join(gaps) + " do not cover this probe"}
    cluster = probe["context"].removeprefix("kind-")
    client = next((p for p in pods.values()
                   if (p.cluster, p.namespace, p.name) == (cluster, probe["namespace"], probe["client"])), None)
    if client is None:
        return {"result": f"FAIL: client {cluster}/{probe['namespace']}/{probe['client']} is not in --pods"}
    seen = [c for c in conns if c.src_ip == client.ip and start <= c.at <= end]

    if probe["expect"] == "deny":
        lines = [r.raw for r in records if start <= r.at <= end
                 and client.ip in (_ip(r.fields.get("src.addr", "")), _ip(r.spans.get("inbound", {}).get("peer", "")))]
        if str(probe.get("curlRC")) == "0":
            return {"result": "FAIL: the denied caller got a response"}
        if lines:
            return {"result": "FAIL: a ztunnel saw the denied caller", "lines": lines}
        if drop_logs is None:
            return {"result": DENIED}
        found = drop_logs.matching(client.ip, start, end, lambda d: _to_target(d, target, pods))
        if found:
            return {"result": f"{DROPPED}: {causes(found)}", "drops": [d.raw for d in found]}
        return {"result": DENIED, "dropSearch": drop_logs.search(start, end)}

    if str(probe.get("curlRC")) != "0":
        return failed_curl(probe, target, client, pods, seen, drop_logs, start, end)
    server = pods.get(target.hostname)
    # A Service address is translated to a backend before ztunnel; join to whichever backend served the port.
    match = [c for c in seen if (c.hbone == f"{target.hostname}:{target.port}" if server
                                 else c.app_port == str(target.port) and _ip(c.hbone) in pods)]
    # The probe's own socket is the outbound src.addr: it names one connection, where the window can hold several.
    client_addr = probe.get("clientAddr")
    if client_addr and match:
        match = [c for c in match if c.outbound and c.outbound.fields.get("src.addr") == client_addr]
        if not match:
            return {"result": f"FAIL: no ztunnel outbound line from the probe's socket {client_addr} "
                              "to this destination in the window"}
    if not match:
        return {"result": "FAIL: no ztunnel connection from the client to this destination in the window"}
    if len(match) > 1:
        return {"result": f"FAIL: {len(match)} ztunnel connections from the client to this destination in the window; "
                          "the probe cannot be joined to one",
                "lines": [r.raw for c in match for r in (c.outbound, c.inbound) if r]}
    conn = match[0]
    server = server or pods[_ip(conn.hbone)]
    want_src, want_dst = spiffe(trust, client), spiffe(trust, server)
    # A per-Pod name must reach that one Pod; any other backend means the name or its Service points elsewhere.
    served, want_server = f"{server.cluster}/{server.name}", probe.get("expectedServer")
    failures = [text for bad, text in (
        (want_server is not None and served != want_server, f"served by {served}, expected {want_server}"),
        (conn.outbound is None, "no client-side (outbound) line"),
        (conn.inbound is None, "no server-side (inbound) line"),
        (conn.outer_port != HBONE_PORT, f"outer port {conn.outer_port}, not HBONE {HBONE_PORT}"),
        (conn.inbound is not None and conn.peer_identity != want_src,
         f"peer identity {conn.peer_identity}, expected {want_src}"),
        (conn.dst.identity != want_dst, f"destination identity {conn.dst.identity}, expected {want_dst}"),
    ) if bad]
    return {
        "result": "FAIL: " + "; ".join(failures) if failures else PROVEN,
        "servedBy": served,
        "originalDestination": conn.hbone,
        "outerPort": conn.outer_port,
        "peerIdentity": conn.peer_identity,
        "destinationIdentity": conn.dst.identity,
        "policy": conn.policy,
        "lines": [r.raw for r in (conn.outbound, conn.inbound) if r],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("probes", nargs="+", help="probe JSON files or directories")
    ap.add_argument("--pods", type=Path, required=True)
    ap.add_argument("--trust-domain", action="append", default=[], metavar="CLUSTER=DOMAIN", required=True)
    ap.add_argument("--logs", nargs="+", required=True, help="ztunnel logs, one per node, named after the node")
    ap.add_argument("--drops", nargs="+", help="Cilium drop captures, one per node, named after the node")
    ap.add_argument("--since", help="ignore probes before this ISO 8601 time")
    ap.add_argument("--window", type=float, default=3.0,
                    help="seconds before a probe's `at` to search, for a row without startedAt (default 3)")
    ap.add_argument("--node-clock-offset", default="0:0", metavar="LO:HI",
                    help="measured bound of node clock minus host clock, in seconds (default 0:0)")
    ap.add_argument("--out", type=Path, help="write every verdict, with its log lines, to this JSON file")
    ap.add_argument("--rows", action="store_true", help="print one line per probe, not only the summary")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = ap.parse_args(argv)

    try:
        trust = dict(t.split("=", 1) for t in args.trust_domain)
    except ValueError:
        ap.error("--trust-domain takes CLUSTER=DOMAIN")
    pods, (records, coverage) = load_pods(args.pods), read_logs(args.logs)
    if not records:
        print("no ztunnel log records found in --logs", file=sys.stderr)
        return 2
    conns, since, window = connections(records), args.since and utc(args.since), timedelta(seconds=args.window)
    try:
        lo, hi = (float(x) for x in args.node_clock_offset.split(":"))
    except ValueError:
        ap.error("--node-clock-offset takes LO:HI in seconds")
    if lo > hi:
        ap.error("--node-clock-offset: LO must not be above HI")
    offset = (timedelta(seconds=lo), timedelta(seconds=hi))
    recorded = {"nodeClockOffset": [lo, hi]} if lo or hi else {}
    drop_logs = DropLogs(*read_drops(args.drops)) if args.drops else None

    verdicts = []
    for name, probe in load_probes(args.probes):
        if since and utc(probe["at"]) < since:
            continue
        verdict = judge(probe, pods, trust, conns, records, coverage, window, drop_logs, offset)
        # The runner's curl timings (time_namelookup, remote_ip, exitcode), when it records them, travel with the row.
        timings = {"curl": probe["curl"]} if "curl" in probe else {}
        verdicts.append({"file": name, "at": probe["at"], "cluster": probe["context"].removeprefix("kind-"),
                         "scope": probe["scope"], "expect": probe["expect"], "client": probe["client"],
                         "url": probe["url"].split("?", 1)[0], "curlRC": probe.get("curlRC"), **timings, **recorded,
                         **verdict})
    if args.out:
        args.out.write_text(json.dumps(verdicts, indent=2) + "\n")

    style = Style(args.color == "always" or (args.color == "auto" and sys.stdout.isatty()
                                             and "NO_COLOR" not in os.environ))

    def result_cell(result):
        color = RESULT_COLORS[DROPPED] if result.startswith(DROPPED) else RESULT_COLORS.get(result, "red")
        return style.color(result, color, bold=result.startswith("FAIL"))

    counts = Counter((v["cluster"], v["scope"], v["expect"], v["result"]) for v in verdicts)
    rows = [[style.cluster(c, c), s, e, str(n), result_cell(r)] for (c, s, e, r), n in sorted(counts.items())]
    out = [section("Probe join", f"{len(verdicts)} probes joined to {len(conns)} ztunnel connections", style),
           table(["CLUSTER", "SCOPE", "EXPECT", "PROBES", "RESULT"], rows, style, right=frozenset({3}))]
    if args.rows:
        rows = [[style.color(v["at"][11:23], "gray"), style.cluster(v["cluster"], f"{v['cluster']}/{v['client']}"),
                 v["url"].removeprefix("http://"), v.get("servedBy", ""),
                 style.color(short_identity(v.get("peerIdentity")), "green"), result_cell(v["result"])]
                for v in verdicts]
        out += [section("Probes", "one row per curl", style),
                table(["AT", "CLIENT", "TARGET", "SERVED BY", "PEER IDENTITY", "RESULT"], rows, style)]
    failed = [v for v in verdicts if v["result"].startswith("FAIL")]
    proven, denied = (sum(v["result"] == r for v in verdicts) for r in (PROVEN, DENIED))
    dropped = sum(v["result"].startswith(DROPPED) for v in verdicts)
    out.append(f"\n  {style.color(str(proven), 'green', bold=True)} proven over mTLS · "
               f"{style.color(str(denied), 'teal', bold=True)} unanswered with no ztunnel line · "
               + (f"{style.color(str(dropped), 'teal', bold=True)} dropped by Cilium · " if drop_logs else "")
               + f"{style.color(str(len(failed)), 'red' if failed else 'green', bold=True)} failed")
    print("\n".join(out))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        sys.stderr.close()
