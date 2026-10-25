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
                  the packets. That needs the Cilium drop event of the same flow.

Inputs:
  probes          JSON files, or directories of them, written by live_mtls_fixture_runner.py: a list of rows with
                  at, context, namespace, client, url, expect, scope and curlRC. `at` is written after curl returns.
  --pods FILE     one fixture Pod per line: CLUSTER NAMESPACE NAME POD_IP NODE SERVICE_ACCOUNT [UID]; '#' comments
  --trust-domain  CLUSTER=DOMAIN for every cluster, e.g. cmtc-a=cmtc-a.mesh.example. The expected SPIFFE ID is
                  spiffe://DOMAIN/ns/NAMESPACE/sa/SERVICE_ACCOUNT. It is given, never read from the logs, so the
                  check is not circular.
  --logs FILES    ztunnel logs, one file per node, named after the node. A filtered extract must declare what it
                  covers with a "# coverage <ISO start> <ISO end>" line (see ztunnel_log_view.read_logs).

Exit status: 0 when every probe is proven or unanswered as expected, 1 when any probe fails, 2 for bad input.

Example:
  scripts/evidence/join_probes_to_ztunnel.py docs/evidence/g1-destination-sources/probes \\
      --pods docs/evidence/g1-destination-sources/fixture-pods.txt \\
      --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \\
      --logs docs/evidence/g1-destination-sources/ztunnel-access/*.log \\
      --since 2026-10-25T23:00:00Z --out docs/evidence/g1-destination-sources/join.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ztunnel_log_view import (HBONE_PORT, Connection, Style, connections, read_logs,  # noqa: E402
                              section, short_identity, table)

PROVEN = "mTLS proven"
DENIED = "no response, no ztunnel line"
RESULT_COLORS = {PROVEN: "green", DENIED: "teal"}


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


def judge(probe: dict, pods: dict[str, Pod], trust: dict[str, str], conns: list[Connection], records,
          coverage: dict, window: timedelta) -> dict:
    """Return the verdict for one probe, with the connection it was joined to."""
    at, target = utc(probe["at"]), urlsplit(probe["url"])
    # Absence of a line means something only where every node's log covers the probe's whole window.
    gaps = sorted(n for n, (start, end) in coverage.items() if not start <= at - window or not at <= end)
    if gaps:
        return {"result": "FAIL: the logs of " + ", ".join(gaps) + " do not cover this probe"}
    cluster = probe["context"].removeprefix("kind-")
    client = next((p for p in pods.values()
                   if (p.cluster, p.namespace, p.name) == (cluster, probe["namespace"], probe["client"])), None)
    if client is None:
        return {"result": f"FAIL: client {cluster}/{probe['namespace']}/{probe['client']} is not in --pods"}
    seen = [c for c in conns if c.src_ip == client.ip and at - window <= c.at <= at]

    if probe["expect"] == "deny":
        lines = [r.raw for r in records if at - window <= r.at <= at
                 and client.ip in (_ip(r.fields.get("src.addr", "")), _ip(r.spans.get("inbound", {}).get("peer", "")))]
        if str(probe.get("curlRC")) == "0":
            return {"result": "FAIL: the denied caller got a response"}
        return {"result": DENIED} if not lines else {"result": "FAIL: a ztunnel saw the denied caller", "lines": lines}

    if str(probe.get("curlRC")) != "0":
        return {"result": f"FAIL: curl exit {probe.get('curlRC')}, no connection to join"}
    server = pods.get(target.hostname)
    # A Service address is translated to a backend before ztunnel; join to whichever backend served the port.
    match = [c for c in seen if (c.hbone == f"{target.hostname}:{target.port}" if server
                                 else c.app_port == str(target.port) and _ip(c.hbone) in pods)]
    if not match:
        return {"result": "FAIL: no ztunnel connection from the client to this destination in the window"}
    conn = next((c for c in reversed(match) if c.outbound and c.inbound), match[-1])
    server = server or pods[_ip(conn.hbone)]
    want_src, want_dst = spiffe(trust, client), spiffe(trust, server)
    failures = [text for bad, text in (
        (conn.outbound is None, "no client-side (outbound) line"),
        (conn.inbound is None, "no server-side (inbound) line"),
        (conn.outer_port != HBONE_PORT, f"outer port {conn.outer_port}, not HBONE {HBONE_PORT}"),
        (conn.inbound is not None and conn.peer_identity != want_src,
         f"peer identity {conn.peer_identity}, expected {want_src}"),
        (conn.dst.identity != want_dst, f"destination identity {conn.dst.identity}, expected {want_dst}"),
    ) if bad]
    return {
        "result": "FAIL: " + "; ".join(failures) if failures else PROVEN,
        "servedBy": f"{server.cluster}/{server.name}",
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
    ap.add_argument("--since", help="ignore probes before this ISO 8601 time")
    ap.add_argument("--window", type=float, default=3.0, help="seconds before a probe's `at` to search (default 3)")
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

    verdicts = []
    for name, probe in load_probes(args.probes):
        if since and utc(probe["at"]) < since:
            continue
        verdict = judge(probe, pods, trust, conns, records, coverage, window)
        verdicts.append({"file": name, "at": probe["at"], "cluster": probe["context"].removeprefix("kind-"),
                         "scope": probe["scope"], "expect": probe["expect"], "client": probe["client"],
                         "url": probe["url"].split("?", 1)[0], "curlRC": probe.get("curlRC"), **verdict})
    if args.out:
        args.out.write_text(json.dumps(verdicts, indent=2) + "\n")

    style = Style(args.color == "always" or (args.color == "auto" and sys.stdout.isatty()
                                             and "NO_COLOR" not in os.environ))

    def result_cell(result):
        return style.color(result, RESULT_COLORS.get(result, "red"), bold=result.startswith("FAIL"))

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
    out.append(f"\n  {style.color(str(proven), 'green', bold=True)} proven over mTLS · "
               f"{style.color(str(denied), 'teal', bold=True)} unanswered with no ztunnel line · "
               f"{style.color(str(len(failed)), 'red' if failed else 'green', bold=True)} failed")
    print("\n".join(out))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        sys.stderr.close()
