#!/usr/bin/env python3
"""Read ztunnel logs and show them as connections, flows, peer identities and problems.

Each input file is one node's ztunnel log. The node is the file name without its extension (or --node for a single
file or stdin). Lines may be ztunnel's own format, TIME<tab>LEVEL<tab>TARGET<tab>MESSAGE<tab>FIELDS, or carry the CRI
prefix of the files under /var/log/pods ("TIME stdout F ").

What the view shows:
  - one row per proxied connection. A connection's outbound line (client node) is paired with its inbound line
    (server node) by client IP, original destination (dst.hbone_addr) and time;
  - the peer identity. Only the inbound line proves it: the server-side ztunnel reads src.identity from the client
    certificate of the TLS connection it accepted (ztunnel src/proxy/inbound.rs, certificate_from_connection);
  - the "allow policy match" line of the inbound side, when the log has it;
  - errors and warnings, grouped by message.

Examples:
  scripts/evidence/ztunnel_log_view.py docs/evidence/g1-destination-sources/ztunnel-access/*.log
  scripts/evidence/ztunnel_log_view.py --brief --since 23:00 --until 23:02 <files>
  kubectl logs -n kube-system ztunnel-cilium-xxxxx | scripts/evidence/ztunnel_log_view.py --node cmtc-a-worker -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

CRI_PREFIX = re.compile(r"^\S+ (?:stdout|stderr) [FP] ")
COVERAGE = re.compile(r"^#\s*coverage\s+(\S+)\s+(\S+)")
FIELD = re.compile(r'([\w.]+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')
SPAN = re.compile(r"(\w+)\{([^}]*)\}")
ERROR_DETAIL = re.compile(r'kind: (\w+), error: "([^"]*)"')
HEX_ID = re.compile(r"\b[0-9a-f]{16,}\b")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
HBONE_PORT = "15008"
# An outbound line and its inbound line are written by two ztunnels within milliseconds of each other.
PAIR_WINDOW = timedelta(seconds=2)
POLICY_WINDOW = timedelta(seconds=1)
SECTIONS = ("overview", "identities", "flows", "timeline", "problems")


# ---------------------------------------------------------------------------------------------------------- parsing

@dataclass(frozen=True, eq=False)
class Record:
    """One parsed ztunnel log line."""
    node: str
    at: datetime
    level: str
    module: str     # the tracing target without its spans, e.g. "access" or "proxy::h2::client"
    spans: dict     # span name -> its fields, e.g. {"proxy": {"wl": "ns/name"}, "inbound": {"peer": "ip:port"}}
    message: str
    fields: dict
    raw: str

    @property
    def workload(self) -> str | None:
        """The workload whose proxy wrote the line, as "namespace/name"."""
        return self.spans.get("proxy", {}).get("wl")


def _fields(text: str) -> dict:
    return {m.group(1): m.group(2) if m.group(2) is not None else m.group(3) for m in FIELD.finditer(text)}


def parse_line(raw: str, node: str) -> Record | None:
    """Parse one line, or return None for a line that is not a ztunnel record (a banner or a wrapped fragment)."""
    line = CRI_PREFIX.sub("", raw.rstrip("\n"), count=1)
    parts = line.split("\t")
    if len(parts) < 4:
        return None
    try:
        at = datetime.fromisoformat(parts[0])
    except ValueError:
        return None
    target = parts[2]
    return Record(
        node=node,
        at=at,
        level=parts[1].strip(),
        module=re.split(r":(?=\w+\{)", target, maxsplit=1)[0],
        spans={name: _fields(body) for name, body in SPAN.findall(target)},
        message=parts[3].strip(),
        fields=_fields("\t".join(parts[4:])),
        raw=line,
    )


def read_logs(paths: list[str], node: str | None = None) -> tuple[list[Record], dict[str, tuple[datetime, datetime]]]:
    """Return every record, oldest first, and the time each node's log covers.

    A filtered extract keeps only some lines, so its first and last line do not show which times it covers. An
    extract declares that with a header line "# coverage <ISO start> <ISO end>". Without one, a node's coverage is
    its first to its last record.
    """
    if node and len(paths) != 1:
        raise SystemExit("--node names a single input; with several files each file name is its node")
    records, coverage = [], {}
    for path in paths:
        name = node or ("stdin" if path == "-" else Path(path).stem)
        lines = sys.stdin if path == "-" else Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        own = []
        for line in lines:
            header = COVERAGE.match(line)
            if header:
                coverage[name] = (datetime.fromisoformat(header.group(1)), datetime.fromisoformat(header.group(2)))
            elif (record := parse_line(line, name)) is not None:
                own.append(record)
        if own and name not in coverage:
            coverage[name] = (min(r.at for r in own), max(r.at for r in own))
        records.extend(own)
    return sorted(records, key=lambda r: r.at), coverage


def read_records(paths: list[str], node: str | None = None) -> list[Record]:
    return read_logs(paths, node)[0]


# ------------------------------------------------------------------------------------------------------ connections

@dataclass(frozen=True)
class Endpoint:
    cluster: str
    namespace: str
    workload: str
    identity: str

    @property
    def label(self) -> str:
        return f"{self.cluster}/{self.workload}" if self.cluster else self.workload or "?"


@dataclass(eq=False)
class Connection:
    """One proxied connection, seen by the client-side ztunnel, the server-side ztunnel, or both."""
    src_ip: str
    hbone: str          # the original destination ip:port, carried inside the HBONE tunnel
    outer_port: str     # the destination port on the wire; HBONE_PORT for a tunnelled connection
    src: Endpoint
    dst: Endpoint
    outbound: Record | None = None
    inbound: Record | None = None
    policy: str | None = None

    @property
    def at(self) -> datetime:
        return (self.inbound or self.outbound).at

    @property
    def app_port(self) -> str:
        return self.hbone.rsplit(":", 1)[-1]

    @property
    def scope(self) -> str:
        if self.src.cluster != self.dst.cluster:
            return "cross cluster"
        if self.outbound and self.inbound:
            return "same node" if self.outbound.node == self.inbound.node else "cross node"
        return "same cluster"

    @property
    def peer_identity(self) -> str | None:
        """The client identity read from the client certificate; only the server side has it."""
        return self.inbound.fields.get("src.identity") if self.inbound else None


def _ip(addr: str) -> str:
    return addr.rsplit(":", 1)[0]


def _endpoint(fields: dict, side: str) -> Endpoint:
    return Endpoint(*(fields.get(f"{side}.{key}", "") for key in ("cluster", "namespace", "workload", "identity")))


def _connection(inbound: Record | None, outbound: Record | None) -> Connection:
    f = (inbound or outbound).fields
    dst_addr = f.get("dst.addr", "")
    return Connection(src_ip=_ip(f.get("src.addr", "")), hbone=f.get("dst.hbone_addr", dst_addr),
                      outer_port=dst_addr.rsplit(":", 1)[-1], src=_endpoint(f, "src"), dst=_endpoint(f, "dst"),
                      outbound=outbound, inbound=inbound)


def connections(records: list[Record]) -> list[Connection]:
    access = [r for r in records if r.module == "access" and r.message == "connection complete"]
    pending = defaultdict(list)
    for r in access:
        if r.fields.get("direction") == "outbound":
            pending[(_ip(r.fields.get("src.addr", "")), r.fields.get("dst.hbone_addr"))].append(r)
    result = []
    for r in access:
        if r.fields.get("direction") != "inbound":
            continue
        key = (_ip(r.fields.get("src.addr", "")), r.fields.get("dst.hbone_addr"))
        near = [o for o in pending.get(key, ()) if abs(o.at - r.at) <= PAIR_WINDOW]
        mate = min(near, key=lambda o: abs(o.at - r.at), default=None)
        if mate:
            pending[key].remove(mate)
        result.append(_connection(r, mate))
    result.extend(_connection(None, o) for rest in pending.values() for o in rest)
    _attach_policies(result, records)
    return sorted(result, key=lambda c: c.at)


def _attach_policies(conns: list[Connection], records: list[Record]) -> None:
    matches = defaultdict(list)
    for r in records:
        if r.message == "allow policy match" and "inbound" in r.spans:
            matches[(r.workload, r.spans["inbound"].get("peer"))].append(r)
    for c in conns:
        if not c.inbound:
            continue
        key = (f"{c.dst.namespace}/{c.dst.workload}", c.inbound.fields.get("src.addr"))
        near = [m for m in matches.get(key, ()) if abs(m.at - c.inbound.at) <= POLICY_WINDOW]
        if near:
            c.policy = min(near, key=lambda m: abs(m.at - c.inbound.at)).fields.get("policy")


# --------------------------------------------------------------------------------------------------------- problems

@dataclass(eq=False)
class Problem:
    level: str
    module: str
    summary: str
    records: list


def summarize(message: str) -> str:
    """Name an error without its per-connection ids, keeping the kind and the reason ztunnel gave."""
    text = HEX_ID.sub("…", message)
    detail = ERROR_DETAIL.search(text)
    if detail:
        return f"{text.split(': Error {', 1)[0]}: {detail.group(1)}, \"{detail.group(2)}\""
    return text if len(text) <= 160 else text[:157] + "…"


def problems(records: list[Record]) -> list[Problem]:
    groups = {}
    for r in records:
        if r.level not in ("error", "warn"):
            continue
        key = (r.level, r.module, summarize(r.message))
        groups.setdefault(key, Problem(*key, records=[])).records.append(r)
    return sorted(groups.values(), key=lambda p: (p.level != "error", p.records[0].at))


# -------------------------------------------------------------------------------------------------------- rendering

TABLEAU = {"blue": (78, 121, 167), "orange": (242, 142, 43), "red": (225, 87, 89), "teal": (118, 183, 178),
           "green": (89, 161, 79), "yellow": (237, 201, 72), "purple": (176, 122, 161), "gray": (148, 148, 148)}
CLUSTER_COLORS = ("blue", "orange", "purple", "teal", "yellow")
SCOPE_COLORS = {"same node": "teal", "cross node": "purple", "cross cluster": "orange", "same cluster": "gray"}


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.clusters: dict[str, str] = {}

    def color(self, text: str, name: str | None = None, bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text
        codes = (["1"] if bold else []) + (["2"] if dim else [])
        if name:
            codes.append("38;2;{};{};{}".format(*TABLEAU[name]))
        return f"\x1b[{';'.join(codes)}m{text}\x1b[0m" if codes else text

    def cluster(self, cluster: str, text: str) -> str:
        name = self.clusters.setdefault(cluster, CLUSTER_COLORS[len(self.clusters) % len(CLUSTER_COLORS)])
        return self.color(text, name)

    def endpoint(self, e: Endpoint) -> str:
        return self.cluster(e.cluster, e.label)

    def ok(self, good: bool, label: str) -> str:
        return self.color(f"✓ {label}", "green") if good else self.color(f"· {label}", dim=True)


def visible(text: str) -> int:
    return len(ANSI.sub("", text))


def table(headers: list[str], rows: list[list[str]], style: Style, right: frozenset = frozenset()) -> str:
    widths = [max([visible(h)] + [visible(r[i]) for r in rows]) for i, h in enumerate(headers)]

    def line(cells):
        out = []
        for i, cell in enumerate(cells):
            pad = " " * (widths[i] - visible(cell))
            out.append(pad + cell if i in right else cell + pad)
        return "  " + "  ".join(out).rstrip()

    head = line([style.color(h, "gray", bold=True) for h in headers])
    rule = "  " + style.color("─" * (sum(widths) + 2 * (len(widths) - 1)), "gray", dim=True)
    return "\n".join([head, rule] + [line(r) for r in rows])


def section(title: str, note: str, style: Style) -> str:
    return f"\n{style.color('▌ ' + title, bold=True)}  {style.color(note, 'gray')}\n"


def short_identity(spiffe: str | None) -> str:
    """spiffe://<trust domain>/ns/<ns>/sa/<sa> -> <sa>@<trust domain>."""
    if not spiffe:
        return ""
    m = re.match(r"spiffe://([^/]+)/ns/[^/]+/sa/(.+)$", spiffe)
    return f"{m.group(2)}@{m.group(1)}" if m else spiffe


def clock(at: datetime) -> str:
    return at.strftime("%H:%M:%S.") + f"{at.microsecond // 1000:03d}"


def span(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m" if seconds >= 3600 else f"{seconds // 60}m{seconds % 60:02d}s"


def bytes_cell(c: Connection) -> str:
    """Request and response bytes, as the server side counted them (else the client side)."""
    if c.inbound:
        f = c.inbound.fields
        return f"{f.get('bytes_recv', '?')}↑ {f.get('bytes_sent', '?')}↓"
    f = c.outbound.fields
    return f"{f.get('bytes_sent', '?')}↑ {f.get('bytes_recv', '?')}↓"


def render_overview(records, conns, probs, paths, coverage, style):
    nodes = sorted({r.node for r in records} | set(coverage))
    first, last = records[0].at, records[-1].at
    levels = Counter(r.level for r in records)
    tunnelled = sum(c.outer_port == HBONE_PORT for c in conns)
    both = sum(bool(c.outbound and c.inbound) for c in conns)
    proven = sum(bool(c.peer_identity) and c.peer_identity == c.src.identity for c in conns)
    rows = [
        ["inputs", f"{len(paths)} file(s), nodes: " + ", ".join(nodes)],
        ["window", f"{first:%Y-%m-%d} {clock(first)}Z → {clock(last)}Z  ({span((last - first).total_seconds())})"],
        ["lines", f"{len(records)} parsed: " + ", ".join(f"{n} {lvl}" for lvl, n in levels.most_common())],
        ["connections", f"{len(conns)} · {tunnelled} over HBONE :{HBONE_PORT} · {both} seen by both ztunnels"
                        f" · {proven} with the peer identity read from its certificate"],
        ["problems", style.color(f"{sum(len(p.records) for p in probs)} lines in {len(probs)} group(s)",
                                 "red" if probs else "green")],
    ]
    out = [section("Overview", "what these logs contain", style)]
    out += [f"  {style.color(k.ljust(12), 'gray')}{v}" for k, v in rows]
    width = max(map(len, nodes), default=0)
    for node in nodes:
        start, end = coverage.get(node, (None, None))
        text = f"{clock(start)}Z → {clock(end)}Z" if start else style.color("no records", "yellow")
        out.append(f"  {style.color('covers'.ljust(12), 'gray')}{style.color(node.ljust(width), bold=True)}  {text}")
    plain = [c for c in conns if c.outer_port != HBONE_PORT]
    if plain:
        out.append("  " + style.color(f"{len(plain)} connection(s) did not use HBONE; see the timeline", "red"))
    return "\n".join(out)


def render_identities(conns, style):
    seen = defaultdict(lambda: {"count": 0, "servers": set()})
    for c in conns:
        if c.peer_identity:
            seen[c.peer_identity]["count"] += 1
            seen[c.peer_identity]["servers"].add(c.dst.label)
    rows = [[style.color(short_identity(i), "green"), str(v["count"]), ", ".join(sorted(v["servers"]))]
            for i, v in sorted(seen.items())]
    note = "client identities the server-side ztunnel read from each accepted client certificate"
    body = table(["PEER IDENTITY (mTLS)", "CONNECTIONS", "ACCEPTED BY"], rows, style, right=frozenset({1})) \
        if rows else "  " + style.color("no inbound lines: no peer identity can be shown", "yellow")
    return section("Peer identities", note, style) + body


def render_flows(conns, style):
    flows = defaultdict(list)
    for c in conns:
        flows[(c.src.label, c.dst.label, c.scope)].append(c)
    rows = []
    for (_, _, scope), group in sorted(flows.items(), key=lambda kv: (kv[0][2], kv[0][0], kv[0][1])):
        c0 = group[0]
        ports = Counter(c.app_port for c in group)
        both = sum(bool(c.outbound and c.inbound) for c in group)
        policy = sum(bool(c.policy) for c in group)
        rows.append([style.endpoint(c0.src), style.color("→", "gray"), style.endpoint(c0.dst),
                     style.color(scope, SCOPE_COLORS[scope]),
                     " ".join(f"{p}×{n}" for p, n in sorted(ports.items(), key=lambda kv: int(kv[0]))),
                     str(len(group)), f"{both}/{len(group)}", f"{policy}/{len(group)}"])
    return section("Flows", "connections grouped by caller, destination and path", style) + table(
        ["FROM", "", "TO", "PATH", "PORTS", "CONN", "BOTH SIDES", "POLICY"], rows, style,
        right=frozenset({5, 6, 7}))


def render_timeline(conns, style, limit):
    shown = conns[-limit:] if limit else conns
    rows = []
    for c in shown:
        identity = short_identity(c.peer_identity)
        identity = style.color(identity, "green") if identity else style.color("(no server-side line)", dim=True)
        port = f":{c.app_port}" + ("" if c.outer_port == HBONE_PORT else style.color(f" plain :{c.outer_port}", "red"))
        dur = (c.inbound or c.outbound).fields.get("duration", "")
        rows.append([style.color(clock(c.at), "gray"), style.endpoint(c.src), style.color("→", "gray"),
                     style.endpoint(c.dst), port, style.color(c.scope, SCOPE_COLORS[c.scope]),
                     f"{style.ok(bool(c.outbound), 'client')} {style.ok(bool(c.inbound), 'server')} "
                     f"{style.ok(bool(c.policy), 'policy')}", identity, bytes_cell(c), dur])
    note = f"every connection, oldest first (UTC){'' if not limit or limit >= len(conns) else f'; last {limit} of {len(conns)}'}"
    return section("Timeline", note, style) + table(
        ["TIME", "FROM", "", "TO", "PORT", "PATH", "SEEN BY", "PEER IDENTITY", "BYTES", "TOOK"], rows, style,
        right=frozenset({8, 9}))


def render_problems(probs, style):
    if not probs:
        return section("Problems", "errors and warnings", style) + "  " + style.color("none", "green")
    out = [section("Problems", "errors and warnings, grouped by message", style)]
    for p in probs:
        first, last = p.records[0].at, p.records[-1].at
        where = Counter(f"{r.workload or '-'} on {r.node}" for r in p.records)
        minutes = Counter(r.at.strftime("%H:%M") for r in p.records)
        out.append(f"  {style.color(f'{p.level.upper():5}', 'red' if p.level == 'error' else 'yellow', bold=True)} "
                   f"{style.color(f'×{len(p.records)}', bold=True)}  {p.summary}")
        out.append(f"        {style.color('module', 'gray')}  {p.module}")
        out.append(f"        {style.color('when  ', 'gray')}  {clock(first)}Z → {clock(last)}Z   per minute: "
                   + ", ".join(f"{m} ×{n}" for m, n in sorted(minutes.items())))
        out.append(f"        {style.color('where ', 'gray')}  " + "; ".join(f"{w} ×{n}" for w, n in where.most_common()))
    return "\n".join(out)


def as_json(conns, probs) -> str:
    def side(r):
        return None if r is None else {"node": r.node, "at": r.at.isoformat(), "fields": r.fields}
    return json.dumps({
        "connections": [{"at": c.at.isoformat(), "from": c.src.label, "to": c.dst.label, "scope": c.scope,
                         "originalDestination": c.hbone, "outerPort": c.outer_port, "peerIdentity": c.peer_identity,
                         "expectedSourceIdentity": c.src.identity, "destinationIdentity": c.dst.identity,
                         "policy": c.policy, "outbound": side(c.outbound), "inbound": side(c.inbound)} for c in conns],
        "problems": [{"level": p.level, "module": p.module, "summary": p.summary, "count": len(p.records),
                      "first": p.records[0].at.isoformat(), "last": p.records[-1].at.isoformat(),
                      "where": sorted({f"{r.workload or '-'} on {r.node}" for r in p.records})} for p in probs],
    }, indent=2)


# --------------------------------------------------------------------------------------------------------------- cli

def _bound(text: str | None, day: datetime) -> datetime | None:
    """A full ISO time, or HH:MM[:SS] on the day of the first record (UTC)."""
    if not text:
        return None
    if "T" in text:
        at = datetime.fromisoformat(text)
        return at if at.tzinfo else at.replace(tzinfo=timezone.utc)
    clock_time = datetime.strptime(text, "%H:%M:%S" if text.count(":") == 2 else "%H:%M").time()
    return datetime.combine(day.date(), clock_time, tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("logs", nargs="+", help="ztunnel log files, one per node, or - for stdin")
    ap.add_argument("--node", help="node name for a single input (default: the file name)")
    ap.add_argument("--since", help="start time: HH:MM[:SS] (UTC, day of the first line) or ISO 8601")
    ap.add_argument("--until", help="end time, same forms as --since")
    ap.add_argument("--workload", help="keep connections and problems whose workload contains this text")
    ap.add_argument("--only", choices=SECTIONS, action="append", help="show only this section (repeatable)")
    ap.add_argument("--brief", action="store_true", help="leave out the per-connection timeline")
    ap.add_argument("--limit", type=int, default=0, help="show only the last N timeline rows")
    ap.add_argument("--json", action="store_true", help="print connections and problems as JSON")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    ap.add_argument("--fail-on-problems", action="store_true", help="exit 1 when any error or warning is present")
    args = ap.parse_args(argv)

    records, coverage = read_logs(args.logs, args.node)
    if not records:
        print("no ztunnel log records found in the input", file=sys.stderr)
        return 2
    since, until = _bound(args.since, records[0].at), _bound(args.until, records[0].at)
    records = [r for r in records if (not since or r.at >= since) and (not until or r.at < until)]
    if not records:
        print("no records inside the requested time window", file=sys.stderr)
        return 2
    conns, probs = connections(records), problems(records)
    if args.workload:
        conns = [c for c in conns if args.workload in c.src.label or args.workload in c.dst.label]
        probs = [p for p in probs if any(args.workload in (r.workload or "") for r in p.records)]

    if args.json:
        print(as_json(conns, probs))
    else:
        use_color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty()
                                               and "NO_COLOR" not in os.environ)
        style = Style(use_color)
        wanted = args.only or [s for s in SECTIONS if not (args.brief and s == "timeline")]
        parts = {
            "overview": lambda: render_overview(records, conns, probs, args.logs, coverage, style),
            "identities": lambda: render_identities(conns, style),
            "flows": lambda: render_flows(conns, style),
            "timeline": lambda: render_timeline(conns, style, args.limit),
            "problems": lambda: render_problems(probs, style),
        }
        print("\n".join(parts[s]() for s in SECTIONS if s in wanted))
    return 1 if args.fail_on_problems and probs else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:  # piped into head or less and closed early
        sys.stderr.close()
