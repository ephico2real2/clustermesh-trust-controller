#!/usr/bin/env python3
"""Retain real Prometheus scrape/query evidence for explicit fence lab nodes.

This does not generate traffic. Compare snapshots immediately surrounding the
lab's real traffic; packet deltas and HTTP outcomes are different evidence.
"""
import argparse
import datetime
import json
import math
import re
from pathlib import Path
import time
import urllib.parse
import urllib.request

FAMILIES = (
    "cmtc_datapath_fence_quarantine_verified",
    "cmtc_datapath_fence_dropped_packets_total",
    "cmtc_datapath_fence_dropped_bytes_total",
)
OBSERVER_FAMILIES = (
    "cmtc_datapath_observer_ready",
    "cmtc_datapath_observer_packets_total",
    "cmtc_datapath_observer_bytes_total",
)
PROFILES = {"fence": ("cmtc-bpf-fence", FAMILIES), "observer": ("cmtc-bpf-observer", OBSERVER_FAMILIES)}
SELECTOR = '{job="cmtc",component="cmtc-bpf-fence"}'


def fetch(base, path, params=None):
    url = base.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=10) as response:
        data = response.read(4*1024*1024+1)
        assert len(data) <= 4*1024*1024, "bounded Prometheus response exceeded 4MiB"
        body = json.loads(data)
    if body.get("status") != "success" or body.get("warnings") or body.get("infos"):
        raise AssertionError(body)
    return body


def expected_nodes(items):
    expected = set()
    for item in items:
        fields = tuple(item.split("/"))
        if len(fields) != 3 or not all(fields) or fields[2] not in ("ingress", "egress") or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", f) for f in fields[:2]):
            raise ValueError("--node requires cluster/node/ingress|egress")
        if fields in expected:
            raise ValueError("duplicate expected node/hook")
        expected.add(fields)
    if not expected or len({(c,n) for c,n,_ in expected}) != len(expected):
        raise ValueError("require exactly one audited hook for each explicit node")
    return expected


def snapshot(base, expected, *, absent=False, target_bases=None, api=fetch, now=None, report=None, profile="fence", clock=time.time):
    component, families = PROFILES[profile]
    now = time.time() if now is None else now
    report = {} if report is None else report
    report.update(profile=profile, families=list(families), observedAt=now, expected=sorted("/".join(k) for k in expected), absent=absent)
    clusters = {c for c,_,_ in expected}
    # Remote-write receiver A has B's series, but its Targets API cannot prove
    # B's local scrape. Require B's local Prometheus URL as separate evidence.
    if target_bases is None:
        assert len(clusters) == 1, "multiple clusters require explicit per-cluster target URLs"
        target_bases = {next(iter(clusters)): base}
    assert set(target_bases) == clusters, "target URLs must cover exactly the selected clusters"
    targets, actual_targets, checked_at = {}, [], {}
    report["targetCheckedAt"] = checked_at
    report["targets"] = targets
    for cluster, target_base in target_bases.items():
        body = api(target_base, "/api/v1/targets", {"state": "active"})
        targets[cluster] = body
        checked_at[cluster] = clock()
        selected = [x for x in body["data"]["activeTargets"] if
                    x.get("labels", {}).get("job") == "cmtc" and
                    x.get("labels", {}).get("component") == component]
        assert all(x["labels"].get("cluster") == cluster for x in selected), "local target cluster mismatch"
        actual_targets.extend(selected)
    expected_pairs = {(c,n) for c,n,_ in expected}
    if absent:
        assert not actual_targets, "fence targets remain after explicit uninstall"
    else:
        pairs = [(x["labels"].get("cluster"), x["labels"].get("node")) for x in actual_targets]
        assert len(pairs) == len(set(pairs)) and set(pairs) == expected_pairs, ("target set", pairs, expected_pairs)
        for target in actual_targets:
            assert target["health"] == "up" and not target.get("lastError"), target
            last = datetime.datetime.fromisoformat(target["lastScrape"].replace("Z", "+00:00")).timestamp()
            assert 0 <= checked_at[target["labels"]["cluster"]]-last <= 15, ("stale successful scrape", target)
    cluster_pattern = "|".join(c.replace(".", r"\.") for c in sorted(clusters))
    selector = SELECTOR.replace("cmtc-bpf-fence", component)[:-1] + ',cluster=~' + json.dumps(cluster_pattern) + '}'
    records = {}
    values = {}
    report["queries"], report["values"] = records, values
    report["sampleTimestampQueries"] = {}
    for family in families:
        body = api(base, "/api/v1/query", {"query": family+selector, "time": now})
        records[family] = body
        rows = body["data"]["result"]
        if absent:
            assert not rows, ("absent exporter became false zero or stale result", family, rows)
            continue
        found = {}
        for row in rows:
            labels = row["metric"]
            key = (labels.get("cluster"), labels.get("node"), labels.get("direction"))
            assert key in expected and key not in found, (family, key)
            for suffix in ("cluster", "node"):
                assert labels.get("exported_"+suffix, labels[suffix]) == labels[suffix], ("exporter/scrape identity disagreement", labels)
            assert not any("uid" in k.lower() or "spiffe" in k.lower() for k in labels), labels
            value = float(row["value"][1])
            assert math.isfinite(value) and value >= 0, (family, row)
            if family == families[0]:
                assert value == 1, ("quarantine sample not verified", row)
            found[key] = value
        assert set(found) == expected, ("missing fence series", family, found, expected)
        values[family] = {"/".join(k): v for k,v in found.items()}
        # Instant-vector value[0] is the evaluation time, not the underlying
        # sample time. A healthy local target cannot prove that remote-write
        # delivered a fresh sample to the central receiver.
        timestamps = api(base, "/api/v1/query", {"query": "timestamp("+family+selector+")", "time": now})
        report["sampleTimestampQueries"][family] = timestamps
        stamped = set()
        for row in timestamps["data"]["result"]:
            labels = row["metric"]
            key = (labels.get("cluster"), labels.get("node"), labels.get("direction"))
            assert key in expected and key not in stamped, ("ambiguous sample timestamp", family, key)
            last = float(row["value"][1])
            assert math.isfinite(last) and 0 <= now-last <= 15, ("stale central sample", family, key, now-last)
            stamped.add(key)
        assert stamped == expected, ("missing sample timestamp", family, stamped, expected)
    report["scope"] = "One audited veth hook/node; packet evidence only, not requests/TLS/Protected"
    return report


def compare(before, after, *, idle=False):
    assert not before["absent"] and not after["absent"]
    assert before["expected"] == after["expected"], "selected node scope changed"
    assert after["observedAt"] > before["observedAt"], "snapshot time did not advance"
    result = {}
    families = before.get("families", list(FAMILIES))
    assert families == after.get("families", list(FAMILIES)), "exporter profile changed"
    for family in families[1:]:
        changes = {}
        for key in before["expected"]:
            first, last = before["values"][family][key], after["values"][family][key]
            # A reset/map replacement invalidates this exact-boundary proof; do
            # not turn it into a positive delta with Prometheus extrapolation.
            assert last >= first, ("counter reset; retry exact-map test", family, key)
            delta = last-first
            assert delta == 0 if idle else delta > 0, ("unexpected idle/load packet delta", family, key, delta)
            changes[key] = delta
        result[family] = changes
    return {"mode": "idle" if idle else "actual-load", "deltas": result,
            "claim": "Counter deltas only; join real HTTP outcome and exact-map-ID ledger separately"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="fence")
    parser.add_argument("--prometheus", required=True)
    parser.add_argument("--node", action="append", default=[])
    parser.add_argument("--targets-prometheus", action="append", default=[], metavar="CLUSTER=URL")
    parser.add_argument("--absent", action="store_true")
    parser.add_argument("--before", type=Path)
    parser.add_argument("--idle", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert not args.idle or args.before, "--idle requires --before"
    expected = expected_nodes(args.node)
    target_bases = {}
    for item in args.targets_prometheus:
        cluster, sep, url = item.partition("=")
        assert sep and cluster and url and cluster not in target_bases, "invalid duplicate CLUSTER=URL"
        target_bases[cluster] = url
    if not target_bases:
        target_bases = None
    report = {"expected": sorted(args.node), "passed": False}
    try:
        report = snapshot(args.prometheus, expected, absent=args.absent, target_bases=target_bases, report=report, profile=args.profile)
        if args.before:
            report["comparison"] = compare(json.loads(args.before.read_text()), report, idle=args.idle)
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
