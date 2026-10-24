#!/usr/bin/env python3
"""Validate dashboard semantics, then optionally retain real Prometheus evidence."""

import argparse
import datetime
import json
import math
import pathlib
import time
import urllib.parse
import urllib.request


FOLDER = pathlib.Path(__file__).resolve().parent
TITLES = {
    3: "mTLS TCP connections started",
    4: "TCP attempts without verified mTLS",
    10: "Connections rejected by policy — DENY",
}
COLORS = {
    "mTLS · no failure flag": "#59a14f",
    "Unauthenticated blocked": "#f28e2b",
    "Authenticated denied": "#edc948",
    "Unverified · no failure flag": "#e15759",
    "Other failures": "#b07aa1",
}
BASE = ('job="cmtc-spire-ztunnel",cluster="cmtc-mtls",'
        'reporter="destination",destination_workload_namespace="mtls-spike"')


def validate_structure(dashboard):
    panels = {p["id"]: p for p in dashboard["panels"]}
    assert len(panels) == len(dashboard["panels"]) == 12, "Duplicate or missing panels"
    for panel in panels.values():
        assert panel.get("description"), f"Missing explanation: {panel['title']}"
    for panel_id, title in TITLES.items():
        panel = panels[panel_id]
        assert panel["title"] == title, f"Misleading connection title: {panel['title']}"
        expr = panel["targets"][0]["expr"]
        assert "increase(" in expr and "[${__range_ms}ms] @ end()" in expr, title
        assert 'reporter="destination"' in expr, title
    assert 'connection_security_policy="mutual_tls"' in panels[3]["targets"][0]["expr"]
    assert 'connection_security_policy!="mutual_tls"' in panels[4]["targets"][0]["expr"]
    deny = panels[10]["targets"][0]["expr"]
    assert "istio_tcp_connections_failed_total" in deny and 'response_flags="DENY"' in deny
    pie = panels[11]
    assert pie["type"] == "piechart" and len(pie["targets"]) == 5
    assert pie["options"]["legend"]["placement"] == "bottom"
    assert set(t["legendFormat"] for t in pie["targets"]) == set(COLORS)
    overrides = {o["matcher"]["options"]: o["properties"] for o in pie["fieldConfig"]["overrides"]}
    for name, color in COLORS.items():
        actual = next(p["value"]["fixedColor"] for p in overrides[name] if p["id"] == "color")
        assert actual == color, f"Outcome colour changed: {name}"
    for target in pie["targets"]:
        assert target["instant"] and not target["range"], "Pie must reduce at range end"
        assert "istio_tcp_connections_closed_total" in target["expr"]
        assert "[${__range_ms}ms] @ end()" in target["expr"]
        assert 'reporter="source"' not in target["expr"], "Double-counted source reports"
        assert "and on()" in target["expr"], "Missing telemetry guard"
    for panel_id in [6, 7]:
        panel = panels[panel_id]
        assert panel["options"]["legend"]["placement"] == "bottom"
        assert panel["fieldConfig"]["defaults"]["min"] == 0
        assert panel["fieldConfig"]["defaults"]["custom"]["lineWidth"] == 1
        assert panel["fieldConfig"]["defaults"]["custom"]["fillOpacity"] == 10
        assert "$__rate_interval" in panel["targets"][0]["expr"]
    return panels


def live_queries(dashboard, base_url, from_ms, to_ms, expect_load):
    assert to_ms > from_ms
    query_time = to_ms / 1000
    range_ms = to_ms - from_ms
    records, categories = [], []

    def query(expr, empty_allowed=False):
        url = base_url.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode({
            "query": expr, "time": query_time,
        })
        started = time.monotonic()
        with urllib.request.urlopen(url, timeout=30) as response:
            result = json.load(response)
        elapsed = time.monotonic() - started
        assert result["status"] == "success", result
        assert not result.get("warnings") and not result.get("infos"), result
        assert empty_allowed or result["data"]["result"], f"Empty query: {expr}"
        return result, elapsed

    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            expr = target["expr"].replace("${__range_ms}ms", f"{range_ms}ms").replace("$__rate_interval", "60s")
            response, elapsed = query(expr)
            records.append({"panelId": panel["id"], "panel": panel["title"],
                            "target": target["refId"], "query": expr,
                            "elapsedSeconds": elapsed, "response": response})
            values = [float(row["value"][1]) for row in response["data"]["result"]]
            assert all(math.isfinite(v) and v >= 0 for v in values), values
            if expect_load and panel["id"] in [2, 3, 4, 5, 6, 7, 10]:
                assert any(v > 0 for v in values), f"Expected load absent: {panel['title']}"
            if panel["id"] == 11:
                assert len(values) == 1
                categories.append({"category": target["legendFormat"], "estimatedConnections": values[0]})
    expr = f"sum(increase(istio_tcp_connections_closed_total{{{BASE}}}[{range_ms}ms] @ end()))"
    total_response, _ = query(expr)
    total = float(total_response["data"]["result"][0]["value"][1])
    assert total > 0, "No completed TCP attempts; no meaningful percentage"
    assert math.isclose(sum(c["estimatedConnections"] for c in categories), total, rel_tol=1e-9, abs_tol=1e-6)
    for category in categories:
        category["percent"] = 100 * category["estimatedConnections"] / total
    assert math.isclose(sum(c["percent"] for c in categories), 100, abs_tol=1e-9)
    missing_expr = next(r["query"] for r in records if r["panelId"] == 11).replace(
        'cluster="cmtc-mtls"', 'cluster="cmtc-does-not-exist"')
    missing, _ = query(missing_expr, empty_allowed=True)
    assert missing["data"]["result"] == [], "Missing telemetry became a false zero"
    return {"observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "fromMilliseconds": from_ms, "toMilliseconds": to_ms,
            "queryTimeSeconds": query_time, "rateInterval": "60s",
            "totalQuerySeconds": sum(r["elapsedSeconds"] for r in records),
            "panels": records,
            "pie": {"query": expr, "estimatedTotal": total, "categories": categories,
                    "partitionEqualsDenominator": True, "percentSum": 100,
                    "missingTelemetryRemainsUnavailable": True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dashboard", type=pathlib.Path, action="append")
    parser.add_argument("--prometheus", help="Prometheus-compatible API base, without /api/v1")
    parser.add_argument("--from-ms", type=int)
    parser.add_argument("--to-ms", type=int)
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--expect-load", action="store_true", help="Require positive mTLS, rejection and payload signals")
    args = parser.parse_args()
    paths = args.dashboard or [FOLDER / "authenticated-only.json"]
    reports = []
    for path in paths:
        dashboard = json.loads(path.read_text())
        validate_structure(dashboard)
        print(f"PASS semantics, fixed colours, captions and layout: {path.name}")
        if args.prometheus:
            assert args.from_ms is not None and args.to_ms is not None and args.out
            report = live_queries(dashboard, args.prometheus, args.from_ms, args.to_ms, args.expect_load)
            reports.append({"dashboard": path.name, **report})
            print(f"PASS native queries, exclusive partition, 100% and missing-telemetry guard: {path.name}")
    if reports:
        args.out.write_text(json.dumps(reports, indent=2) + "\n")


if __name__ == "__main__":
    main()
