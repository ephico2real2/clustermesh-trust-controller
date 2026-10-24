#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
# distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""List every metric a workload emits, with what kind of data each is, before any panel is chosen.

    metrics-inventory --prometheus <url> --match '{namespace="app",job="app"}' > inventory.md      (installed)
    metrics-inventory --text <saved /metrics page> > inventory.md

A dashboard shows the few metrics that answer a reader's question, not the hundreds a workload emits. The
choice needs the whole list first: this writes it as Markdown, one row per metric name, with
  - its declared type (counter, gauge, histogram, summary), from the endpoint's own TYPE lines;
  - how many series it has now, and the labels that tell them apart, with how many values each takes;
  - how many of those series changed in the window (--window, default 1h): a metric that never moves is not a line;
  - how many distinct values the series hold now: one value on every series is a fact to state, not to chart;
  - the kind of data that makes it, and so the panel it can be (skill/dashboard/SKILL.md, section 2).

With --prometheus it asks a Prometheus-compatible API (Prometheus, Thanos Querier). A bearer token is read from the
environment variable named by --token-env (default PROMETHEUS_TOKEN), never from the command line; --ca-file names
the CA that signed the API's certificate. With --text it reads a saved exposition page: names, types and series
only. It reads; it changes nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

# Labels Prometheus or the platform puts on every series of a target: they say where it came from, not what it is.
TARGET_LABELS = {"__name__", "job", "instance", "namespace", "pod", "container", "service", "endpoint", "node",
                 "prometheus", "prometheus_replica", "cluster"}
# A sample name ending in one of these belongs to the family named without it, when that family is declared.
SUFFIXES = ("_bucket", "_count", "_sum", "_total", "_created")
# A label with more values than this on one metric is worth a look before it is drawn or kept.
MANY_VALUES = 50

Get = Callable[[str, dict[str, str]], dict]


def http_get(base: str, token: str | None, ca_file: str | None) -> Get:
    """A getter for one Prometheus-compatible API: path and parameters in, the decoded `data` out."""
    context = ssl.create_default_context(cafile=ca_file) if base.startswith("https") else None

    def get(path: str, params: dict[str, str]) -> dict:
        request = urllib.request.Request(f"{base.rstrip('/')}{path}?{urllib.parse.urlencode(params)}")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                body = json.load(response)
        except urllib.error.HTTPError as error:
            # The API says why in the body ("vector cannot contain metrics with the same labelset"); the status alone does not.
            raise RuntimeError(f"{path} {params} answered {error.code}: {error.read().decode(errors='replace')[:300]}") from error
        if body.get("status") != "success":
            raise RuntimeError(f"{path} answered {body.get('status')}: {body.get('error', '')}")
        return body["data"]

    return get


def family_of(name: str, declared: dict[str, str]) -> str:
    """The declared family a sample name belongs to: `x_bucket`, `x_sum` and `x_count` are the histogram `x`."""
    if name in declared:
        return name
    for suffix in SUFFIXES:
        if name.endswith(suffix) and name[: -len(suffix)] in declared:
            return name[: -len(suffix)]
    return name


def kind_of(name: str, declared_type: str, series: int, changing: int | None, distinct: int | None) -> str:
    """The kind of data a metric is, in the words of the standard's chart table."""
    if declared_type == "histogram":
        return "a distribution: a percentile from its buckets, across instances"
    if declared_type == "summary":
        return "a summary: an average from _sum over _count; its own quantiles do not combine across instances"
    if declared_type == "counter" or name.endswith("_total"):
        return "a counter: its rate over time; never the raw number"
    if name.endswith("_info"):
        return "facts as labels: a table"
    if changing is None or distinct is None:
        return "a level: a line if it moves, a number or a table if it does not"
    if changing == 0 and distinct <= 1:
        return "constant, the same on every series: a number or a table row, not a line"
    if changing == 0:
        return "constant, differing by series: a table or sorted bars, not a line"
    return "a level that moves: a line over time; a number for now"


def _by_name(vector: list[dict], label: str = "__name__") -> dict[str, int]:
    return {sample["metric"][label]: int(float(sample["value"][1])) for sample in vector}


def inventory_from_api(get: Get, match: str, window: str, labels: bool = True) -> list[dict]:
    """One row per metric name the selector matches, from a Prometheus-compatible API."""
    series = _by_name(get("/api/v1/query", {"query": f"count by (__name__) ({match})"})["result"])
    # changes() drops the metric name, and two metrics with the same labels then collide ("vector cannot contain
    # metrics with the same labelset"): the name is copied to a label first, which needs a subquery to range over.
    named = f'label_replace({match}, "metric", "$1", "__name__", "(.+)")'
    changing = _by_name(get("/api/v1/query", {"query": f"count by (metric) (changes({named}[{window}:1m]) > 0)"})["result"],
                        "metric")
    distinct = _by_name(get("/api/v1/query",
                            {"query": f'count by (__name__) (count_values by (__name__) ("value", {match}))'})["result"])
    metadata = get("/api/v1/metadata", {})
    declared = {family: entries[0].get("type", "unknown") for family, entries in metadata.items() if entries}
    helps = {family: entries[0].get("help", "") for family, entries in metadata.items() if entries}
    values: dict[str, dict[str, set[str]]] = {}
    if labels:
        for one in get("/api/v1/series", {"match[]": match}):
            per_label = values.setdefault(one["__name__"], {})
            for label, value in one.items():
                if label not in TARGET_LABELS:
                    per_label.setdefault(label, set()).add(value)
    rows = []
    for name in sorted(series):
        family = family_of(name, declared)
        kind = declared.get(family, "unknown")
        rows.append({"name": name, "family": family, "type": kind, "series": series[name],
                     "changing": changing.get(name, 0), "distinct": distinct.get(name, 0),
                     "labels": {label: len(found) for label, found in sorted(values.get(name, {}).items())},
                     "help": helps.get(family, ""),
                     "kind": kind_of(name, kind, series[name], changing.get(name, 0), distinct.get(name, 0))})
    return rows


def inventory_from_text(text: str) -> list[dict]:
    """One row per metric name of a saved exposition page: names, declared types and series only."""
    declared: dict[str, str] = {}
    helps: dict[str, str] = {}
    series: dict[str, int] = {}
    values: dict[str, dict[str, set[str]]] = {}
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, family, kind = line.split(None, 3)
            declared[family] = kind.strip()
        elif line.startswith("# HELP "):
            parts = line.split(None, 3)
            helps[parts[2]] = parts[3] if len(parts) > 3 else ""
        elif line and not line.startswith("#"):
            found = re.match(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s", line)
            if not found:
                continue
            name = found.group(1)
            series[name] = series.get(name, 0) + 1
            for label, value in re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"', found.group(2) or ""):
                if label not in TARGET_LABELS:
                    values.setdefault(name, {}).setdefault(label, set()).add(value)
    rows = []
    for name in sorted(series):
        family = family_of(name, declared)
        kind = declared.get(family, "unknown")
        rows.append({"name": name, "family": family, "type": kind, "series": series[name], "changing": None,
                     "distinct": None, "labels": {label: len(found) for label, found in sorted(values.get(name, {}).items())},
                     "help": helps.get(family, ""), "kind": kind_of(name, kind, series[name], None, None)})
    return rows


def _group(name: str) -> str:
    """The first two words of a name: `mongot_index_stats_indexSizeBytes` is in `mongot_index`."""
    return "_".join(name.split("_")[:2])


def render(rows: list[dict], source: str, window: str | None) -> str:
    """The inventory as Markdown: totals, then one table per group of names."""
    families = {row["family"]: row["type"] for row in rows}
    by_type: dict[str, int] = {}
    for kind in families.values():
        by_type[kind] = by_type.get(kind, 0) + 1
    out = ["# Metrics inventory", "", f"Source: {source}", "",
           f"{len(rows)} metric names in {len(families)} families, {sum(row['series'] for row in rows)} series.", "",
           "| Declared type | Families |", "| --- | --- |",
           *(f"| {kind} | {count} |" for kind, count in sorted(by_type.items())), ""]
    measured = window is not None
    if measured:
        still = sum(row["changing"] == 0 for row in rows)
        out += [f"{still} of the {len(rows)} names did not change on any series in the last {window}.", ""]
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(_group(row["name"]), []).append(row)
    for group, members in sorted(groups.items()):
        out += [f"## {group} ({len(members)})", ""]
        head = ["Metric", "Type", "Series"] + (["Changed", "Distinct values"] if measured else []) + ["Labels", "Kind of data"]
        out += ["| " + " | ".join(head) + " |", "| " + " | ".join("---" for _ in head) + " |"]
        for row in members:
            labels = ", ".join(f"{label} ({count}{' !' if count > MANY_VALUES else ''})" for label, count in row["labels"].items())
            cells = [f"`{row['name']}`", row["type"], str(row["series"])]
            if measured:
                cells += [str(row["changing"]), str(row["distinct"])]
            out.append("| " + " | ".join([*cells, labels, row["kind"]]) + " |")
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="metrics-inventory", description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--prometheus", help="the base address of a Prometheus-compatible API")
    source.add_argument("--text", type=pathlib.Path, help="a saved /metrics page")
    parser.add_argument("--match", help='the selector of the workload, for example \'{namespace="app",job="app"}\'')
    parser.add_argument("--window", default="1h", help="how far back a series is checked for change (default 1h)")
    parser.add_argument("--token-env", default="PROMETHEUS_TOKEN", help="the environment variable holding a bearer token")
    parser.add_argument("--ca-file", help="the CA that signed the API's certificate")
    parser.add_argument("--no-labels", action="store_true", help="skip the label columns (one request less, on a large selector)")
    args = parser.parse_args(argv)
    try:
        if args.text:
            print(render(inventory_from_text(args.text.read_text()), f"the page `{args.text.name}`", None))
            return 0
        if not args.match:
            parser.error("--prometheus needs --match: an inventory of every metric of a cluster is not a workload's")
        get = http_get(args.prometheus, os.environ.get(args.token_env), args.ca_file)
        rows = inventory_from_api(get, args.match, args.window, labels=not args.no_labels)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"metrics-inventory: {error}", file=sys.stderr)
        return 1
    if not rows:
        print(f"metrics-inventory: the selector {args.match} matches no series", file=sys.stderr)
        return 1
    print(render(rows, f"`{args.match}`", args.window))
    return 0


if __name__ == "__main__":
    sys.exit(main())

