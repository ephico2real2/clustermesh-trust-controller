"""What the tests read: the contract, the rule files and the dashboards of observability/v2, and the rules that
join them.

Status classes, the words every panel title carries (tests/test_dashboards.py) and every rule file obeys:
  current   emitted by the deployed source, and scraped by the labs today;
  proposed  emitted by the deployed source, collected once the v2 deploy/ runs (" · proposed");
  planned   needs a source change first, a proposed source change (" · planned").
"""
import collections
import functools
import json
import pathlib
import re

import helmyaml
import promql

V2 = pathlib.Path(__file__).resolve().parent.parent
CONTRACT = V2 / "metrics" / "contract.json"
SCHEMA = V2 / "metrics" / "contract.schema.json"
RULES = V2 / "rules"
DASHBOARDS = V2 / "dashboards" / "grafana"
RANK = {"current": 0, "proposed": 1, "planned": 2}
MARKERS = {"proposed": " · proposed", "planned": " · planned"}
# Labels Prometheus adds to ALERTS; the rest come from the alert's own expression and labels.
ALERT_LABELS = {"alertname", "alertstate", "severity", "owner"}


@functools.cache
def contract():
    return json.loads(CONTRACT.read_text())


@functools.cache
def entries():
    """Contract entries by metric name (a name two components emit has two entries)."""
    out = collections.defaultdict(list)
    for metric in contract()["metrics"]:
        out[metric["name"]].append(metric)
    return dict(out)


def job_of(component):
    return contract()["components"][component]["job"]


@functools.cache
def jobs():
    """{job: status class of its up series}: current when the labs scrape the job today; planned when every metric
    of the job needs a source change first (the job is off until then); proposed otherwise."""
    out = {}
    for name, component in contract()["components"].items():
        metrics = [m for m in contract()["metrics"] if m["component"] == name]
        if component["scraped"]:
            found = "current"
        elif metrics and all(entry_class(m) == "planned" for m in metrics):
            found = "planned"
        else:
            found = "proposed"
        job = component["job"]
        out[job] = min(out.get(job, found), found, key=RANK.get)
    return out


def entry_class(metric, label_values=()):
    """The status class of one contract entry; label_values are the (label, value) pairs a query selects it with."""
    if metric["status"] != "emitted" or metric["source"].get("patch"):
        return "planned"
    for label in metric["labels"]:
        for name, value in label_values:
            if name == label["name"] and value in label.get("proposed_values", ()):
                return "planned"
    return "current" if metric["collection"] == "scraped" else "proposed"


def family(name):
    """The contract name of a series name: a histogram's _bucket, _sum and _count belong to the histogram."""
    if name in entries():
        return name
    for suffix in ("_bucket", "_sum", "_count"):
        base = name[: -len(suffix)]
        if name.endswith(suffix) and base in entries() and entries()[base][0]["type"] in ("histogram", "summary"):
            return base
    return None


def resolve(name):
    """The contract names a selected name stands for: one name, or every name a "re:" pattern matches."""
    if name.startswith("re:"):
        pattern = re.compile(name[3:])
        return sorted(n for n in entries() if pattern.fullmatch(n))
    found = family(name)
    return [found] if found else []


def job_matches(job_matchers, job):
    for op, value in job_matchers:
        if op == "=" and job != value or op == "!=" and job == value:
            return False
        if op == "=~" and not re.fullmatch(value, job) or op == "!~" and re.fullmatch(value, job):
            return False
    return True


def rule_files(proposed=None):
    """The rule files: rules/*.rules.yaml (proposed False), rules/proposed/ (True) or both (None)."""
    current = sorted(RULES.glob("*.rules.yaml"))
    later = sorted((RULES / "proposed").glob("*.rules.yaml"))
    return {None: current + later, False: current, True: later}[proposed]


@functools.cache
def parsed_rules():
    """{path: parsed rule file} for every rule file."""
    files = rule_files()
    return dict(zip(files, helmyaml.load([f.read_text() for f in files])))


def rules():
    """(path, group name, rule) for every rule."""
    return [(path, group["name"], rule) for path, doc in parsed_rules().items() for group in doc["groups"]
            for rule in group["rules"]]


@functools.cache
def records():
    """{recorded series: [(path, expr, the labels the rule adds)]}."""
    out = collections.defaultdict(list)
    for path, _, rule in rules():
        if "record" in rule:
            out[rule["record"]].append((path, rule["expr"], tuple(rule.get("labels", {}))))
    return dict(out)


def occurrences(expr):
    """(name, job matchers, equality matchers) for every selector of expr; a {__name__=~"x"} selector is named
    "re:x"."""
    out = []
    for name, found in promql.selectors(expr):
        for label, op, value in found:
            if label == "__name__":
                name = value if op == "=" else f"re:{value}"
        if name is None:
            continue
        job_matchers = [(op, value) for label, op, value in found if label == "job"]
        label_values = [(label, value) for label, op, value in found if op == "=" and label not in ("job", "__name__")]
        out.append((name, job_matchers, label_values))
    return out


def expr_class(expr, _seen=()):
    """(status class, [what the contract does not know]) of an expression: the highest class it selects."""
    worst, unknown = "current", []
    for name, job_matchers, label_values in occurrences(expr):
        if name in records():
            if name in _seen:
                continue
            for path, record_expr, _ in records()[name]:
                found, missing = expr_class(record_expr, _seen + (name,))
                if path.parent.name == "proposed":
                    found = "planned"
                worst, unknown = max(worst, found, key=RANK.get), unknown + missing
            continue
        if name == "up":
            # up of several jobs shows what is scraped today: its class is that of the most current job.
            matched = [job for job in jobs() if job_matches(job_matchers, job)]
            if not matched:
                unknown.append(f"up of no job of the contract {job_matchers}")
                continue
            worst = max(worst, min((jobs()[job] for job in matched), key=RANK.get), key=RANK.get)
            continue
        names = resolve(name)
        if not names:
            unknown.append(name)
            continue
        candidates = [m for n in names for m in entries()[n] if job_matches(job_matchers, job_of(m["component"]))]
        if not candidates:
            unknown.append(f"{name} of no component of job {job_matchers}")
            continue
        found = min((entry_class(m, label_values) for m in candidates), key=RANK.get)
        worst = max(worst, found, key=RANK.get)
    return worst, unknown


def hub_labels(metric):
    """The labels a series of this entry carries at the hub: the target labels of its job, and its own labels,
    renamed exported_<label> where a target label has the same name (honor_labels is false)."""
    targets = set(contract()["components"][metric["component"]]["target_labels"])
    own = {label["name"] for label in metric["labels"]}
    return targets | {f"exported_{l}" if l in targets else l for l in own}


def _arguments(text, start):
    """The top-level arguments of the call whose "(" is at text[start]."""
    depth, current, out = 0, [], []
    for ch in text[start:]:
        if ch == "(":
            depth += 1
            if depth == 1:
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                out.append("".join(current))
                return out
        elif ch == "," and depth == 1:
            out.append("".join(current))
            current = []
            continue
        current.append(ch)
    return out


def created_labels(expr):
    """Labels an expression creates: label_replace's destination and count_values' label."""
    out = set()
    for match in re.finditer(r'\b(label_replace|count_values)\s*\(', expr):
        args = _arguments(expr, match.end() - 1)
        index = 1 if match.group(1) == "label_replace" else 0
        if len(args) > index:
            value = args[index].strip()
            if value.startswith('"') and value.endswith('"'):
                out.add(value[1:-1])
    return out


def allowed_labels(expr, _seen=()):
    """Every label a grouping clause of expr may name: the hub labels of what it selects, the labels of the
    recorded series it reads, and the labels it creates. None when it reads ALERTS (any label)."""
    out = set(created_labels(expr))
    for name, job_matchers, _ in occurrences(expr):
        if name == "ALERTS":
            return None
        if name in records():
            if name in _seen:
                continue
            for _, record_expr, added in records()[name]:
                inner = allowed_labels(record_expr, _seen + (name,))
                if inner is None:
                    return None
                out |= promql.grouping_labels(record_expr) | inner | set(added)
            continue
        if name == "up":
            for data in contract()["components"].values():
                if job_matches(job_matchers, data["job"]):
                    out |= set(data["target_labels"])
            continue
        for n in resolve(name):
            for metric in entries()[n]:
                if job_matches(job_matchers, job_of(metric["component"])):
                    out |= hub_labels(metric)
    return out


@functools.cache
def dashboards():
    """{file name: dashboard} of dashboards/grafana/."""
    return {p.name: json.loads(p.read_text()) for p in sorted(DASHBOARDS.glob("*.json"))}


def panels(dashboard):
    """(section, panel) for every panel, rows included; section is the row title above the panel."""
    out, section = [], None
    for panel in dashboard["panels"]:
        if panel["type"] == "row":
            section = panel["title"]
            out.append((section, panel))
            for inner in panel.get("panels", []):
                out.append((section, inner))
        else:
            out.append((section, panel))
    return out


def marker_class(title):
    for status, marker in MARKERS.items():
        if title.endswith(marker):
            return status
    return "current"


def unmarked(title):
    for marker in MARKERS.values():
        if title.endswith(marker):
            return title[: -len(marker)]
    return title
