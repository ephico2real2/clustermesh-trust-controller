"""The rule files of rules/ select only what the contract defines, carry an owner and a runbook on every alert,
and are exercised by the promtool tests of rules/tests/, which run here when promtool is available."""
import collections
import os
import re
import shutil
import subprocess
import unittest

import helmyaml
import model
import promql

SEVERITIES = {"info", "warning", "critical"}
DURATION = re.compile(r"^([0-9]+(ms|s|m|h|d|w|y))+$")


def literal_alternatives(value):
    """The literal values a regex matcher such as "A|B" selects, or None when it is not a plain alternation."""
    parts = value.split("|")
    return parts if all(re.fullmatch(r"[A-Za-z0-9_ .:/-]+", p) for p in parts) else None


class Rules(unittest.TestCase):
    def test_group_names_are_unique(self):
        # On OpenShift every group goes into one PrometheusRule, whose groups must have distinct names.
        names = collections.Counter(group for _, group, _ in {(p, g, None) for p, g, _ in model.rules()})
        self.assertEqual([n for n, count in names.items() if count > 1], [])

    def test_recorded_series_are_unique(self):
        # Several rules may record one name, each with its own labels (cmtc:dependency_available:bool).
        records = collections.Counter((r["record"], tuple(sorted(r.get("labels", {}).items())))
                                      for _, _, r in model.rules() if "record" in r)
        self.assertEqual([n for n, count in records.items() if count > 1], [])

    def test_alerts_have_severity_owner_summary_and_runbook(self):
        for path, _, rule in model.rules():
            if "alert" not in rule:
                continue
            with self.subTest(file=path.name, alert=rule["alert"]):
                self.assertIn(rule.get("labels", {}).get("severity"), SEVERITIES)
                self.assertTrue(rule["labels"].get("owner") or "owner" in model.created_labels(rule["expr"]),
                                "the component that owns the alert: a label, or set by the expression")
                self.assertGreaterEqual(len(rule.get("annotations", {}).get("summary", "")), 20)
                self.assertGreaterEqual(len(rule["annotations"].get("runbook", "")), 40)
                if "for" in rule:
                    self.assertRegex(rule["for"], DURATION)

    def test_no_fabricated_zero(self):
        for path, _, rule in model.rules():
            with self.subTest(file=path.name, rule=rule.get("record") or rule.get("alert")):
                self.assertNotIn("vector(0)", rule["expr"].replace(" ", ""),
                                 "a missing exporter is unavailable, never a healthy zero")

    def test_names_are_in_the_contract(self):
        for path, _, rule in model.rules():
            found, unknown = model.expr_class(rule["expr"])
            with self.subTest(file=path.name, rule=rule.get("record") or rule.get("alert")):
                self.assertEqual(unknown, [])

    def test_current_files_select_nothing_planned(self):
        for path, _, rule in model.rules():
            found, _ = model.expr_class(rule["expr"])
            with self.subTest(file=path.relative_to(model.RULES).as_posix(), rule=rule.get("record") or rule.get("alert")):
                if path.parent.name == "proposed":
                    self.assertEqual(found, "planned", "a rule of proposed/ waits for a source change; else it "
                                                       "belongs in rules/")
                else:
                    self.assertNotEqual(found, "planned", "a rule on a metric that needs a source change belongs "
                                                          "in rules/proposed/")

    def test_label_values_are_in_the_contract(self):
        """A value a matcher names is one the contract lists, or one a source change adds (proposed_values with its
        patch, planned_values without one)."""
        for path, _, rule in model.rules():
            for name, job_matchers, _ in model.occurrences(rule["expr"]):
                metrics = [m for n in model.resolve(name) for m in model.entries()[n]
                           if model.job_matches(job_matchers, model.job_of(m["component"]))]
                selected = [(label, op, value) for n, label, op, value in promql.matchers(rule["expr"])
                            if n == name and op in ("=", "=~") and label not in ("job", "__name__")]
                for metric in metrics:
                    labels = {l["name"]: l for l in metric["labels"]}
                    for label, op, value in selected:
                        if label not in labels or "values" not in labels[label]:
                            continue
                        values = literal_alternatives(value) if op == "=~" else [value]
                        allowed = (set(labels[label]["values"]) | set(labels[label].get("proposed_values", []))
                                   | set(labels[label].get("planned_values", [])))
                        for v in values or []:
                            with self.subTest(file=path.name, metric=metric["name"], label=label, value=v):
                                self.assertIn(v, allowed)

    def test_grouping_labels_exist(self):
        for path, _, rule in model.rules():
            allowed = model.allowed_labels(rule["expr"])
            if allowed is None:
                continue
            with self.subTest(file=path.name, rule=rule.get("record") or rule.get("alert")):
                self.assertEqual(sorted(promql.grouping_labels(rule["expr"]) - allowed - {"le"}), [])


class PromtoolTests(unittest.TestCase):
    """Every rule file is loaded by a test file, and every alert and recorded series of it is tested there."""

    @classmethod
    def setUpClass(cls):
        cls.tests = sorted((model.RULES / "tests").glob("*.test.yaml"))
        cls.docs = dict(zip(cls.tests, helmyaml.load([t.read_text() for t in cls.tests])))

    def test_every_rule_is_tested(self):
        loaded = collections.defaultdict(list)
        for test, doc in self.docs.items():
            for rule_file in doc["rule_files"]:
                loaded[(test.parent / rule_file).resolve()].append(doc)
        for path, doc in model.parsed_rules().items():
            docs = loaded.get(path.resolve(), [])
            with self.subTest(file=path.name):
                self.assertTrue(docs, "no test file loads it")
            alerts = {a["alertname"] for d in docs for t in d["tests"] for a in t.get("alert_rule_test", [])}
            exprs = [e["expr"] for d in docs for t in d["tests"] for e in t.get("promql_expr_test", [])]
            for group in doc["groups"]:
                for rule in group["rules"]:
                    with self.subTest(file=path.name, rule=rule.get("record") or rule.get("alert")):
                        if "alert" in rule:
                            self.assertIn(rule["alert"], alerts)
                        else:
                            self.assertTrue(any(rule["record"] in e for e in exprs), "no promql_expr_test reads it")

    def test_promtool(self):
        promtool = os.environ.get("PROMTOOL") or shutil.which("promtool")
        if not promtool:
            self.skipTest("promtool not found: set PROMTOOL, or run rules/run-promtool.sh with podman or docker")
        done = subprocess.run(["bash", str(model.RULES / "run-promtool.sh")], env={**os.environ, "PROMTOOL": promtool},
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout[-3000:] + done.stderr[-3000:])


if __name__ == "__main__":
    unittest.main()
