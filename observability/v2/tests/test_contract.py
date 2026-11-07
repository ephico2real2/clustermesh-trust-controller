"""metrics/contract.json is valid, consistent with itself, and true to its fixture pages."""
import collections
import json
import re
import unittest

import model
import schema

SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+\S+(?:\s+\S+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def fixture_series(path):
    """{series name: [labels of each sample]} of a fixture page."""
    out = collections.defaultdict(list)
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = SAMPLE.match(line)
        if not match:
            raise AssertionError(f"{path.name}: not a sample line: {line!r}")
        out[match.group(1)].append(dict(LABEL.findall(match.group(2) or "")))
    return out


class Contract(unittest.TestCase):
    def setUp(self):
        self.contract = model.contract()
        self.metrics = self.contract["metrics"]

    def test_schema(self):
        errors = schema.validate(self.contract, json.loads(model.SCHEMA.read_text()))
        self.assertEqual(errors, [], "\n".join(errors[:20]))

    def test_one_entry_per_name_and_component(self):
        keys = collections.Counter((m["name"], m["component"]) for m in self.metrics)
        self.assertEqual([k for k, n in keys.items() if n > 1], [])

    def test_references_resolve(self):
        for m in self.metrics:
            with self.subTest(metric=m["name"]):
                self.assertIn(m["component"], self.contract["components"])
                self.assertIn(m["stage"], self.contract["stages"])
                for question in m["questions"]:
                    self.assertIn(question, self.contract["questions"])

    def test_every_question_and_stage_is_used(self):
        asked = {q for m in self.metrics for q in m["questions"]}
        self.assertEqual(sorted(set(self.contract["questions"]) - asked), [])
        staged = {m["stage"] for m in self.metrics}
        self.assertEqual(sorted(set(self.contract["stages"]) - staged), [])

    def test_every_label_is_bounded(self):
        for m in self.metrics:
            for label in m["labels"]:
                with self.subTest(metric=m["name"], label=label["name"]):
                    self.assertTrue(label.get("values") or label.get("bound"),
                                    "a label needs its values or a bound on them")

    def test_status_matches_source(self):
        for m in self.metrics:
            source = m["source"]
            with self.subTest(metric=m["name"], component=m["component"]):
                if m["status"] == "emitted":
                    self.assertIn("line", source, "emitted: the line that defines it at the deployed ref")
                if m["status"] == "needs-source-change":
                    self.assertTrue(source.get("patch") or source.get("change"),
                                    "needs-source-change: the patch, or the branch that carries the change")
                    self.assertEqual(m["collection"], "not-deployed")
                if m["status"] == "planned":
                    self.assertNotIn("patch", source)
                    self.assertNotIn("line", source)
                    self.assertEqual(m["collection"], "not-deployed")
                if source.get("patch"):
                    self.assertTrue(m["status"] == "needs-source-change" or m["collection"] == "not-configured",
                                    "a patch either adds the metric or configures its exporter")

    def test_patches_exist(self):
        paths = {m["source"]["patch"] for m in self.metrics if m["source"].get("patch")}
        paths |= {label["proposed_by"] for m in self.metrics for label in m["labels"] if label.get("proposed_by")}
        for path in sorted(paths):
            with self.subTest(patch=path):
                self.assertTrue((model.V2 / path).is_file(), f"{path} is named in the contract")

    def test_component_scraped_flag_matches_its_metrics(self):
        # up and ALERTS are written by Prometheus itself, whether or not it scrapes its own page.
        for name, component in self.contract["components"].items():
            scraped = any(m["collection"] == "scraped" for m in self.metrics
                          if m["component"] == name and m["name"] not in ("up", "ALERTS"))
            with self.subTest(component=name):
                self.assertEqual(component["scraped"], scraped)

    def test_observed_series_match_the_fixture(self):
        for m in self.metrics:
            observed = m.get("observed")
            if not observed:
                continue
            path = model.V2 / observed["fixture"]
            with self.subTest(metric=m["name"], fixture=path.name):
                self.assertTrue(path.is_file())
                series = fixture_series(path)
                counted = m["name"] + "_count" if m["type"] == "histogram" else m["name"]
                self.assertEqual(len(series.get(counted, [])), observed["series"])
                if m["zero_initialized"]:
                    self.assertGreater(observed["series"], 0, "zero-initialized: its series exist before any event")

    def test_fixture_labels_are_in_the_contract(self):
        """Every label an exporter served for a metric is a label the contract lists, with one of its values, or
        one its job drops at ingestion (components.<name>.dropped_labels, the labeldrop of deploy/)."""
        for m in self.metrics:
            observed = m.get("observed")
            if not observed:
                continue
            series = fixture_series(model.V2 / observed["fixture"])
            names = [m["name"] + s for s in ("_bucket", "_sum", "_count")] if m["type"] == "histogram" else [m["name"]]
            declared = {label["name"]: label for label in m["labels"]}
            dropped = set(self.contract["components"][m["component"]].get("dropped_labels", []))
            for name in names:
                for labels in series.get(name, []):
                    for label, value in labels.items():
                        if label in dropped:
                            continue
                        with self.subTest(metric=m["name"], label=label):
                            self.assertIn(label, declared)
                            values = declared[label].get("values")
                            if values:
                                self.assertIn(value, values)


class Questions(unittest.TestCase):
    def rows(self):
        out = collections.defaultdict(set)
        for dashboard in model.dashboards().values():
            for _, panel in model.panels(dashboard):
                if panel["type"] == "row":
                    out[dashboard["uid"]].add(model.unmarked(panel["title"]))
        return out

    def test_every_section_is_a_dashboard_row(self):
        rows = self.rows()
        for question, data in model.contract()["questions"].items():
            for section in data["sections"]:
                with self.subTest(question=question, section=section["section"]):
                    self.assertIn(section["dashboard"], rows)
                    self.assertIn(section["section"], rows[section["dashboard"]])

    def test_every_dashboard_row_answers_a_question(self):
        answered = {(s["dashboard"], s["section"]) for q in model.contract()["questions"].values()
                    for s in q["sections"]}
        for uid, titles in self.rows().items():
            for title in sorted(titles):
                with self.subTest(dashboard=uid, row=title):
                    self.assertIn((uid, title), answered)


if __name__ == "__main__":
    unittest.main()
