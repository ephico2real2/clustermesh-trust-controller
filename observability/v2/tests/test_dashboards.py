"""The Grafana dashboards follow the /dashboard standard and the contract: words on every panel, Tableau 10 colours
fixed per cluster, the query type each panel kind needs, metrics the contract defines, and a title marker that says
what each panel still waits for (diagram-kit skill/dashboard/SKILL.md; model.py, the status classes)."""
import json
import re
import unittest

import model
import promql

# Tableau 10 (SKILL.md, "Identity"): the six colours in use and the four free ones.
TABLEAU = {"#4e79a7", "#e15759", "#edc948", "#b07aa1", "#59a14f", "#f28e2b",
           "#76b7b2", "#ff9da7", "#9c755f", "#bab0ac"}
CLUSTER_COLOUR = {"cmtc-a": "#4e79a7", "cmtc-b": "#e15759"}
INSTANT = {"stat", "table", "bargauge"}
RANGE = {"timeseries", "status-history"}
PREFIX = {"proposed": "Proposed: needs ", "planned": "Planned, a proposed source change: needs "}


def colours(node):
    """Every colour a panel sets: fixed colours, threshold steps, value mappings."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("fixedColor", "color") and isinstance(value, str):
                yield value
            else:
                yield from colours(value)
    elif isinstance(node, list):
        for value in node:
            yield from colours(value)


def drawing_panels():
    for name, dashboard in model.dashboards().items():
        for section, panel in model.panels(dashboard):
            if panel["type"] != "row":
                yield name, section, panel


class Dashboards(unittest.TestCase):
    def test_identity(self):
        uids = set()
        for name, dashboard in model.dashboards().items():
            with self.subTest(dashboard=name):
                self.assertRegex(dashboard["uid"], r"^cmtc-v2-[a-z-]+$")
                self.assertGreaterEqual(len(dashboard.get("description", "")), 40)
                variables = {v["name"]: v for v in dashboard["templating"]["list"]}
                self.assertEqual(variables.get("DS_PROMETHEUS", {}).get("type"), "datasource")
                uids.add(dashboard["uid"])
        self.assertEqual(len(uids), len(model.dashboards()))

    def test_every_panel_has_words(self):
        for name, section, panel in drawing_panels():
            with self.subTest(dashboard=name, panel=panel.get("title")):
                # A text panel needs a title too: percli names an untitled panel "empty" in the Perses form.
                self.assertTrue(panel.get("title"))
                self.assertIsNotNone(section, "every panel sits under a row that names its question")
                if panel["type"] == "text":
                    self.assertGreaterEqual(len(panel["options"]["content"]), 40)
                else:
                    self.assertGreaterEqual(len(panel.get("description", "")), 40)

    def test_one_data_source(self):
        for name, section, panel in drawing_panels():
            for target in panel.get("targets", []):
                with self.subTest(dashboard=name, panel=panel["title"], refId=target["refId"]):
                    self.assertEqual(target["datasource"]["uid"], "${DS_PROMETHEUS}")

    def test_colours_are_tableau(self):
        for name, section, panel in drawing_panels():
            for colour in colours(panel.get("fieldConfig", {})):
                with self.subTest(dashboard=name, panel=panel["title"], colour=colour):
                    self.assertIn(colour.lower(), TABLEAU)

    def test_each_cluster_keeps_its_colour(self):
        for name, section, panel in drawing_panels():
            exprs = {t["refId"]: t["expr"] for t in panel.get("targets", [])}
            for override in panel.get("fieldConfig", {}).get("overrides", []):
                if override["matcher"]["id"] != "byFrameRefID":
                    continue
                expr = exprs.get(override["matcher"]["options"], "")
                clusters = set(re.findall(r'cluster="(cmtc-[ab])"', expr))
                for prop in override["properties"]:
                    if prop["id"] == "color" and "fixedColor" in prop["value"] and len(clusters) == 1:
                        with self.subTest(dashboard=name, panel=panel["title"], refId=override["matcher"]["options"]):
                            self.assertEqual(prop["value"]["fixedColor"], CLUSTER_COLOUR[clusters.pop()])

    def test_query_type_follows_the_panel(self):
        for name, section, panel in drawing_panels():
            for target in panel.get("targets", []):
                with self.subTest(dashboard=name, panel=panel["title"], refId=target["refId"]):
                    if panel["type"] in INSTANT:
                        self.assertTrue(target.get("instant"), "a stat, table or bar gauge reads one instant")
                        self.assertFalse(target.get("range"))
                    if panel["type"] in RANGE:
                        self.assertTrue(target.get("range"), "a time series draws a range")
                        self.assertFalse(target.get("instant"))

    def test_legends_below_and_tables_without_time(self):
        for name, section, panel in drawing_panels():
            with self.subTest(dashboard=name, panel=panel["title"]):
                if panel["type"] in RANGE:
                    self.assertEqual(panel["options"]["legend"]["placement"], "bottom")
                if panel["type"] == "table":
                    organize = [t for t in panel.get("transformations", []) if t["id"] == "organize"]
                    self.assertTrue(organize and organize[0]["options"]["excludeByName"].get("Time"))

    def test_no_data_is_never_zero(self):
        """A stat, bar gauge or table says why it is empty: a missing exporter is unavailable, never zero."""
        for name, section, panel in drawing_panels():
            if panel["type"] in INSTANT:
                with self.subTest(dashboard=name, panel=panel["title"]):
                    no_value = panel["fieldConfig"]["defaults"].get("noValue", "")
                    self.assertTrue(no_value.strip() and not no_value.strip().startswith("0"), no_value)

    def test_queries_select_the_contract(self):
        for name, section, panel in drawing_panels():
            for target in panel.get("targets", []):
                expr = target["expr"]
                with self.subTest(dashboard=name, panel=panel["title"], refId=target["refId"]):
                    self.assertNotIn("vector(0)", expr.replace(" ", ""))
                    self.assertEqual(model.expr_class(expr)[1], [])
                    allowed = model.allowed_labels(expr)
                    if allowed is not None:
                        self.assertEqual(sorted(promql.grouping_labels(expr) - allowed - {"le"}), [])

    def test_markers_say_what_each_panel_waits_for(self):
        for name, section, panel in drawing_panels():
            if panel["type"] == "text":
                continue
            computed = max((model.expr_class(t["expr"])[0] for t in panel.get("targets", [])),
                           key=model.RANK.get, default="current")
            marked = model.marker_class(panel["title"])
            with self.subTest(dashboard=name, panel=panel["title"]):
                self.assertEqual(marked, computed)
                if marked in PREFIX:
                    self.assertTrue(panel["description"].startswith(PREFIX[marked]), panel["description"][:80])

    def test_row_markers(self):
        """A row is current when one of its panels is; otherwise it carries the marker of its most current panel."""
        for name, dashboard in model.dashboards().items():
            rows = {}
            for section, panel in model.panels(dashboard):
                if panel["type"] == "row":
                    rows[section] = []
                elif panel["type"] != "text":
                    rows[section].append(model.marker_class(panel["title"]))
            for title, classes in rows.items():
                with self.subTest(dashboard=name, row=title):
                    self.assertTrue(classes, "a row with no drawing panel")
                    self.assertEqual(model.marker_class(title), min(classes, key=model.RANK.get))


class PersesForm(unittest.TestCase):
    """dashboards/perses/ is generated from the Grafana JSON by perses-dashboard (docs/COLLECTION.md), never edited:
    the same panels, sections and queries in the same order, each query on the chart's PersesDatasource. A Grafana
    edit without a new generation fails here."""
    DATASOURCE = {"kind": "PrometheusDatasource", "name": "cmtc-thanos"}

    @staticmethod
    def place(key):
        return tuple(int(part) for part in key.split("_"))

    def test_generated_from_the_grafana_json(self):
        perses = {p.name for p in (model.V2 / "dashboards" / "perses").glob("*.json")}
        self.assertEqual(perses, set(model.dashboards()))
        for name, dashboard in model.dashboards().items():
            spec = json.loads((model.V2 / "dashboards" / "perses" / name).read_text())
            grafana = [p for _, p in model.panels(dashboard) if p["type"] != "row"]
            converted = [spec["panels"][k] for k in sorted(spec["panels"], key=self.place)]
            with self.subTest(dashboard=name):
                self.assertEqual([p["spec"]["display"]["name"] for p in converted], [p["title"] for p in grafana])
                self.assertEqual([l["spec"]["display"]["title"] for l in spec["layouts"]],
                                 [p["title"] for _, p in model.panels(dashboard) if p["type"] == "row"])
                for source, panel in zip(grafana, converted):
                    queries = panel["spec"].get("queries", [])
                    self.assertEqual([q["spec"]["plugin"]["spec"]["query"] for q in queries],
                                     [t["expr"] for t in source.get("targets", [])], source["title"])
                    for query in queries:
                        self.assertEqual(query["spec"]["plugin"]["spec"]["datasource"], self.DATASOURCE)


if __name__ == "__main__":
    unittest.main()
