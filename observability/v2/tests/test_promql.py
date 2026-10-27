"""promql.py finds the metric names, matchers and grouping labels of each construct the v2 expressions use."""
import unittest

import promql


class Names(unittest.TestCase):
    def test_constructs(self):
        cases = {
            'sum by (cluster) (rate(a_total{job="x", rcode="SERVFAIL"}[5m])) or on (cluster) (0 * sum(rate(a_total[5m])))':
                ["a_total"],
            'histogram_quantile(0.99, sum by (cluster, le) (rate(b_seconds_bucket{job="x"}[$__rate_interval])))':
                ["b_seconds_bucket"],
            'cmtc:expected_node:info unless on (cluster, node) group by (cluster, node) (up{job="ztunnel"})':
                ["cmtc:expected_node:info", "up"],
            'increase(x_total[5m]) unless (x_total unless x_total offset 5m) and on (cluster) (up offset 5m == 1)':
                ["up", "x_total"],
            'label_replace(vector(1), "cluster", "cmtc-a", "", "")': [],
            'max by (cluster) (time() - timestamp(up{job="cilium-native"})) > 60': ["up"],
            'sort_desc(count by (owner) (ALERTS{alertstate="firing"}))': ["ALERTS"],
            'topk(5, sum without (pod) (rate({__name__="a_total", job="x"}[1m])))': ["a_total"],
            'predict_linear(c{job="cadvisor"}[30m], 24 * 3600) > bool 1e3': ["c"],
            'sum(rate(d_total{cluster="${cluster}"}[$__range]))': ["d_total"],
        }
        for expr, want in cases.items():
            with self.subTest(expr=expr):
                self.assertEqual(promql.names(expr), want)

    def test_regex_name(self):
        self.assertEqual(promql.names('rate({__name__=~"s_svids(_total)?", job="spire-agent"}[5m])'),
                         ["re:s_svids(_total)?"])

    def test_label_values_that_look_like_names_are_not_names(self):
        self.assertEqual(promql.names('x{reason="Policy denied", origin="node"}'), ["x"])


class Matchers(unittest.TestCase):
    def test_matchers(self):
        self.assertEqual(promql.matchers('up{job=~"a|b", cluster="cmtc-a"} == 0 or rate(z{rcode!="NOERROR"}[5m])'),
                         [("up", "job", "=~", "a|b"), ("up", "cluster", "=", "cmtc-a"), ("z", "rcode", "!=", "NOERROR")])

    def test_regex_name_selector(self):
        self.assertEqual(promql.matchers('{__name__=~"s(_total)?", job="x"}'),
                         [(None, "__name__", "=~", "s(_total)?"), (None, "job", "=", "x")])

    def test_grouping_labels(self):
        self.assertEqual(promql.grouping_labels('sum by (cluster, node) (x) / on (cluster) group_left (owner) y'),
                         {"cluster", "node", "owner"})
        self.assertEqual(promql.grouping_labels('label_replace(x, "by", "$1", "on", "(.*)")'), set())


if __name__ == "__main__":
    unittest.main()
