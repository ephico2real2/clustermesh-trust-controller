"""Acceptance must reject incomplete collection and incorrect identity pairs."""
import copy
import unittest

import build
import validate


def row(labels, value):
    return {'metric': labels, 'value': [1, str(value)]}


class NativeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.domains = {'cmtc-a': 'alpha.example', 'cmtc-b': 'beta.example'}
        self.nodes = {'cmtc-a': ['a-control', 'a-worker'], 'cmtc-b': ['b-control', 'b-worker']}
        self.coverage = [row({'cluster': cluster, 'node': node}, 1)
                         for cluster, nodes in self.nodes.items() for node in nodes]
        self.lifecycle = [row(r['metric'].copy(), 0) for r in self.coverage]
        self.pairs = [row({'cluster': receiver,
                          'source_trust_domain': self.domains[sender],
                          'destination_trust_domain': self.domains[receiver]}, 10)
                      for receiver, sender in [('cmtc-a', 'cmtc-b'), ('cmtc-b', 'cmtc-a')]]
        pie = next(p for p in build.all_panels(build.security()) if p['type'] == 'piechart')
        self.parts = {target['legendFormat']: 0 for target in pie['targets']}
        self.parts.update({'mTLS · no failure flag': 20, 'Authenticated denied': 2,
                           'Unauthenticated blocked': 3})
        self.expressions = {validate.substitute(t['expr'], 'cmtc-a|cmtc-b'): t['legendFormat']
                            for t in pie['targets']}
        self.total = 25

    def query(self, expression):
        if expression.startswith('up{'):
            result = self.coverage
        elif expression.startswith('workload_manager_'):
            result = self.lifecycle
        elif expression.startswith('sum by(cluster,source_trust_domain,destination_trust_domain)'):
            self.assertIn('"source_principal"', expression)
            self.assertIn('"destination_principal"', expression)
            self.assertIn('reporter="destination"', expression)
            self.assertIn('response_flags="-"', expression)
            self.assertIn('istio_tcp_connections_closed_total', expression)
            result = self.pairs
        elif expression in self.expressions:
            result = [row({}, self.parts[self.expressions[expression]])]
        else:
            self.assertEqual(expression, validate.substitute(build.closed(build.DEST), 'cmtc-a|cmtc-b'))
            result = [row({}, self.total)]
        return {'data': {'result': result}}, 0

    def check(self):
        return validate.native_acceptance(self.query, self.domains, self.nodes)

    def test_positive_requires_both_identity_domains_and_each_node(self):
        result = self.check()
        self.assertEqual(len(result['clusterPairs']), 2)
        self.assertEqual(len(result['reportingNodes']), 4)

    def test_missing_duplicate_unknown_and_down_targets_are_rejected(self):
        baseline = copy.deepcopy(self.coverage)
        variants = [baseline[:-1], baseline[:3] + [baseline[0]],
                    baseline + [baseline[0]],
                    baseline[:3] + [row({'cluster': 'cmtc-b', 'node': 'unknown'}, 1)],
                    baseline[:3] + [row(baseline[-1]['metric'], 0)]]
        for rows in variants:
            with self.subTest(rows=rows):
                self.coverage = rows
                with self.assertRaisesRegex(AssertionError, 'exactly one reporting'): self.check()

    def test_missing_or_wrong_direction_and_destination_domain_are_rejected(self):
        baseline = copy.deepcopy(self.pairs)
        wrong = copy.deepcopy(baseline)
        wrong[0]['metric']['destination_trust_domain'] = 'attacker.example'
        missing = copy.deepcopy(baseline)
        del missing[0]['metric']['destination_trust_domain']
        for rows in [baseline[:1], wrong, missing]:
            with self.subTest(rows=rows):
                self.pairs = rows
                with self.assertRaisesRegex(AssertionError, 'authenticated'): self.check()

    def test_reachable_targets_with_partial_lifecycle_telemetry_are_rejected(self):
        self.lifecycle.pop()
        with self.assertRaisesRegex(AssertionError, 'every frozen node'): self.check()

    def test_negative_traffic_and_plaintext_outcomes_are_mandatory(self):
        baseline = self.parts.copy()
        for key in ['mTLS · no failure flag', 'Authenticated denied', 'Unauthenticated blocked']:
            with self.subTest(key=key):
                self.parts = baseline.copy()
                self.parts[key] = 0
                self.total = sum(self.parts.values())
                with self.assertRaises(AssertionError): self.check()
        self.parts = baseline.copy()
        self.parts['Unverified · no failure flag'] = 1
        self.total = sum(self.parts.values())
        with self.assertRaisesRegex(AssertionError, 'Unverified'): self.check()

    def test_no_traffic_or_overlapping_partition_cannot_pass(self):
        for total in [0, 24, 26]:
            with self.subTest(total=total):
                self.total = total
                with self.assertRaises(AssertionError): self.check()

    def test_expected_nodes_must_be_frozen_and_distinct(self):
        for nodes in [None, {'cmtc-a': None, 'cmtc-b': None},
                      {'cmtc-a': ['same', 'same'], 'cmtc-b': ['b1', 'b2']}]:
            with self.subTest(nodes=nodes):
                with self.assertRaisesRegex(AssertionError, 'frozen node'):
                    validate.native_acceptance(self.query, self.domains, nodes)


if __name__ == '__main__':
    unittest.main()
