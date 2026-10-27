"""Pure tests of cilium_cluster_values.py's constants; no Kubernetes, Helm or network access."""
import pathlib
import unittest

from cilium_cluster_values import constants, load_environment

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ConstantsTests(unittest.TestCase):
    def setUp(self):
        self.env = load_environment(ROOT / 'config/lab/environments/cmtc.yaml')

    def test_each_cluster_signs_its_leaves_with_its_own_intermediate(self):
        for cluster in ('cmtc-a', 'cmtc-b'):
            got = constants(self.env, cluster)
            issuer = {'name': f'{cluster}-clustermesh-intermediate'}
            self.assertEqual(got['clustermesh']['apiserver']['tls']['auto']['certManagerIssuerRef'], issuer)
            self.assertEqual(got['hubble']['tls']['auto']['certManagerIssuerRef'], issuer)

    def test_hubble_relay_and_ui_run_in_the_control_cluster_only(self):
        self.assertEqual(self.env['controlCluster'], 'cmtc-a')
        self.assertEqual(constants(self.env, 'cmtc-a')['hubble']['relay'], {'enabled': True})
        self.assertEqual(constants(self.env, 'cmtc-a')['hubble']['ui'], {'enabled': True})
        self.assertEqual(constants(self.env, 'cmtc-b')['hubble']['relay'], {'enabled': False})
        self.assertEqual(constants(self.env, 'cmtc-b')['hubble']['ui'], {'enabled': False})


if __name__ == '__main__':
    unittest.main()
