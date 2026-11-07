"""Pure tests of cmtc_adopt.py; helm template runs on the repository chart, no Kubernetes access."""
import unittest
from types import SimpleNamespace

from cmtc_adopt import ROOT, foreign_release, render, with_release_metadata


class ReleaseMetadataTests(unittest.TestCase):
    def test_names_the_cmtc_release(self):
        o = with_release_metadata({'kind': 'Role', 'metadata': {'name': 'x', 'labels': {'a': 'b'}}})
        self.assertEqual(o['metadata']['annotations'], {'meta.helm.sh/release-name': 'cmtc',
                                                        'meta.helm.sh/release-namespace': 'cmtc-system'})
        self.assertEqual(o['metadata']['labels'], {'a': 'b', 'app.kubernetes.io/managed-by': 'Helm'})

    def test_input_unchanged(self):
        o = {'kind': 'Role', 'metadata': {'name': 'x'}}
        with_release_metadata(o)
        self.assertEqual(o, {'kind': 'Role', 'metadata': {'name': 'x'}})

    def test_foreign_release(self):
        notes = lambda name, ns: {'metadata': {'annotations': {'meta.helm.sh/release-name': name,
                                                               'meta.helm.sh/release-namespace': ns}}}
        self.assertIsNone(foreign_release(notes('cmtc', 'cmtc-system')))
        self.assertIsNone(foreign_release({'metadata': {}}))
        self.assertEqual(foreign_release(notes('cmtc-trust', 'default')), 'cmtc-trust/default')


class RenderTests(unittest.TestCase):
    def test_lab_values_render_no_secret_and_the_arbiter_off_on_request(self):
        for cluster in ('cmtc-a', 'cmtc-b'):
            args = SimpleNamespace(values=str(ROOT / f'config/lab/cmtc/values-{cluster}.yaml'),
                                   set=['image.tag=x', 'controller.issuerApproval.enabled=false'])
            kinds = {(o['kind'], o['metadata']['name']) for o in render(args)}
            self.assertIn(('DaemonSet', 'cmtc-node-agent'), kinds)
            self.assertIn(('ServiceAccount', 'cmtc-peer-reader'), kinds)
            self.assertNotIn(('ConfigMap', 'cmtc-issuer-approval-config'), kinds)
            self.assertFalse([k for k in kinds if k[0] == 'Secret'])


if __name__ == '__main__':
    unittest.main()
