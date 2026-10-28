"""Pure tests of cilium_release.py; no Kubernetes, Helm or network access."""
import unittest

from cilium_release import ident


class IdentityTests(unittest.TestCase):
    def test_namespace_and_group_keep_objects_apart(self):
        a = {'kind': 'Role', 'apiVersion': 'rbac.authorization.k8s.io/v1', 'metadata': {'name': 'r', 'namespace': 'a'}}
        b = {'kind': 'Role', 'apiVersion': 'rbac.authorization.k8s.io/v1', 'metadata': {'name': 'r', 'namespace': 'b'}}
        self.assertNotEqual(ident(a), ident(b))
        self.assertEqual(ident({'kind': 'Namespace', 'apiVersion': 'v1', 'metadata': {'name': 'n'}}), 'Namespace/n')


if __name__ == '__main__':
    unittest.main()
