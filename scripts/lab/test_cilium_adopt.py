"""Pure tests of the managedFields transfer in cilium_adopt.py; no Kubernetes, Helm or network access."""
import unittest

from cilium_adopt import SERVER_MAINTAINED, changes, comparable, foreign_release, transferred, union, without

DS = 'apps/v1'


def entry(manager, fields, operation='Update', api=DS, **extra):
    return {'manager': manager, 'operation': operation, 'apiVersion': api, 'fieldsType': 'FieldsV1',
            'fieldsV1': fields, **extra}


def live(*entries, api=DS):
    return {'kind': 'DaemonSet', 'apiVersion': api, 'metadata': {'name': 'x', 'managedFields': list(entries)}}


class UnionTests(unittest.TestCase):
    def test_member_with_members_below_keeps_its_own_membership(self):
        # Both ztunnel-origin-config backups had this shape (client-side apply owned f:data, kubectl-patch a key).
        want = {'f:data': {'.': {}, 'f:cmtc-b': {}}}
        self.assertEqual(union({'f:data': {}}, {'f:data': {'f:cmtc-b': {}}}), want)
        self.assertEqual(union({'f:data': {'f:cmtc-b': {}}}, {'f:data': {}}), want)

    def test_disjoint_shared_and_marked(self):
        self.assertEqual(union({'f:a': {}}, {'f:b': {}}), {'f:a': {}, 'f:b': {}})
        self.assertEqual(union({'f:a': {}}, {'f:a': {}}), {'f:a': {}})
        self.assertEqual(union({'f:m': {'.': {}, 'f:x': {}}}, {'f:m': {'f:y': {}}}),
                         {'f:m': {'.': {}, 'f:x': {}, 'f:y': {}}})

    def test_top_level_is_a_set(self):
        self.assertEqual(union({}, {'f:spec': {'f:x': {}}}), {'f:spec': {'f:x': {}}})

    def test_inputs_unchanged(self):
        a, b = {'f:data': {}}, {'f:data': {'f:k': {}}}
        union(a, b)
        self.assertEqual((a, b), ({'f:data': {}}, {'f:data': {'f:k': {}}}))


class WithoutTests(unittest.TestCase):
    path = ('f:metadata', 'f:annotations', 'f:deprecated.daemonset.template.generation')

    def test_prunes_parents_that_only_held_it(self):
        tree = {'f:metadata': {'f:annotations': {'f:deprecated.daemonset.template.generation': {}}}, 'f:spec': {}}
        self.assertEqual(without(tree, self.path), {'f:spec': {}})

    def test_keeps_marked_parent_and_siblings(self):
        tree = {'f:metadata': {'f:annotations': {'.': {}, 'f:deprecated.daemonset.template.generation': {},
                                                 'f:other': {}}}}
        self.assertEqual(without(tree, self.path), {'f:metadata': {'f:annotations': {'.': {}, 'f:other': {}}}})

    def test_absent_path(self):
        self.assertEqual(without({'f:spec': {}}, self.path), {'f:spec': {}})


class TransferredTests(unittest.TestCase):
    def test_kubectl_fields_join_helm_and_others_stay(self):
        helm = entry('helm', {'f:spec': {'f:a': {}}}, 'Apply')
        patch = entry('kubectl-patch', {'f:spec': {'f:b': {}}})
        rollout = entry('kubectl-rollout', {'f:spec': {'f:restartedAt': {}}})
        status = entry('kube-controller-manager', {'f:status': {}}, subresource='status')
        out = transferred(live(helm, patch, rollout, status), [])
        self.assertEqual([m['manager'] for m in out], ['kubectl-rollout', 'kube-controller-manager', 'helm'])
        self.assertEqual(out[-1]['fieldsV1'], {'f:spec': {'f:a': {}, 'f:b': {}}})
        self.assertEqual(out[-1]['operation'], 'Apply')

    def test_server_maintained_fields_stay_unowned(self):
        csa = entry('kubectl-client-side-apply', {'f:metadata': {'f:annotations': {
            'f:deprecated.daemonset.template.generation': {}}}, 'f:spec': {'f:x': {}}})
        self.assertEqual(SERVER_MAINTAINED[0][-1], 'f:deprecated.daemonset.template.generation')
        self.assertEqual(transferred(live(csa), [])[-1]['fieldsV1'], {'f:spec': {'f:x': {}}})

    def test_repeat_with_backup_repairs_and_then_is_a_no_op(self):
        lossy = entry('helm', {'f:data': {'f:cmtc-b': {}}}, 'Apply')
        backup = [entry('kubectl-client-side-apply', {'f:data': {}}, api='v1'),
                  entry('kubectl-patch', {'f:data': {'f:cmtc-b': {}}}, api='v1')]
        obj = live(dict(lossy, apiVersion='v1'), api='v1')
        repaired = transferred(obj, backup)
        self.assertEqual(repaired[-1]['fieldsV1'], {'f:data': {'.': {}, 'f:cmtc-b': {}}})
        again = live(*repaired, api='v1')
        self.assertIs(transferred(again, backup), again['metadata']['managedFields'])

    def test_nothing_to_move_creates_no_entry(self):
        obj = live(entry('kube-controller-manager', {'f:spec': {}}))
        self.assertEqual(transferred(obj, []), obj['metadata']['managedFields'])

    def test_other_api_version_refused(self):
        with self.assertRaises(SystemExit):
            transferred(live(entry('kubectl-patch', {'f:spec': {}}, api='extensions/v1beta1')), [])


class ChangesTests(unittest.TestCase):
    def test_named_lists_by_name_then_order(self):
        out = []
        changes({'v': [{'name': 'a', 'x': 1}, {'name': 'b'}]}, {'v': [{'name': 'b'}, {'name': 'a', 'x': 2}]}, '', out)
        self.assertEqual(out, [('.v[name="a"].x', 1, 2), ('.v (order)', ['"a"', '"b"'], ['"b"', '"a"'])])


class ForeignReleaseTests(unittest.TestCase):
    def test_foreign_release_by_name_or_namespace(self):
        meta = lambda **n: {'metadata': {'annotations': {f'meta.helm.sh/release-{k}': v for k, v in n.items()}}}
        self.assertIsNone(foreign_release(meta(name='cilium', namespace='kube-system')))
        self.assertIsNone(foreign_release({'metadata': {}}))
        self.assertEqual(foreign_release(meta(name='other', namespace='kube-system')), 'other/kube-system')
        self.assertEqual(foreign_release(meta(name='cilium', namespace='elsewhere')), 'cilium/elsewhere')


class SecretTests(unittest.TestCase):
    def test_values_never_appear(self):
        secret = {'kind': 'Secret', 'apiVersion': 'v1', 'data': {'k': 'c2VjcmV0'}, 'metadata': {'name': 's',
                  'annotations': {'kubectl.kubernetes.io/last-applied-configuration': '{"data":{"k":"c2VjcmV0"}}'}}}
        self.assertNotIn('c2VjcmV0', repr(comparable(secret)))
        self.assertIn('c2VjcmV0', repr(secret))


if __name__ == '__main__':
    unittest.main()
