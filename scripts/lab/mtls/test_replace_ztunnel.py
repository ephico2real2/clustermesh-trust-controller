"""Pure tests of replace_ztunnel.py; no node, SPIRE or Kubernetes access."""
import unittest

from replace_ztunnel import check_template, delegate_entry, entry_id_for, node_order, runs_image

IMAGE = 'ghcr.io/ephico2real2/cmtc-ztunnel@sha256:' + 'b' * 64


def pod(uid='db033a2b-22a9-471a-9754-eed294722b09', node='cmtc-b-worker', image_id=IMAGE):
    return {'metadata': {'name': 'ztunnel-cilium-x', 'uid': uid},
            'spec': {'serviceAccountName': 'ztunnel-cilium', 'nodeName': node},
            'status': {'containerStatuses': [{'imageID': image_id}]}}


def daemonset(image=IMAGE, strategy='OnDelete', host_pid=True):
    return {'spec': {'updateStrategy': {'type': strategy},
                     'template': {'spec': {'hostPID': host_pid,
                                           'containers': [{'name': 'istio-proxy', 'image': image}]}}}}


class DelegateEntryTests(unittest.TestCase):
    def test_entry_id_matches_the_lab_entries(self):
        # Recorded 2026-10-27 in docs/evidence/root-pin-retirement-20261027/ledger.jsonl for ztunnel-cilium-rxmwb.
        self.assertEqual(entry_id_for('cmtc-b', 'db033a2b-22a9-471a-9754-eed294722b09'),
                         '35d3bacf-c237-519f-b92e-acc35fc3a662')

    def test_entry_binds_the_pod_uid_node_and_service_account(self):
        entry_id, args, selectors = delegate_entry('cmtc-b', pod())
        self.assertEqual(selectors, ['k8s:ns:kube-system', 'k8s:sa:ztunnel-cilium',
                                     'k8s:pod-uid:db033a2b-22a9-471a-9754-eed294722b09',
                                     'k8s:node-name:cmtc-b-worker'])
        self.assertEqual(args[:3], ['entry', 'create', '-entryID'])
        self.assertEqual(args[3], entry_id)
        self.assertIn('spiffe://cmtc-b.mesh.example/ztunnel-proxy', args)
        self.assertIn('spiffe://cmtc-b.mesh.example/ns/cilium-spire/sa/spire-agent', args)
        self.assertEqual(args[args.index('-x509SVIDTTL') + 1], '120')
        self.assertEqual(args.count('-selector'), 4)


class TemplateTests(unittest.TestCase):
    def test_accepts_the_helm_rendered_template(self):
        check_template(daemonset(), IMAGE)

    def test_refuses_another_image_strategy_or_missing_host_pid(self):
        with self.assertRaisesRegex(ValueError, 'cilium_adopt.py upgrade'):
            check_template(daemonset(image=IMAGE.replace('b' * 64, 'a' * 64)), IMAGE)
        with self.assertRaisesRegex(ValueError, 'OnDelete'):
            check_template(daemonset(strategy='RollingUpdate'), IMAGE)
        with self.assertRaisesRegex(ValueError, 'hostPID'):
            check_template(daemonset(host_pid=False), IMAGE)


class PodTests(unittest.TestCase):
    def test_runs_image_compares_the_digest(self):
        self.assertTrue(runs_image(pod(), IMAGE))
        self.assertTrue(runs_image(pod(image_id='docker.io/x@sha256:' + 'b' * 64), IMAGE))
        self.assertFalse(runs_image(pod(image_id='ghcr.io/x@sha256:' + 'a' * 64), IMAGE))
        self.assertFalse(runs_image({'status': {}}, IMAGE))

    def test_workers_first(self):
        self.assertEqual(node_order(['cmtc-a-control-plane', 'cmtc-a-worker2', 'cmtc-a-worker']),
                         ['cmtc-a-worker', 'cmtc-a-worker2', 'cmtc-a-control-plane'])


if __name__ == '__main__':
    unittest.main()
