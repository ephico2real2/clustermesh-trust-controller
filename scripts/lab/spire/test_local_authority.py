#!/usr/bin/env python3
"""Decision tests for local_authority.py with a fake SPIRE server; no cluster is needed."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import local_authority as la

OLD_UPSTREAM, INTERMEDIATE = '9c3af0aa', '1b2c3d4e'


class FakeSpire:
    """The authority state SPIRE's localauthority API reports, and the commands it receives."""

    def __init__(self, active, prepared=None, old=None, bundle=True):
        self.slots = {'active': active, 'prepared': prepared, 'old': old}
        self.bundle, self.calls, self.name, self.ledger = bundle, [], 'cmtc-a', None

    def spire(self, *args):
        self.calls.append(args)
        if args[0] == 'show':
            return {k: {'authority_id': v[0], 'upstream_authority_subject_key_id': v[1], 'expires_at': '1'}
                    for k, v in self.slots.items() if v}
        if args[0] == 'prepare':
            self.slots['prepared'] = ('new', INTERMEDIATE)
            return {'prepared_authority': {'authority_id': 'new', 'upstream_authority_subject_key_id': INTERMEDIATE}}
        if args[0] == 'activate':
            self.slots['old'], self.slots['active'], self.slots['prepared'] = self.slots['active'], self.slots['prepared'], None
            return {}
        return {}

    state = la.Cluster.state
    record = lambda self, *a, **k: None

    def mesh_root_in_bundle(self):
        return self.bundle


class Decisions(unittest.TestCase):
    def commands(self, fake):
        return [args[0] for args in fake.calls if args[0] != 'show']

    def test_rotate_replaces_a_prepared_ca_from_the_old_upstream(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM), ('waiting', OLD_UPSTREAM))
        la.rotate(fake, INTERMEDIATE, propagation=0, bundle_timeout=1)
        self.assertEqual(self.commands(fake), ['prepare', 'activate'])
        self.assertIn(('activate', '-authorityID', 'new'), fake.calls)
        self.assertEqual(fake.slots['active'], ('new', INTERMEDIATE))

    def test_rotate_keeps_a_prepared_ca_from_the_intermediate(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM), ('ready', INTERMEDIATE))
        la.rotate(fake, INTERMEDIATE, propagation=0, bundle_timeout=1)
        self.assertEqual(self.commands(fake), ['activate'])
        self.assertIn(('activate', '-authorityID', 'ready'), fake.calls)

    def test_rotate_waits_for_the_mesh_root_and_then_refuses(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM), ('ready', INTERMEDIATE), bundle=False)
        with mock.patch.object(la.time, 'sleep'), self.assertRaisesRegex(la.Refusal, 'mesh root not in'):
            la.rotate(fake, INTERMEDIATE, propagation=0, bundle_timeout=0)
        self.assertEqual(self.commands(fake), [])

    def test_activate_refuses_a_ca_from_another_upstream(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM), ('waiting', OLD_UPSTREAM))
        with self.assertRaisesRegex(la.Refusal, 'not the SPIRE intermediate'):
            la.activate(fake, INTERMEDIATE, 'waiting')
        self.assertEqual(self.commands(fake), [])

    def test_activate_refuses_an_authority_that_is_not_the_prepared_one(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM), ('ready', INTERMEDIATE))
        with self.assertRaisesRegex(la.Refusal, 'not other'):
            la.activate(fake, INTERMEDIATE, 'other')

    def test_prepare_refuses_when_the_upstream_is_not_the_intermediate(self):
        fake = FakeSpire(('cur', OLD_UPSTREAM))
        fake.spire = lambda *args, _orig=fake.spire: (
            {'prepared_authority': {'authority_id': 'x', 'upstream_authority_subject_key_id': OLD_UPSTREAM}}
            if args[0] == 'prepare' else _orig(*args))
        fake.slots['prepared'] = ('x', OLD_UPSTREAM)
        with self.assertRaisesRegex(la.Refusal, 'not the SPIRE intermediate'):
            la.prepare(fake, INTERMEDIATE)

    def test_taint_and_revoke_act_only_on_the_old_authority(self):
        state = FakeSpire(('cur', INTERMEDIATE), ('next', INTERMEDIATE), ('gone', OLD_UPSTREAM)).spire('show')
        la.check_old(state, 'gone')
        for refused in ('cur', 'next', 'unknown'):
            with self.assertRaises(la.Refusal):
                la.check_old(state, refused)


class Certificates(unittest.TestCase):
    def test_subject_key_id_matches_openssl(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = Path(d, 'k.pem'), Path(d, 'c.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                            '-keyout', str(key), '-out', str(crt), '-subj', '/CN=t', '-days', '1'],
                           check=True, capture_output=True)
            pem = crt.read_text()
            ski = la.subject_key_id(pem)
            self.assertRegex(ski, '^[0-9a-f]{40}$')
            der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=pem.encode(), capture_output=True,
                                 check=True).stdout
            self.assertEqual(la.der_sha256(pem), __import__('hashlib').sha256(der).hexdigest())


if __name__ == '__main__':
    unittest.main()
