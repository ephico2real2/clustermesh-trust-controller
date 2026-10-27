#!/usr/bin/env python3
"""Decision tests for renew_approval.py on a synthetic ledger; no cluster is needed."""
import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import renew_approval as r


def ledger(expires_in_days, **overrides):
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=expires_in_days)
    data = {
        'success': True,
        'identity': {'issuerMode': 'spire-intermediate', 'generation': 6, 'image': 'img@sha256:1', 'imageConfig': 'sha256:2',
                     'sourceRevision': 'a' * 40, 'rootSHA256': 'b' * 64,
                     'clusterPins': {'cmtc-a': 'ka', 'cmtc-b': 'kb'}, 'intermediatePins': {'cmtc-a': 'ia', 'cmtc-b': 'ib'},
                     'deploymentPins': {'cmtc-a': 'da', 'cmtc-b': 'db'},
                     'nodePins': {'cmtc-a/cmtc-a-worker': 'na', 'cmtc-b/cmtc-b-worker': 'nb'}},
        'approval': {'generation': 6, 'expiresAt': expires.strftime('%Y-%m-%dT%H:%M:%SZ')},
        'freshProofs': {'cmtc-a': {'certificateUID': 'ia', 'revision': 1}, 'cmtc-b': {'certificateUID': 'ib', 'revision': 1}},
    }
    data.update(overrides)
    return data


class Renewal(unittest.TestCase):
    def run_main(self, data, *argv, kubectl=None, advance=None):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'ledger.json').write_text(json.dumps(data))
            calls = []

            def fake_run(cmd, **_):
                calls.append(cmd)
                if cmd[0] == 'kubectl':
                    return kubectl(cmd)
                return advance(cmd, d)
            args = ['renew_approval.py', '--state-dir', d, '--kubeconfig', 'k', *argv]
            with mock.patch.object(sys, 'argv', args), mock.patch.object(subprocess, 'run', fake_run), \
                    mock.patch('builtins.print'):
                try:
                    code = r.main()
                except SystemExit as e:
                    code = e.code
            return code, calls

    @staticmethod
    def live(revisions):
        def kubectl(cmd):
            cluster = cmd[cmd.index('--context') + 1][len('kind-'):]
            body = {'metadata': {'uid': {'cmtc-a': 'ia', 'cmtc-b': 'ib'}[cluster]}, 'status': {'revision': revisions[cluster]}}
            return subprocess.CompletedProcess(cmd, 0, json.dumps(body), '')
        return kubectl

    def test_not_due_changes_nothing(self):
        code, calls = self.run_main(ledger(20))
        self.assertEqual((0, []), (code, calls))

    def test_check_reports_due_without_acting(self):
        code, calls = self.run_main(ledger(3), '--check')
        self.assertEqual((10, []), (code, calls))

    def test_due_runs_the_advance_with_generation_plus_one_and_the_ledger_pins(self):
        def advance(cmd, d):
            moved = ledger(29);moved['identity']['generation'] = moved['approval']['generation'] = 7
            Path(d, 'ledger.json').write_text(json.dumps(moved))
            return subprocess.CompletedProcess(cmd, 0, '{"success": true}', '')
        code, calls = self.run_main(ledger(3), kubectl=self.live({'cmtc-a': 1, 'cmtc-b': 1}), advance=advance)
        self.assertEqual(0, code)
        argv = calls[-1]
        self.assertEqual('7', argv[argv.index('--generation') + 1])
        self.assertEqual(str(29 * r.DAY), argv[argv.index('--horizon') + 1])
        self.assertEqual(['--spire-intermediate', '--advance'], [x for x in argv if x in ('--spire-intermediate', '--advance')])
        for pin in ('cmtc-a=ka', 'cmtc-b=ib', 'cmtc-a=da', 'cmtc-b/cmtc-b-worker=nb'):
            self.assertIn(pin, argv)

    def test_a_renewed_intermediate_is_refused_before_any_advance(self):
        code, calls = self.run_main(ledger(3), kubectl=self.live({'cmtc-a': 1, 'cmtc-b': 2}))
        self.assertEqual(20, code)
        self.assertTrue(all(c[0] == 'kubectl' for c in calls))

    def test_a_failed_advance_returns_its_status(self):
        advance = lambda cmd, d: subprocess.CompletedProcess(cmd, 3, '', 'Refusal: drift')
        code, _ = self.run_main(ledger(3), kubectl=self.live({'cmtc-a': 1, 'cmtc-b': 1}), advance=advance)
        self.assertEqual(3, code)

    def test_an_unqualified_or_signer_mode_ledger_is_refused(self):
        for data in (ledger(3, success=False), ledger(3, advancing=7)):
            self.assertEqual(20, self.run_main(data)[0])
        signer = ledger(3);signer['identity']['issuerMode'] = None
        self.assertEqual(20, self.run_main(signer)[0])


if __name__ == '__main__':
    unittest.main()
