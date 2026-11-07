"""Pure tests of what clean-caches.py selects; no Docker, Go or network access."""
import importlib.util
import os
import pathlib
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('clean_caches', pathlib.Path(__file__).with_name('clean-caches.py'))
clean_caches = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clean_caches)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, name, directory=True, age_hours=48):
        p = self.root / name
        if directory:
            (p / '00').mkdir(parents=True)
        else:
            p.write_bytes(b'x')
        old = time.time() - age_hours * 3600
        for x in ([p / '00'] if directory else []) + [p]:
            os.utime(x, (old, old))
        return p

    def selected(self, min_age_hours=24):
        return {p.name for p in clean_caches.host_candidates(self.root, min_age_hours * 3600)}

    def test_caches_and_artifacts_by_name(self):
        for n in ('cilium-ztunnel-linux-go-cache', 'cmtc-gocache', 'cilium-go-build-cache', 'cmtc-observer-mod-cache',
                  'cmtc-spire-go-modules', 'cmtc-spire-bootstrap-go-mod', 'cmtc-ztunnel-cargo-home'):
            self.make(n)
        self.make('cmtc-builder.tar', directory=False)
        self.make('cmtc-membership.test', directory=False)
        self.assertEqual(len(self.selected()), 9)

    def test_source_trees_evidence_and_protected_names_stay(self):
        for n in ('cmtc-peer-lease-proposal', 'cmtc-admission-20261024', 'cmtc-opus-final-20261025',
                  'claude-501', 'cmtc-opus-final-go-cache'):
            self.make(n)
        self.make('cmtc-a-b-20261024.kubeconfig', directory=False)
        self.make('cmtc-go-cache.tar', directory=True)  # a directory named like a tarball is not an artifact
        self.assertEqual(self.selected(), set())

    def test_recent_writes_stay(self):
        cache = self.make('cmtc-gocache')
        now = time.time()
        os.utime(cache / '00', (now, now))  # a build wrote into a subdirectory just now
        self.assertEqual(self.selected(), set())
        self.assertEqual(self.selected(min_age_hours=0), {'cmtc-gocache'})

    def test_symlinks_stay(self):
        target = self.make('real-go-cache')
        (self.root / 'link-go-cache').symlink_to(target)
        self.assertEqual(self.selected(), {'real-go-cache'})


class RemoveTests(unittest.TestCase):
    def test_read_only_module_cache_is_removed(self):
        with tempfile.TemporaryDirectory() as t:
            p = pathlib.Path(t) / 'x-go-modules'
            (p / 'mod').mkdir(parents=True)
            (p / 'mod' / 'f').write_text('x')
            os.chmod(p / 'mod' / 'f', 0o444)
            os.chmod(p / 'mod', 0o555)
            clean_caches.remove_tree(p)
            self.assertFalse(p.exists())


if __name__ == '__main__':
    unittest.main()
