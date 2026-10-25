"""Actual Linux checks for the private, server-only emptyDir init step."""
import ast
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from test_agent_admin_group import credentials

source=ast.parse(Path('/src/scripts/lab/spire/qualify_registrar.py').read_text())
SCRIPT=next(ast.literal_eval(n.value) for n in source.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='SERVER_SOCKET_PREPARE' for x in n.targets))

class ServerDirectory(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith('linux') and os.geteuid()==0,'actual disposable Linux root fixture required')
        self.temp=tempfile.TemporaryDirectory(prefix='cmtc-server-admin-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);os.chmod(self.root,0o755)
        self.directory=self.root/'private';self.directory.mkdir();os.chown(self.directory,0,1000);os.chmod(self.directory,0o2777)
    def invoke(self):
        script=SCRIPT.replace('/tmp/spire-server/private',str(self.directory))
        # credentials() empties all capability sets and supplementary groups,
        # including the bounding set before exec. UID0 gains no DAC capability.
        return subprocess.run(['/bin/sh','-ec',script],preexec_fn=credentials(0,1000),cwd='/',capture_output=True,text=True,timeout=5)
    def test_root_owner_without_capabilities_narrows_only_empty_volume(self):
        before=self.directory.stat();result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
        after=self.directory.stat();self.assertEqual(after.st_ino,before.st_ino)
        self.assertEqual((after.st_uid,after.st_gid,stat.S_IMODE(after.st_mode)),(0,1000,0o770))
        self.assertEqual(list(self.directory.iterdir()),[])
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o755)
    def test_nonempty_foreign_owner_and_symlink_are_rejected(self):
        for variant in ['nonempty','foreign-owner','symlink']:
            with self.subTest(variant=variant):
                if variant=='nonempty':(self.directory/'retain').write_text('public fixture')
                elif variant=='foreign-owner':os.chown(self.directory,1000,1000)
                else:
                    self.directory.rename(self.root/'retained');self.directory.symlink_to(self.root/'retained',target_is_directory=True)
                result=self.invoke();self.assertNotEqual(result.returncode,0)
                actual=self.root/'retained' if variant=='symlink' else self.directory
                self.assertEqual(stat.S_IMODE(actual.stat().st_mode),0o2777)
                if variant=='nonempty':(self.directory/'retain').unlink()
                elif variant=='foreign-owner':os.chown(self.directory,0,1000)
