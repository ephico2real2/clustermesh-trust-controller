#!/usr/bin/env python3
"""Real private Linux DAC regression. Run as root inside a disposable container.

No host namespaces, Kubernetes API, credentials or SPIRE data are used. The
Unix servers below test DAC only; native SPIRE delegate authorization is a
separate mandatory lab gate, especially for an ordinary caller with UID1000.
"""
import ctypes
import errno
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import agent_admin_group as profile

CHILD=r'''
import json,os,socket,stat,sys
path,action=sys.argv[1:]
caps={k:v.strip() for k,v in (line.split(':',1) for line in open('/proc/self/status')) if k in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')}
if any(int(v,16) for v in caps.values()):raise RuntimeError('test process retained capabilities: '+str(caps))
if os.getgroups():raise RuntimeError('test process retained supplementary groups')
if action=='server':
 if os.path.lexists(path):
  old=os.lstat(path)
  if not stat.S_ISSOCK(old.st_mode):raise RuntimeError('non-socket replacement refused')
  if old.st_uid!=os.getuid() or old.st_gid!=os.getgid():raise RuntimeError('foreign socket replacement refused')
  os.unlink(path)
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(path);os.chmod(path,0o770);s.listen()
 st=os.stat(path)
 print(json.dumps({'ready':True,'uid':os.getuid(),'gid':os.getgid(),'socketUID':st.st_uid,'socketGID':st.st_gid,'mode':oct(st.st_mode&0o7777),'caps':caps}),flush=True)
 while True:
  c,_=s.accept();c.sendall(b'owned');c.close()
elif action=='client':
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 try:s.connect(path)
 except PermissionError:print('DAC_DENIED',flush=True);sys.exit(42)
 except OSError as e:print('UNEXPECTED_CONNECT_ERROR:'+str(e),flush=True);sys.exit(43)
 assert s.recv(32)==b'owned';s.close();print('DAC_ALLOWED',flush=True)
'''

def credentials(uid,gid):
    def apply():
        libc=ctypes.CDLL(None,use_errno=True)
        # Empty bounding set prevents UID0 regaining capabilities at exec.
        for cap in range(64):
            if libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=errno.EINVAL:
                raise OSError(ctypes.get_errno(),'PR_CAPBSET_DROP')
        if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS')
        os.setgroups([]);os.setgid(gid);os.setuid(uid)
        class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
        class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
        h=Header(0x20080522,0);d=(Data*2)()
        if libc.capset(ctypes.byref(h),ctypes.byref(d))!=0:raise OSError(ctypes.get_errno(),'capset(drop ALL)')
    return apply

class KernelDAC(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith('linux') and os.geteuid()==0,'requires disposable Linux root fixture; do not skip')
        self.temp=tempfile.TemporaryDirectory(prefix='cmtc-admin-dac-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);os.chmod(self.root,0o755)
        for name in ('agent','admin','server-admin'):
            p=self.root/name;p.mkdir(mode=0o700);os.chown(p,1000,1000)
        self.procs=[];self.addCleanup(self.stop_all)
    def stop_all(self):
        for p in self.procs:
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
            p.stdout.close();p.stderr.close()
    def migrate(self,expected=0):
        script=profile.MIGRATE.replace('/cmtc-node-sockets',str(self.root))
        p=subprocess.run(['/bin/sh','-ec',script],preexec_fn=credentials(1000,1337),cwd='/',text=True,capture_output=True,timeout=3)
        self.assertEqual(p.returncode,expected,p.stdout+p.stderr)
    def server(self,name,gid):
        path=str(self.root/name/'api.sock')
        p=subprocess.Popen([sys.executable,'-c',CHILD,path,'server'],preexec_fn=credentials(1000,gid),cwd='/',text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.procs.append(p)
        ready,_,_=select.select([p.stdout],[],[],3)
        self.assertTrue(ready,'private Unix server did not report readiness')
        line=p.stdout.readline();self.assertTrue(line,'server failed: '+(p.stderr.read() if p.poll() is not None else ''))
        import json
        evidence=json.loads(line);self.assertTrue(evidence['ready']);self.assertEqual(evidence['socketUID'],1000);self.assertEqual(evidence['socketGID'],gid);self.assertEqual(evidence['mode'],'0o770')
        return p,path,evidence
    def client(self,path,uid,gid,allowed):
        p=subprocess.run([sys.executable,'-c',CHILD,path,'client'],preexec_fn=credentials(uid,gid),cwd='/',text=True,capture_output=True,timeout=3)
        self.assertEqual(p.returncode,0 if allowed else 42,p.stdout+p.stderr)
        self.assertEqual(p.stdout.strip(),'DAC_ALLOWED' if allowed else 'DAC_DENIED')
    def test_group_access_private_endpoints_and_restart(self):
        inode=os.stat(self.root/'admin').st_ino;self.migrate();self.migrate()
        st=os.stat(self.root/'admin');self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(1000,1337,0o710));self.assertEqual(st.st_ino,inode)
        agent,path,_=self.server('admin',1337)
        self.client(path,0,1337,True)
        self.client(path,0,1000,False)
        self.client(path,65532,1000,False)
        # The directory owner is intentionally a SPIRE TCB identity. DAC alone
        # cannot distinguish another process with UID1000. Native SPIRE must
        # still refuse an unregistered/unauthorized delegate using this UID.
        self.client(path,1000,1000,True)
        _,workload,_=self.server('agent',1337);self.client(workload,0,1337,False)
        _,serveradmin,_=self.server('server-admin',1000);self.client(serveradmin,0,1337,False)
        agent.terminate();agent.wait(timeout=3)
        replacement,path,_=self.server('admin',1337);self.assertNotEqual(agent.pid,replacement.pid)
        self.client(path,0,1337,True);self.client(path,0,1000,False)
        st=os.stat(self.root/'agent');self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(1000,1000,0o700))
        st=os.stat(self.root/'server-admin');self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(1000,1000,0o700))
    def test_interrupted_owner_group_transition_recovers(self):
        os.chown(self.root/'admin',1000,1337)
        self.migrate();st=os.stat(self.root/'admin')
        self.assertEqual((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)),(1000,1337,0o710))
    def test_foreign_metadata_refused_without_touching_target(self):
        os.chmod(self.root/'admin',0o711);before=os.stat(self.root/'admin');self.migrate(42);after=os.stat(self.root/'admin')
        self.assertEqual((before.st_uid,before.st_gid,before.st_mode),(after.st_uid,after.st_gid,after.st_mode))
        os.chmod(self.root/'admin',0o700);os.chown(self.root/'admin',2000,1000);self.migrate(42)

if __name__=='__main__':unittest.main()
