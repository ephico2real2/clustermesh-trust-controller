"""Actual local TLS fixture: pinned CA + exact DNS with hostname checks enabled.

Synthetic ephemeral test keys only; no Kubernetes or real authority key access.
This verifies fixture transport semantics, not the deployed SPIRE agent.
"""
import os, socket, ssl, tempfile, threading, unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from test_workload_api import cert

class TLS(unittest.TestCase):
    def handshake(self,pem,leaf_key,trusted_ca,server_name):
        with tempfile.TemporaryDirectory(prefix='cmtc-kubelet-tls-') as d:
            os.chmod(d,0o700);p=Path(d)
            for name,content in [('server.pem',pem.encode()),('key.pem',leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))]:
                fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as f:f.write(content)
            server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(p/'server.pem',p/'key.pem')
            client=ssl.create_default_context(cadata=trusted_ca.public_bytes(serialization.Encoding.PEM).decode());self.assertTrue(client.check_hostname);self.assertEqual(client.verify_mode,ssl.CERT_REQUIRED)
            sock=socket.socket();sock.settimeout(3)
            try:sock.bind(('127.0.0.1',0));sock.listen(1)
            except BaseException:sock.close();raise
            address=sock.getsockname();errors=[]
            def serve():
                try:
                    connection,_=sock.accept()
                    with connection:
                        connection.settimeout(3)
                        with server.wrap_socket(connection,server_side=True) as tls:tls.sendall(b'public-node-fixture')
                except (ssl.SSLError,OSError) as e:errors.append(type(e).__name__)
            thread=threading.Thread(target=serve);thread.start();passed=False
            try:
                with socket.create_connection(address,timeout=3) as raw:
                    with client.wrap_socket(raw,server_hostname=server_name) as tls:passed=tls.recv(64)==b'public-node-fixture'
            except ssl.SSLCertVerificationError:passed=False
            finally:
                sock.close();thread.join(5);self.assertFalse(thread.is_alive(),'fixture server must be reaped')
            return passed
    def test_exact_dns_and_ca(self):
        pem,_,_,_,ca,key=cert();self.assertTrue(self.handshake(pem,key,ca,'cmtc-a-worker'))
    def test_wrong_dns_rejected(self):
        pem,_,_,_,ca,key=cert();self.assertFalse(self.handshake(pem,key,ca,'cmtc-a-control-plane'))
    def test_wrong_ca_rejected(self):
        pem,_,_,_,_,key=cert();_,_,_,_,other,_=cert();self.assertFalse(self.handshake(pem,key,other,'cmtc-a-worker'))
    def test_valid_leaf_renewal_same_ca(self):
        _,_,_,cakey,ca,_=cert();pem,_,_,_,_,key=cert(ca_key=cakey,ca_cert=ca);self.assertTrue(self.handshake(pem,key,ca,'cmtc-a-worker'))
    def test_ca_rotation_requires_new_approval(self):
        _,_,_,_,old,_=cert();pem,_,_,_,_,key=cert();self.assertFalse(self.handshake(pem,key,old,'cmtc-a-worker'))
if __name__=='__main__':unittest.main()
