# Expiry of the disposable lab root, 2026-10-27T19:37Z

`kube-system/cmtc-public-root` (the Cilium chart's `tls.caBundle`, Helm-owned) holds two roots: `CMTC disposable lab
root` (SHA-256 `805e7059…637b`, notAfter 2026-10-27T19:37:36Z) and `cmtc mesh root CA` (`6c12c735…275f`, to 2036).
The disposable intermediates (`cmtc-lab-intermediate`) expired at 19:37:39Z (cmtc-a) and 19:37:43Z (cmtc-b). No
Certificate on either cluster uses `cmtc-lab-intermediate`: every Certificate chains to a per-cluster mesh
intermediate (read 19:22Z). The root was left to expire; its removal from the bundle stays a separate Helm change
([MESH_PKI.md](../../../MESH_PKI.md#open-items), item 2).

State: **measured**. The expiry changed nothing.

| Check | Before (19:27:14Z) | After (from 19:38:00Z) |
|---|---|---|
| ClusterMesh, every Cilium agent | 1/1 remote clusters ready, synchronized, 0 reconnections ([before](clustermesh-before.txt)) | the same ([after](clustermesh-after.txt)) |
| clustermesh-apiserver restarts | 0 | 0 ([issuers](issuers-after.txt)) |
| Certificates not Ready | none | none |
| mTLS matrix | 96/96, 36/36 (19:20:55Z) | 96 proven, 0 unanswered, 36 dropped, 0 failed ([join](matrix/join.txt), 19:38:00–19:42:03Z) |

Observation: cert-manager still reports `cmtc-lab-intermediate` Ready ("Signing CA verified") after its CA expired;
the ClusterIssuer's Ready condition does not check the CA's validity. Nothing uses it; deleting it is an open item.
