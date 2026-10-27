# Helm adoption of Cilium on kind-cmtc-b (#33), 2026-10-27

Result: the `cilium` release on kind-cmtc-b renders equal to the live objects (0 differences), at revision 7.

1. 16:44Z `scripts/cilium/prepare.sh` (lock `config/cilium-images.lock.json`, source `1bd555f313`), then
   `cilium_cluster_values.py ... cmtc-b --from-live` and `cilium_release.py check ... --strict`: 10 differences, all in
   the agent DaemonSet pod template (Prometheus annotations and `hostPort` 9962 missing live; the ztunnel bootstrap
   volume named `cmtc-ztunnel-bootstrap` live and `cilium-ztunnel-secrets` rendered, same Secret
   `cmtc-ztunnel-ads-tls` and mount `/etc/ztunnel`; list order), and 7 ztunnel objects outside the release.
2. `cilium_adopt.py plan`: 41 changes, 0 deletions, 0 refusals ([plan.txt](plan.txt)). The ztunnel DaemonSet has
   metadata changes only, no pod-template change.
3. `cilium_adopt.py transfer`: the `kubectl-patch` fields of DaemonSets `cilium` and `ztunnel-cilium` given to Helm;
   the earlier managedFields are kept in
   `/private/tmp/cmtc-opus-final-20261025/review/helm-adoption-cmtc-b-20261027T1645Z/`.
4. 16:45:57Z to 16:46:28Z `cilium_adopt.py upgrade` (server-side, `--take-ownership`): revision 7. Both agents
   restarted, one at a time. ztunnel Pods were not replaced (6 h old), clustermesh-apiserver did not restart (23 h
   old), and `cilium clustermesh status`: 2/2 nodes connected to cmtc-a.
5. `cilium_release.py check`: 0 differences, 0 to delete, 0 to take over.
6. 16:46:50Z to 16:48:50Z `scripts/evidence/run_mtls_matrix.sh` ([matrix/join.txt](matrix/join.txt)): 96 proven over
   mTLS, 36 dropped by Cilium (unregistered callers, `Policy denied`), 0 unanswered, 0 failed.

cert-manager's built-in approver was on during this change (MESH_PKI.md, Approval).
