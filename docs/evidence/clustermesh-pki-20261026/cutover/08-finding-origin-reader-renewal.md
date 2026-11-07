# Finding: a ztunnel-origin-reader reissue closes cross-cluster admission for ~10 s (2026-10-26)

Event meshpki-step8-cmtc-a: ztunnel-origin-reader (cmtc-a) reissued at 13:47:54Z. Cross-cluster requests failed in
both directions from 13:47:58.00Z to 13:48:07.83Z (49 + 49 of 731, curl 56); same-node and crossnode had none.
The direct-origin client hashes CA, certificate and key every 2 s and rebuilds itself on a change
(`pkg/ztunnel/remote_workload/origin_supervisor.go:163,876`); the rebuild invalidates the remote snapshot until the
new watch lists. The certificate's duration is 24 h (certValidityDuration 1, renewBefore 1h), so every renewal costs
cross-cluster admission per cluster. To design: keep the old session until the new one has listed
(make-before-break), or lengthen the client lifetime.

**Re-measured on cmtc-b (meshpki-step8-cmtc-b).** The same reissue at 13:50:56Z cost 1-2 requests per cross-cluster
direction, at 13:51:01.30-13:51:01.51Z (~0.4 s). The earlier sentence "every renewal costs ~10 s" is retracted: the
cost varies from ~0.4 s to ~10 s between two measurements; the cause of the difference is not yet known.
