# Finding: a clustermesh-apiserver restart closes same-cluster crossnode admission (2026-10-26)

**Observed (cmtc-a, event meshpki-apiserver-restart-cmtc-a).** Restart 13:18:13-13:18:16Z. From 13:18:43.95Z every
cmtc-a crossnode request failed (634 in the window, curl 52/56; still failing 13:21:20Z by Pod IP). Same-node and
cross-cluster paths recovered (cross-cluster after 35 s).

**Chain, from logs and source.**
1. Destination ztunnel: `no allow policies matched` / `allow policies exist, but none allowed`; the effective policy
   `cilium_l4_effective_ebbea7…` (server-control-plane) lists no same-cluster source on the other node.
2. Agent: `Caller is not admitted as an effective ztunnel policy source … key=cluster reason="this cluster's source
   leases expired at 0001-01-01"` (13:18:44Z), `pkg/ztunnel/xds/effective_sources.go:188`.
3. Both source writers re-acquired their lock (13:18:22Z, 13:18:28Z) and keep refreshing
   (`pkg/ztunnel/membership/source_publisher.go:497-519`); no session ended afterwards.
4. The local reader's watch started 04:08:49Z at revision 15976 and logged no restart, relist or error since. etcd
   clientv3 resumes a watch on reconnect from its last revision; the restarted etcd starts near revision 1, so the
   watch waits for a future revision and delivers nothing. Cilium's ListAndWatch relists only on a watch error or
   on a recreated watcher, and a recreated watcher keeps `nextRev` (`pkg/kvstore/etcd.go:849-851`).
5. `runLocalSourceMembershipWatch` (`pkg/ztunnel/remote_workload/source_join.go:690`) expires leases receiver-side
   every second, so the view empties and stays empty.

**Status.** Hypothesis for step 4 is consistent with every log line; not yet proven by reading the etcd revision.
Recovery: restart each agent (fresh list). Fix to design: detect an etcd member/revision regression (e.g. the
response header's revision or cluster ID going backwards, or a heartbeat key) and relist. /lifecycle-recovery item.
