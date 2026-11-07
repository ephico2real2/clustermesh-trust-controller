# Published images on the labs, 2026-10-26

This record qualifies the images published to `ghcr.io/ephico2real2` on kind-cmtc-a and kind-cmtc-b. Each component
moved from a local image to its published digest under continuous traffic, one step at a time. A probe matrix after
the steps proved mTLS per request. Then the Cilium agent moved to fork commit a99264f008, which lets TCP DNS from
enrolled Pods reach CoreDNS ([MESH_DNS.md](../../../MESH_DNS.md)).

The deployed digests and their sources are in [delivery status](../../agile/DELIVERY_STATUS.md#deployed-images).

## Rollout steps

Each step ran inside the lifecycle wrapper: a traffic watch over 8 paths (same node, cross node and cross cluster from
each cluster, and an unregistered caller per cluster), node clock bounds before and after, and a per-request join to
the ztunnel logs. The folders under [rollouts/](rollouts/) keep the event output, the exit line and the join summary.
The full traffic and log files stay in the review area.

| Step | Event (UTC) | Requests proven over mTLS | Allowed requests failed | Denied caller seen by a ztunnel |
|---|---|---|---|---|
| 1 CMTC controller and node agent, cmtc-a | 16:17:54–16:18:18 | 4411 | 0 | 0 |
| 1 same, cmtc-b | 16:21:09–16:21:34 | 4380 | 0 | 0 |
| 2 SPIRE node agent, cmtc-a | 16:24:30–16:24:49 | 5270 | 0 | 0 |
| 2 same, cmtc-b | 16:29:27–16:29:50 | 5266 | 0 | 0 |
| 3 SPIRE server, cmtc-a | 16:34:25–16:35:32 | 4195 | 0 | 0 |
| 3 same, cmtc-b | 16:39:45–16:40:53 | 6146 | 0 | 0 |
| 4 ztunnel, cmtc-a and each cmtc-b node | 16:45:17–16:56:07 | not joined (below) | — | — |
| 5 Cilium operator, ClusterMesh API server and agents, cmtc-a | 17:02:45–17:03:15 | 4196, and 5547 not attributable | 813 | 4 |
| 5 same, cmtc-b | 17:28:44–17:29:15 | 9901 | 649 | 6 |
| Cilium agent a99264f008 (TCP DNS), cmtc-a | 18:48:05–18:48:33 | 10292 | 273 | 6 |
| same, cmtc-b | 18:57:21–18:57:49 | 10267 | 270 | 4 |

- Step 4 replaced the ztunnel Pods. A deleted Pod's log goes with it, so the join found the copied logs did not cover
  the window and refused to judge (`traffic-join.out` in each step 4 folder). Matrix 4, run after step 4, is the proof
  for these images.
- Step 5 on cmtc-a predates the client-socket join (#28): 5547 requests had two candidate connections and were not
  attributed. Its 643 cross-cluster failures (321 from cmtc-a, 322 from cmtc-b) follow the ClusterMesh API server
  restart (#30).
- In the agent restarts (step 5 and the TCP DNS step) every failure falls inside the event window. The denied caller
  reached a ztunnel 4 to 6 times per restart, and ztunnel refused each one (#31).

## Probe matrices

Each matrix probes every allowed path by Pod IP and by Global Service name, and the unregistered callers, on both
clusters. From matrix 6 on, it also probes each server Pod by its own name, and every probe records its client socket.

| Matrix | Window (UTC) | mTLS proven | Dropped by Cilium as expected | Not joined |
|---|---|---|---|---|
| [0 baseline](matrix-0-baseline/join.txt) | 16:10:57–16:11:41 | 48 | 12 | 24 Global-name probes, two or more candidate connections |
| [4 after ztunnel](matrix-4-ztunnel/join.txt) | 16:58:13–16:58:57 | 48 | 12 | 24, same cause |
| [5 after Cilium](matrix-5-cilium/join.txt) | 17:46:03–17:46:47 | 48 | 12 | 24, same cause |
| [6 by name, client socket](matrix-6-by-name/join.txt) | 17:55:32–17:57:31 | 96 | 36 | 0 |
| [7 after the TCP DNS agent](matrix-7-tcp-dns/join.txt) | 19:05:50–19:07:49 | 96 | 36 | 0 |

The 24 rows not joined in matrices 0, 4 and 5 had curl exit 0; the old join could not tell which of several connections
was theirs. Matrix 6 joins every row by the probe's socket.

## DNS

| Run | Folder | Result |
|---|---|---|
| Before the TCP rule, 18:36–18:39 | [dns/before-tcp-bypass/](dns/before-tcp-bypass/) | UDP 6/6 and TCP 0/6 per cluster from enrolled Pods; TCP 2/2 from the unenrolled control; 9/9 negative probes failed |
| After the TCP rule, 18:54–19:04 | [dns/after-tcp-bypass/](dns/after-tcp-bypass/) | UDP 6/6 and TCP 6/6 per cluster; control 2/2; 9/9 negative probes failed, TCP 53 to non-resolvers dropped at `bpf_lxc.c:1630` |
| ztunnel refusals before the rule, 18:25:47 | [dns/tcp-dns-before-fix-20261026T182547Z-ztunnel.txt](dns/tcp-dns-before-fix-20261026T182547Z-ztunnel.txt) | 4 refusals, one per enrolled client |
| BusyBox short name | [dns/nslookup-short-name-20261026T182625Z.txt](dns/nslookup-short-name-20261026T182625Z.txt) | NXDOMAIN on enrolled and unenrolled Pods; the full name resolves |

The first DNS probes (18:13–18:16, top of [dns/](dns/)) used the short name `kubernetes.default` and scored a BusyBox
limit as a failure. They are kept as recorded.

## Repeat

```sh
python3 scripts/evidence/dns_probes.py --cluster cmtc-a --out <dir> positive
python3 scripts/evidence/dns_probes.py --cluster cmtc-a --out <dir> negative
bash scripts/evidence/run_mtls_matrix.sh <dir>
```
