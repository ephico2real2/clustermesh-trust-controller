# Both labs after six unattended days, 2026-11-04 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

> **Correction (2026-11-04T09:30Z).** The first sentence below covers only the credentials in the table (ADS server,
> origin session, ClusterMesh, SPIRE CA). It did not check ztunnel's workload certificates, and those did not renew:
> from 08:37Z every allowed connection failed. See [ztunnel certificate refresh](../ztunnel-cert-refresh-20261104/README.md).

Result: from the last change (2026-10-28T19:23Z) to this check (2026-11-04T08:33Z), every scheduled certificate
renewal on both clusters completed in place, without a Cilium agent or ztunnel restart. Each of the 9 peer
withdrawals and all 2,935 issuer-profile session closes came within 16 s of a host sleep or wake transition. The matrix
after the check: 96 of 96 allowed probes proven over mTLS, 36 of 36 unregistered probes dropped, 0 failed.

State: **measured** (this check). Image and sources: unchanged since
[ads-fix-rollout](../cert-rotation-drills-20261028/ads-fix-rollout/README.md) (Cilium fork `c84f7d0741`, agent
`cilium-dev@sha256:369090126600…dafa60`, cmtc-b Helm revision 13, cmtc-a revision 12).

## How the data was read

- The kubeconfig `/private/tmp/cmtc-a-b-20261024.kubeconfig` was gone (last used 2026-10-28T19:23Z). It was written
  again with `kind get kubeconfig --name cmtc-a` and `--name cmtc-b` through the `colima-cmtc-cilium` Docker
  context, then merged with `kubectl config view --flatten`, file mode 600, not printed. Both kube-system UIDs
  matched the pinned values (cmtc-a `bb7182c7-…`, cmtc-b `f2687af6-…`).
- Sources: Pod status, cert-manager Certificate status, the Cilium agent and ztunnel logs the kubelet keeps (from
  2026-10-30 to 2026-11-01 onward, after rotation), the SPIRE server, `local_authority.py show`, a TLS handshake
  to each node's ADS server, and the host's power log (`pmset -g log`).

## Renewals completed in place

| Credential | What renewed | Agent or ztunnel restarts |
|---|---|---|
| ztunnel ADS server certificate | cmtc-a revision 5 to 11, cmtc-b revision 6 to 12 (from the R3 drills). Each agent logged `Keypair updated` daily (2026-11-01, 11-02, 11-03; 3 in its kept log), 0 `Keypair update failed`. At 08:34Z every node served the current revision to a new handshake | 0 |
| Origin client certificate (`ztunnel-origin-reader`) and the peer's server leaf | Each agent: 4 `Direct-origin transport refreshed in place` (about 2026-11-01 15:18-15:22Z, 11-02 03:07Z, 11-03 11:54Z, 11-03 14:02-14:04Z) | 0 |
| ClusterMesh certificates | Server cert cmtc-a revision 18, cmtc-b revision 19; admin, local and remote 16 and 17 | 0 |
| SPIRE X.509 CA | Active CAs `99e44fde…` (cmtc-a) and `11924811…` (cmtc-b), both to 2026-11-05T07:19Z; the previous CAs are kept to 12:05Z ([spire-authorities-0840.json](spire-authorities-0840.json)) | 0 |

The agents run since 2026-10-28 18:50Z to 19:04Z and the ztunnels since 2026-10-27, all with 0 restarts.

## Host sleep: the cause of every withdrawal and session close

The labs run in a Colima VM on a laptop. From 2026-10-30 to 2026-11-04 the host log has 299 sleeps, 304 wakes and 295
dark wakes, and one hibernation from 2026-11-03T22:07:38Z to 2026-11-04T07:19:34Z (9 h 12 min). The VM stops while
the host sleeps, and its clocks jump forward at the wake.

- **Peer withdrawals.** 9 `event=withdrawn` lines on the 4 agents, at 5 times: 2026-11-01 02:26:11Z, 11-01 23:19:35Z, 11-02
  05:53:37Z, 11-02 09:38:22Z, 11-04 07:19:39Z. Each was 0 to 10 s after a host wake or dark wake, and the peer was
  projected again.
- **Issuer-profile session closes.** The agent closes the ztunnel issuer-profile session when its API observation
  fails (`pkg/ztunnel/xds/issuer_profile.go:420-428` at `c84f7d0741`: "It is not permission to reuse the last good
  profile"). The 4 agents logged it 2,935 times, every time with `publication lease expired or from future`, and every
  time within 16 s of a host transition (2,901 within 10 s). ztunnel logs the matching `fresh session required`
  and reconnects after a back-off of hundreds of milliseconds.
- **The hibernation.** At 07:19:43-45Z, the SPIRE agents (exit 1) and kvstoremesh (exit 255) of both clusters
  stopped and were restarted by the kubelet. cert-manager's 68 restarts per cluster end with exit 0 (the last at
  07:37:38Z and 07:37:41Z). The SPIRE servers' new active CAs end 24 h after the wake (07:19Z), so the 9 h jump
  skipped the normal prepare-then-activate schedule.
- These are fail-closed reactions to a stopped clock, not renewal failures. A production node does not sleep.
  Nothing measured here shows how long traffic failed after each wake: no probes ran while the host slept.

## Traffic now

[matrix-0840](matrix-0840/join.txt), 08:35:42Z to 08:39:48Z: 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium
(`Policy denied at bpf_lxc.c:2381`), 0 failed.

## Open

- How long workload mTLS takes to recover after a host wake, measured with probes running across a sleep.
- A SPIRE CA activation on the normal schedule after the hibernation (next prepare at about 19:19Z, activation at
  about 03:19Z on 2026-11-05).
