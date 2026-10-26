# Incident: workload mTLS failed closed after a SPIRE CA rotation (2026-10-25T23:55Z)

**Result first.** Workload mTLS on `kind-cmtc-a` and `kind-cmtc-b` failed closed from 23:55Z on 2026-10-25: every
HBONE handshake failed with `no approved direct issuer`. The operator authorized a one-time re-bootstrap onto a
generation-2 issuer approval. It finished at 03:01Z on 2026-10-26.

The first matrix after it (03:03:47Z) still failed. The re-bootstrap had replaced every ztunnel Pod without
registering the new Pods' SPIRE delegate entries, so ztunnel had no workload certificates. That omission was mine. The
entries were registered at 03:06:48Z. The matrix result is in [Restoration](#restoration).

The generation-2 approval holds until SPIRE activates its next CA, at about 11:55Z. A rotation without a reset must
be qualified before then. No second reset is authorized.

This record is written from the operator's side: what they saw, when, what I (Claude Code, session `b744973a`) told
them, and which of those statements were wrong.

## Timeline (UTC)

| Time | What happened | Source |
| --- | --- | --- |
| 10-25 03:55:11 | SPIRE (cmtc-a) issues X509 CA slot A, valid to 10-26 03:55:11. cmtc-b is about 30 s later. | SPIRE server log (`issued_at` of slot A) |
| 10-25 04:41:46 | `cmtc-issuer-approval-g1` is created (cmtc-b 04:42:24). It pins only slot A's signing key (SPKI cmtc-a `d78e77ae…`, cmtc-b `5135ed8c…`). | ConfigMap `creationTimestamp` |
| 10-25 08:13:40 | The SPIRE server logs `X509 CA activated` for slot A. | SPIRE server log, cmtc-a |
| 10-25 15:55:19 | SPIRE logs `X509 CA prepared` for slot B, valid to 10-26 15:55:19. No CMTC component reads it. | SPIRE server log, cmtc-a |
| 10-25 23:55:17 | SPIRE activates slot B (cmtc-b 23:55:44). Every ztunnel handshake now fails: `no approved direct issuer for domain cmtc-<x>.mesh.example`. | ztunnel logs; `src/tls/domain_anchors.rs:552-565` |
| 10-25 23:58:50 | I commit `2b86420`, a delivery status that says enrolled traffic "runs over workload mTLS", "read from both cluster APIs at 23:56Z". It was read from readiness, not from traffic. Traffic had already failed. | `git log`; `docs/agile/DELIVERY_STATUS.md` at `2b86420` |
| 10-26 00:02:22 | The operator asks why the approval lasts only 4 hours. I answer that it expires at 03:55:11Z and that "I expect workload mTLS on both labs to stop then". **Wrong: it had stopped 7 minutes earlier.** | transcript |
| 10-26 00:02:26 | I ask the operator to choose an expiry plan. Every option assumes the labs still work. One option is "Re-bootstrap with long horizon … the 30-day maximum". **Wrong: an approval cannot outlive the CA it pins.** Its expiry is the earliest expiry of its roots, parents and issuers (`internal/trustprofile/profile.go:345,399,423`), here 15:55:19Z. | transcript |
| 10-26 ~00:10 | The DNS-fix agent reports the live outage as the blocker of its live tests, with the SPKI mismatch. | `review/dns-fix/REPORT.md` |
| 10-26 00:10:49 | The operator chooses "One-time re-bootstrap now", on the wrong premise. | transcript |
| 10-26 00:12:09 | I retract both claims and ask again: the outage started at 23:55Z, and a re-bootstrap restores mTLS only until about 11:55Z, when SPIRE activates its next CA. | transcript |
| 10-26 00:12:21 | The operator chooses "Re-bootstrap now, fix by 11:55Z". This authorizes one exception to the never-reset rule. | transcript |
| 10-26 00:16:11 | The usage limit stops the session. I stop the three background agents and release both leases. Nothing changed on the labs. | transcript |
| 10-26 02:37 | The operator resumes the session. | transcript |
| 10-26 02:47 | Both producers publish generation 2 from `cmtc-issuer-approval-g2`, with the slot-B keys. This took three attempts; the helper was fixed in `f795dbf`, `b562673` and `41afb41`. | `advance-output-attempt{1,2,3}.txt` |
| 10-26 02:54–03:01 | Node re-bootstrap, one node at a time, both clusters. | [operations](#what-was-done) |

## What the operator saw

- A status report, pushed at 23:58:50Z, that said mTLS worked while it had already failed.
- An answer at 00:02Z that put the failure 4 hours in the future.
- A choice with three options, all built on that wrong premise, one of them impossible.
- A corrected question 10 minutes later.
- Then a session stop at the usage limit, with the labs still down. Recovery waited until the operator resumed at
  02:37Z.

## Root cause

1. **The approval pinned one CA, not the CA that SPIRE was about to use.** SPIRE's `ca_ttl` is 24 h. SPIRE prepares the
   next CA at half its life and activates it at 5/6 of its life. The approval schema allows two issuers per cluster
   (`internal/trustprofile/profile.go:352`), but nothing added the prepared CA.
2. **The approval object's UID was pinned in three places.** A new approval is a new immutable ConfigMap with a new UID.
   The UID is pinned in:
   - the controller arguments (`--issuer-profile-source{,-uid}`);
   - the node `pins.json` read by the Cilium agent (`pkg/ztunnel/xds/issuer_profile.go:87,133`);
   - the ztunnel checkpoint origin (`src/tls/profile_checkpoint.rs:32-58`, rejected at `:213-216`).

   So no rotation without a reset existed.
3. **No signal warned before 23:55Z.** `observability/prometheus/alerts.yaml` has 9 alerts. Two cover the issuer
   profile: `CMTCIssuerProfileLeaseExpired` and `CMTCIssuerProfileSourceStale`. None compares the approved issuers with
   SPIRE's active and prepared CAs, and none measures the time to the next activation.

Linkerd, Istio and SPIRE pin content (trust anchors) and overlap old and new before they switch:
- [Linkerd manual rotation](https://linkerd.io/2/tasks/manually-rotating-control-plane-tls-credentials/);
- [SPIRE server `prepare` / `activate`](https://spiffe.io/docs/latest/deploying/spire_server/);
- Istio's combined `root-cert.pem`.

## My errors

| Error | Rule broken | Correction |
| --- | --- | --- |
| Reported "runs over workload mTLS" from cluster readiness at 23:56Z. | Never infer traffic protection from readiness. | Status is rewritten from this record and the matrix below. |
| Put the failure at 03:55Z without reading SPIRE's CA times. | Empirical data only. | Retracted at 00:12:09Z. |
| Offered a 30-day approval. | Verify the premise (the expiry bound in `profile.go`). | Retracted at 00:12:09Z. |
| Replaced every ztunnel Pod without registering the new Pods' exact SPIRE delegate entries. The established rollout tool (`review/rollout_ztunnel.py`, `register_delegate`) does this for every replacement. | Read the existing procedure in full before writing a new one. | [`register_proxies.py`](register_proxies.py) at 03:06:48Z; log [`delegate-entries.jsonl`](delegate-entries.jsonl). |

## Decisions

| Time | Decision | By |
| --- | --- | --- |
| 00:12:21 | One exception to the never-reset rule: a generation-2 approval and a one-time checkpoint re-bootstrap on all four nodes. No second reset without the operator. | operator |
| 00:12:21 | Build the rotation without a reset (source succession, SPIRE's prepared CA as second issuer) before 11:55Z. | operator |

## What was done

The operations are in [`rebootstrap.py`](rebootstrap.py). Its logs are [`cmtc-a/operations.log`](cmtc-a/operations.log)
and [`cmtc-b/operations.log`](cmtc-b/operations.log). Nothing was deleted. The generation-1 pins and checkpoint files
are on each node, in `/etc/cmtc/ztunnel-issuer-pins.g1-preserved-<ts>/` and
`/var/lib/cmtc/ztunnel-issuer-checkpoint.g1-preserved-<ts>/`. The issuer ledger is backed up as
`~/.local/share/cmtc-issuer-profile/live-a-b.g1-ledger-preserved-20261026T024240Z.json`.

Per cluster:

1. Add `cmtc-issuer-approval-g2` to the Cilium agent's issuer Role.
2. Set `ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP=true` in the ztunnel DaemonSet template. The DaemonSet is `OnDelete`, so no
   Pod restarts.
3. Per node, worker first:
   1. Preserve the g1 `pins.json` and install the g2 pins.
   2. Restart the Cilium agent.
   3. Require that the agent stops rejecting the publication. Before: every issuer-profile line was
      `API observation unavailable … publication origin/floor mismatch`. After: 0 failures in 85–95 lines over 45 s,
      on every node.
   4. Stop the ztunnel Pod that holds the g1 state.
   5. Move the g1 marker and state into the preserved directory.
   6. Wait for kubelet to restart the bootstrap-mode container in place. It is never deleted at this point: ztunnel
      writes its marker before its first state (`profile_checkpoint.rs:759-771`), so a kill between the two leaves a
      store that neither open mode accepts.
   7. Require a g2 checkpoint (generation 2, `Validated`).
4. Set bootstrap back to `false`. Restart each ztunnel from its existing checkpoint, and require the same origin and a
   sequence that does not go back.
5. Remove g1 from the Cilium Role.

| Node | g2 checkpoint at | Restart from checkpoint, sequence |
| --- | --- | --- |
| cmtc-a-worker | 02:56:10 | 6061 → 6062 |
| cmtc-a-control-plane | 02:57:45 | 6062 → 6063 |
| cmtc-b-worker | 02:59:52 | 6088 → 6089 |
| cmtc-b-control-plane | 03:01:28 | 6089 → 6090 |

## Restoration

Measured with [`matrix/run_matrix.sh`](matrix/run_matrix.sh), the same probe scopes as the
[G1 traffic record](../g1-destination-sources/README.md), and the per-connection join of
[the proof guide](../g1-destination-sources/PROVE_MTLS_FROM_ZTUNNEL_LOGS.md).

| Run (UTC) | Result | Record |
| --- | --- | --- |
| 03:02:36 | Refused before any probe: I passed a new directory as the runner's `--out`. The runner needs its fixture state there (`Namespace incarnation mismatch`). | `matrix/refused-attempt-1/` |
| 03:03:47 | Every allowed probe failed: `curl: (56) Connection reset by peer`. ztunnel had no workload certificates: SPIRE refused the new ztunnel Pods with `No identity issued`. Negatives were denied, 6/6 per cluster. | `matrix/failed-attempt-2/` |
| 03:06:48 | Delegate entries registered for the 4 ztunnel Pods. | `delegate-entries.jsonl` |
| 03:09:41–03:10:29 | **48 of 48 allowed Pod-IP probes proven over mTLS.** Every probe is joined to a connection that both ztunnels logged, over HBONE port 15008, with the expected client identity read from the client certificate. 12 of 12 unregistered callers dropped by Cilium (`Policy denied at bpf_lxc.c:2373`). The global service by name fails at DNS (`bpf_lxc.c:1626`), as before. ztunnel logged 0 errors or warnings. | `matrix/join.txt`, `matrix/join.json`, `matrix/ztunnel-view.txt` |

The first join of the third run read a log window that began at the first probe. The join reads each probe from 3 s
before its time, so 25 probes counted as not covered (24 on cmtc-a, 1 on cmtc-b). The narrow extract and its join are kept as
`matrix/*narrow-window*`. The logs were extracted again for 03:09:30–03:10:40Z. `run_matrix.sh` now keeps a 10 s
margin.

The drop captures in `matrix/cilium-drops/` are not the third run's own capture. They are the second run's
900 s capture (headers `for 900s`, coverage 03:03:46.9–03:18:46.0Z, written at 03:18:45Z); its own report in
`matrix/failed-attempt-2/capture.txt` names these files. The second run exited 1 at the log extraction
(`matrix/failed-attempt-2/run.txt`) and left its capture running. The third run wrote its own 240 s capture
into the same directory (coverage 03:09:40–03:13:39Z, `matrix/capture.txt`). The join read it at 03:14:34Z. At
03:18:45Z the second run's capture ended and replaced those files, so the third run's drop files are lost. The
remaining capture covers the third run's whole probe window on the same four nodes. `matrix/join.json` is
regenerated from it: the 62 verdicts are unchanged. 14 verdicts quote drops, and only their arrival stamps changed
(by microseconds), because two monitors timed the same events. `matrix/join.txt` is unchanged. Since commit
`61ca693`, `capture_cilium_drops.sh` refuses a directory that already holds a capture.

This is workload-mTLS traffic qualification for the generation-2 approval. It is not a `Protected` claim. Recovery
after the next SPIRE CA activation (about 11:55Z) is not qualified; that is the rotation fix.
