# Rotation drills on ztunnel build 8705a64e, 2026-11-07 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

State: **measured** (the records below). This build does not meet #47. An allowed connection can fail at any
certificate deadline, with or without a rotation. The sequence stopped at R4. R5 and the negative drills did not run.

Image: `ghcr.io/ephico2real2/cmtc-ztunnel@sha256:8705a64e73a63be66ae91d058b5082f338eaa6a9a111322ab6a026c85d1b43fa`
(ztunnel fork `a545c3a`). The sequence is [`run-positive.sh`](run-positive.sh), and its log is
[`positive.log`](positive.log).

| Record | Event | Window | Allowed probes failed | Withdrawals |
|---|---|---|---|---|
| [R6 on cmtc-a](R6-cmtc-a/README.md) | none | 03:00:06Z to 03:02:45Z | 0 | 0 |
| [R6 on cmtc-b](R6-cmtc-b/README.md) | none | 03:02:45Z to 03:05:23Z | 0 | 0 |
| [R1 on cmtc-a](R1-cmtc-a/README.md) | `ztunnel-origin-reader` renewed | 03:05:23Z to 03:07:58Z | 0 | 0 |
| [R2 on cmtc-a](R2-cmtc-a/README.md) | `ztunnel-membership-writer` renewed | 03:07:58Z to 03:10:32Z | 0 | 0 |
| [R4 on cmtc-a](R4-cmtc-a/README.md) | 4 ClusterMesh API server certificates renewed, 03:10:53Z to 03:11:24Z | 03:10:33Z to 03:13:57Z | **1**, `cmtc-a-crossnode` at 03:13:04.038Z, 99 s after the event | 0 |
| [R6 on cmtc-a, 300 s](R6-cmtc-a-300s/README.md) | none | 03:22:30Z to 03:27:38Z | **1**, `cmtc-a-same` | 0 |

## Why the two probes failed

Each TLS stream of ztunnel closes when a certificate ends: the local certificate or the verified peer, whichever is
first (`ProfileIo::check`, `src/tls/profile_provider.rs`). This close is the fail-closed design. The pool
(`H2ConnectClient::ready_to_use`, `src/proxy/h2/client.rs`) did not read that deadline. It could give a request a
connection that closes a moment later. The request then failed with curl code 56.

[`pool-deadline/measure.py`](pool-deadline/measure.py) samples the workload certificates of all four ztunnels and
compares their `notAfter` times with the error `Error in HBONE connection handshake: ... expired or changed`:

| Window | Traffic | Errors | Errors in a second that a sampled `notAfter` names | Result |
|---|---|---|---|---|
| 03:16:02Z to 03:22:05Z | none | 0 | 0 | [`result-no-traffic.json`](pool-deadline/result-no-traffic.json) |
| 03:22:25Z to 03:28:08Z | the 300 s R6 above | 28 | 28 | [`result-with-traffic.json`](pool-deadline/result-with-traffic.json) |

A random second matches a sampled `notAfter` with a chance of about 0.104 in the second window, so the match is not a
coincidence. The failed `cmtc-a-same` probe is the one `error access` line in
[`errors-with-traffic.txt`](pool-deadline/errors-with-traffic.txt), at 03:26:39.000280Z. The record of the fix is in
[ztunnel pooled transport retirement](../ztunnel-pool-retirement-20261107/README.md).

## A second reason for a connection to close

`errors-with-traffic.txt` also has 5 errors of another kind on `ztunnel-cilium-q6l85`:

| Time | ztunnel | Line |
|---|---|---|
| 03:24:28.506Z | `q6l85` (cmtc-b worker) | 4 errors `native outbound source expired` |
| 03:24:46.810Z | `q6l85` (cmtc-b worker) | 1 error `peer closed connection`, when `vbt5v` (cmtc-b control plane) logged `direct source witness invalidated` |

At those two times the Cilium agent of the same node logged `Enrolled all endpoints in namespace`, and then
`Published effective ztunnel policy`, for `client-worker` at 03:24:28Z. A new Address object for the workload invalidates
the witness of each connection that uses it, and those connections close (`src/state/outbound_source.rs`,
`src/state/source_binding.rs`). The same lines are in the records of R1 and R2, on cmtc-a, at 03:07:56Z and 03:08:17Z.

No probe failed for this reason in these records. A stream in progress at that moment closes. What starts the
enrollment reconcile was not determined.
