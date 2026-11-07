# ztunnel stopped renewing workload certificates after host sleep, 2026-11-04 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Result: from 2026-11-04T08:37Z, every allowed connection on both clusters failed (curl 52 and 56). Denied traffic
stayed denied. Each worker's ztunnel kept handing out workload certificates that had expired at 08:37:03Z to
08:38:11Z, and still reported them `Available` at 09:03Z. The cause is in ztunnel (fork `68c0282`, and upstream
istio/ztunnel at `c95d433f0`): it schedules each certificate refresh on the monotonic clock through a mapping to the
wall clock that is fixed when ztunnel starts. In the lab VM the monotonic clock is 95.77 h behind the wall clock
since the ztunnels started, so each refresh is due about 95.77 h after the certificate it replaces.

State: **measured** (this record). The outage ended on 2026-11-07 at 02:48Z, when the fixed ztunnel ran on both
clusters ([deployment and qualification](#deployment-and-qualification-2026-11-07)). The fix is **not yet qualified
across a host sleep**.

## What failed

- The [R1 drill on cmtc-a](../cert-rotation-drills-20261104/R1-cmtc-a/README.md), 08:43:34Z to 08:46:03Z: 149 of 149
  probes failed on each of the 12 allowed paths, 0 of 75 answered on each denied path. ztunnel logged
  `no approved direct issuer for domain cmtc-a.mesh.example` for the connections it refused.
- The ztunnel certificate cache on each worker ([config_dump-cmtc-a-worker.json](config_dump-cmtc-a-worker.json),
  [config_dump-cmtc-b-worker.json](config_dump-cmtc-b-worker.json), read 09:03Z; public certificates only):

  | Node | Identity | State | Valid from | Expires |
  |---|---|---|---|---|
  | cmtc-a-worker | `mesh-client` | Available | 08:35:02Z | 08:37:12Z |
  | cmtc-a-worker | `rebel-base` | Available | 08:34:53Z | 08:37:03Z |
  | cmtc-b-worker | `mesh-client` | Available | 08:36:01Z | 08:38:11Z |
  | cmtc-b-worker | `rebel-base` | Available | 08:35:31Z | 08:37:41Z |

- The SPIRE agents (healthy on all four nodes), the SPIRE entries (present, unchanged, TTL 120 s) and the SPIRE
  servers (no errors after 08:20Z) were checked and are not the cause. The last `Fetching PID for workload UID` in each
  worker's ztunnel log is at 08:35:47Z (cmtc-a) and 08:36:47Z (cmtc-b): ztunnel asked for no certificate after that.
- The [matrix at 08:35-08:39Z](../lab-health-20261104/matrix-0840/join.txt) passed (96 of 96) because each cluster's
  allowed probes ran within 5 s of the first certificate fetch (cmtc-a 08:35:47-08:35:51Z, cmtc-b 08:36:47-08:36:51Z),
  inside the certificate's 130 s life. A matrix that short cannot detect a refresh that never happens.

## Why ztunnel did not refresh

The code, at ztunnel fork `68c0282` (`src/identity/manager.rs`, `src/time.rs`):

1. `SecretManager::new_with_client` builds one `time::Converter`, which stores an `(Instant, SystemTime)` pair taken
   at start-up. `system_time_to_instant(t)` returns `start_instant + (t - start_system_time)`.
2. After each fetch the worker schedules the refresh at `time_conv.system_time_to_instant(certs.refresh_at())`, the
   certificate's half-life in wall-clock time mapped to an `Instant`, and sleeps until then with
   `tokio::time::sleep_until` (manager.rs lines 463 and 485).
3. A cached `Available` certificate is returned to every caller without an expiry check (`start_fetch_key`, line 664).

`Instant` is `CLOCK_MONOTONIC`. In the Colima VM, the monotonic clock does not advance while the host sleeps; the wall
clock does. Each sleep makes the fixed mapping wrong by the time slept, and the error adds up. Measured on the four
nodes ([clocks.txt](clocks.txt), [drift.txt](drift.txt)):

| ztunnel Pod | Started (kubelet, wall clock) | Start by the monotonic clock | Wall clock ahead by |
|---|---|---|---|
| cmtc-a-worker `ztunnel-cilium-5l4kd` | 2026-10-27T19:14:53Z | 2026-10-31T19:01:04.75Z | 344,771.75 s (95.77 h) |
| cmtc-a-control-plane `ztunnel-cilium-fg2qr` | 2026-10-27T19:16:04Z | 2026-10-31T19:02:15.60Z | 344,771.60 s |
| cmtc-b-worker `ztunnel-cilium-rxmwb` | 2026-10-27T19:05:46Z | 2026-10-31T18:51:57.55Z | 344,771.55 s |
| cmtc-b-control-plane `ztunnel-cilium-w6hrb` | 2026-10-27T19:08:16Z | 2026-10-31T18:54:27.42Z | 344,771.42 s |

"Start by the monotonic clock" is `btime + starttime / CLK_TCK` from `/proc`; in this VM `/proc/uptime` equals the
monotonic clock, so the guest does not count the host's sleep as suspend. A certificate fetched at 08:35:02Z has its
half-life at 08:36:07Z; the fixed mapping puts that at an `Instant` 95.77 h later. The certificate expired at
08:37:12Z, and ztunnel kept returning it.

Production nodes do not sleep, but the same error follows any wall-clock step against the monotonic clock: a VM pause
or live migration, or an NTP step. The longer ztunnel runs, the more such steps it collects, because the mapping is
never taken again. Upstream istio/ztunnel (`c95d433f0`, 2026-09-22) has the same code; no upstream issue was found
(`gh search issues --repo istio/ztunnel` for "certificate refresh clock", "suspend certificate",
"certificate expired not rotated").

Not determined: why the fixture workloads' certificates were fetched again at 08:35Z rather than kept from before.

## Fix

ztunnel fork commits `d5f24b5` ("identity: schedule certificate refreshes by the wall clock", on `68c0282`) and
`a545c3a` ("identity: decide on the certificate value that is marked seen", from the review below), draft PR
ephico2real2/ztunnel#2. State: **implemented, tested and deployed**; traffic-qualified after a restart, not yet across
a host sleep ([deployment and qualification](#deployment-and-qualification-2026-11-07)).

- `time::WallClock` reads the wall clock at each conversion (`SystemTime::now()` in production; tests derive it from
  Tokio's paused clock and can step it without moving the monotonic clock).
- The worker schedules each refresh from the certificate's wall-clock half-life, keeps that due time, and compares the
  two clocks every 5 s (`CLOCK_CHECK_INTERVAL`). After a jump of 1 s or more (`CLOCK_JUMP_THRESHOLD`) it reschedules
  every Background refresh from its wall-clock due time and logs `wall clock moved ahead of the monotonic clock`.
  After a host wake, an overdue refresh therefore starts within 5 s.
- An expired cached certificate is never returned: the caller waits for a new fetch, and gets an error if the fetch
  fails, instead of an expired certificate.
- New tests: `test_refresh_follows_wall_clock_jump` and `test_expired_certificate_is_not_returned`
  (`src/identity/manager.rs`). Each fails when its half of the fix is removed (mutation runs below).

Tests, 2026-11-04, in `rust:1.90.0` (`sha256:e227f20e…726c`) on the lab's Colima VM, limited to 6 GiB and 3 CPUs, on
a copy of the fork at `d5f24b5`. The 4 GiB podman VM could not compile the test crate (rustc killed with signal 9),
and the fork's `Rust Related Checks` did not start for the push (no check run after 15 minutes; the cause was found
later: [GitHub had stopped Actions on the fork](../fork-ci-20261107/README.md)).

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | passes |
| `cargo clippy --lib --tests --benches --bins -- -D warnings` | passes |
| `cargo test --lib -- identity:: time::` | 62 passed, 0 failed, including both new tests |
| `cargo test --lib -- --skip inpod::` | 526 passed, 0 failed, 1 ignored |
| `cargo test --lib -- inpod::` | 12 passed, 25 failed (`assertion failed: lo_up`: they set up network namespaces, which needs privileges this container does not have); the same 25 fail at `68c0282` |
| Mutation: no rescheduling after a jump | `test_refresh_follows_wall_clock_jump` fails |
| Mutation: no expiry check in `start_fetch_key` | `test_expired_certificate_is_not_returned` fails |

Not run here: the integration tests (`--tests --benches --bins`), which CI runs with `sudo` for the same namespace
reason. CI ran them on 2026-11-07 ([below](#deployment-and-qualification-2026-11-07)).

### Review of `d5f24b5`

A second reviewer (OB2, Fable 5.1) checked six claims by reading the code and by running a model of the scheduler: the
same `tokio` 1.53.1 and `keyed_priority_queue` 0.4.2 as `Cargo.lock`, `src/time.rs` unchanged and the
`Worker::run` scheduling lifted from the commit; 10 cases passed ([review-harness](review-harness/src/lib.rs), [run3.log](review-harness/run3.log)). The real test crate could not be built on that
machine (no `protoc`). Results:

- No blocking finding. The refresh after a forward jump starts at the next 5 s check; without a jump the refresh time
  equals that of `68c0282` (the arithmetic is the same); an expired certificate causes one fetch per key, not one per
  caller, and no wait without an end; backward steps and very large jumps do not panic.
- Finding, fixed in `a545c3a`: `start_fetch_key` checked the cached value for expiry and then marked the channel
  seen in a second read. A refresh sent between the two reads was marked seen too, so the caller waited for the
  redundant fetch it had just requested (one extra fetch, one fetch round trip of delay). The decision now reads the
  value it marks seen, and a valid cached value is marked unseen again (`Receiver::mark_changed`, tokio 1.53.1
  `sync/watch.rs:758`), so `wait()` returns it at once as before. The race cannot be forced in the real function; the
  reviewer showed it at the level of the watch channel.
- Also in `a545c3a`: the expired branch logs at `debug` (it runs once per caller until the new certificate arrives),
  and the comment on the due-time map says that it is used only while a refresh's priority is Background.
- Not covered by design: wall-clock steps each under 1 s (`CLOCK_JUMP_THRESHOLD`) are not rescheduled; NTP slew is at
  most 500 ppm, 2.5 ms per 5 s check.

Tests of `a545c3a`, 2026-11-04 09:46-09:51Z, the same container and limits ([run-review.sh](tests/run-review.sh),
[test-review-vm.txt](tests/test-review-vm.txt)):

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | passes |
| `cargo clippy --lib --tests --benches --bins -- -D warnings` | passes |
| `cargo test --lib -- identity:: time::` | 62 passed, 0 failed |
| `cargo test --lib -- --skip inpod::` | 526 passed, 0 failed, 1 ignored |
| Mutation: no rescheduling after a jump | `test_refresh_follows_wall_clock_jump` fails |
| Mutation: an expired cached certificate is returned (as at `68c0282`) | `test_expired_certificate_is_not_returned` fails |

## Deployment and qualification, 2026-11-07

Result: the fixed ztunnel runs on both clusters, and allowed traffic is proven over mTLS again. This does not yet show
that the fix survives a host sleep ([what this does not show](#what-this-does-not-show)).

**Image.** `ghcr.io/ephico2real2/cmtc-ztunnel@sha256:8705a64e73a63be66ae91d058b5082f338eaa6a9a111322ab6a026c85d1b43fa`,
built from `a545c3a` by fork run `42329168256` ([lock](rollout-20261107/images.lock.json)). The registry reports the
same digest, for linux/amd64 and linux/arm64. The build started 2 days after the first push because
[GitHub had stopped Actions on the fork](../fork-ci-20261107/README.md).

**CI on the fix.** Fork commit `71951b7` has `a545c3a`'s source and only workflow changes after it.

| Run | Result |
|---|---|
| `Rust Related Checks` `42329199245` | success: lint, and `sudo cargo test --benches --tests --bins`, including the `inpod` tests (37 passed; 25 of them fail in this record's unprivileged container) and both new tests ([extract](rollout-20261107/ci-rust-checks-71951b7-extract.txt)). Cargo stops at the first failed target, so the step's success covers every target; the log read here ends about 32 s before the step ended, so no total is given |
| `Image CI Build` `42329199211` | success: four release binaries with `-D warnings` (amd64, arm64; aws-lc, boring); the Quay push is skipped on a fork |
| `E2E Tests` `42329199208` | skipped on a fork. It needs the Quay image, so this fix has no upstream E2E result |

**Rollout.** One cluster at a time, with `cilium_adopt.py` and `replace_ztunnel.py`. The image values came from
`prepare.py` on the committed lock ([values](rollout-20261107/cilium-image-values-0cff841.json)), not from the
[older file](../cert-rotation-drills-20261104/README.md#helm-drift-check-for-the-negative-drills).

| Step | cmtc-b | cmtc-a |
|---|---|---|
| Plan | [2 changes](rollout-20261107/cmtc-b-plan-new-ztunnel.txt): the image and the template generation | [2 changes](rollout-20261107/cmtc-a-plan-new-ztunnel.txt): the same |
| Helm upgrade | revision 14, 02:34:58Z; [no Pod changed](rollout-20261107/cmtc-b-upgrade.txt) | revision 13, 02:48:04Z; [no Pod changed](rollout-20261107/cmtc-a-upgrade.txt) |
| Pods replaced, worker first | [02:35:12Z to 02:35:20Z](rollout-20261107/cmtc-b-replace.jsonl) | [02:48:26Z to 02:48:34Z](rollout-20261107/cmtc-a-replace.jsonl) |
| Other Pods | [only ztunnel changed](rollout-20261107/cmtc-b-pods-after-replace.txt) | [only ztunnel changed](rollout-20261107/cmtc-a-pods-after-replace.txt) |

**Renewal on cmtc-b, 02:36:05Z to 02:47:20Z** ([rounds](rollout-20261107/cmtc-b-renewal/rounds.txt),
[script](rollout-20261107/renewal-probes.sh)). Seven rounds of same-cluster probes: 168 of 168 allowed probes answered
and 126 of 126 denied probes got no answer. Each round's certificate cache held a new certificate: `rebel-base` was
valid from 02:36:00Z in round 1 and from 02:46:21Z in round 7. Cross-cluster paths were not probed, because cmtc-a
still ran the old build. These probes check the answers only; the matrix below proves mTLS from the ztunnel logs.

**Matrix, 02:51:21Z to 02:53:21Z** ([join](matrix-20261107/join.txt)): 96 proven over mTLS, 0 unanswered, 36 dropped by
Cilium (policy denied), 0 failed, in all scopes on both clusters. It started 154 s after the first certificate fetch
([script](rollout-20261107/matrix-after-one-life.sh)), so it does not have the blind spot of the 08:35Z matrix.
`scripts/evidence/run_mtls_matrix.sh` now does this itself.

### What this does not show

- **The fix across a host sleep.** The outage came from a clock mapping that is taken when ztunnel starts. A new Pod
  takes a new mapping, so the old build would also pass these tests until the host next sleeps. The last host wake
  before this rollout was 2026-11-05 22:57Z (`pmset -g log`), and at 02:55Z the four new Pods had logged no clock jump.
  The fix is proven across a sleep only when, after the next host sleep, each ztunnel logs
  `wall clock moved ahead of the monotonic clock` and allowed traffic is still proven.
- **Protection of a workload.** This record covers the fixture's probe paths only.
