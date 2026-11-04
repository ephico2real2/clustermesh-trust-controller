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

State: **measured** (this record). The fix is in [the fix section](#fix); its deployment and qualification are recorded
there.

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
ephico2real2/ztunnel#2. State: **implemented and unit-tested**; not yet built, deployed or traffic-qualified.

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
and the fork's `Rust Related Checks` did not start for the push (no check run after 15 minutes).

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | passes |
| `cargo clippy --lib --tests --benches --bins -- -D warnings` | passes |
| `cargo test --lib -- identity:: time::` | 62 passed, 0 failed, including both new tests |
| `cargo test --lib -- --skip inpod::` | 526 passed, 0 failed, 1 ignored |
| `cargo test --lib -- inpod::` | 12 passed, 25 failed (`assertion failed: lo_up`: they set up network namespaces, which needs privileges this container does not have); the same 25 fail at `68c0282` |
| Mutation: no rescheduling after a jump | `test_refresh_follows_wall_clock_jump` fails |
| Mutation: no expiry check in `start_fetch_key` | `test_expired_certificate_is_not_returned` fails |

Not run: the integration tests (`--tests --benches --bins`), which CI runs with `sudo` for the same namespace reason.

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
