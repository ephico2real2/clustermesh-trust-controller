# ztunnel pooled transport retirement, 2026-11-07 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

State: **implemented and tested** in ztunnel fork commit `2a1897b` (branch `feat/root-pin-retirement`). **Not deployed**:
the labs run image `8705a64e` (`a545c3a`), which does not have this change. No result on this page qualifies traffic.

## The defect

An allowed connection could fail at a certificate deadline, with or without a rotation. The measurement is in
[the drills of 2026-11-07](../cert-rotation-drills-20261107/README.md): 2 of 13,130 allowed probes failed, and 28 of 28
teardown errors fell in a second that a sampled certificate `notAfter` names.

## The change

This is our change in the ztunnel fork. Upstream ztunnel does not close a transport at a certificate deadline.

| File | Change |
|---|---|
| `src/tls/profile_provider.rs` | `ProfileIo::certificate_deadline()`: the local certificate's end or the verified peer's, whichever is first. `Lease::current_time()`: the verifier clock of a live lease |
| `src/proxy/h2/client.rs` | `ready_to_use()` is false when the deadline is 5 s away or less. `bind_profile()` takes the deadline, so no caller can bind a lease without it |
| `src/proxy/pool.rs`, `src/proxy/outbound.rs` | Read the deadline from the TLS stream and pass it |

The close at the deadline does not change, so a stream in progress still closes there. Pool checkout already drops a
transport that is not ready and opens a new one. A new transport uses the certificate renewed at half of its life.

## Tests

[`tests/run.sh`](tests/run.sh) ran on the lab's Colima VM with rust 1.90.0, on the sources of `2a1897b`. Output:
[`tests/test-vm.txt`](tests/test-vm.txt).

| Check | Result |
|---|---|
| `cargo fmt --check`, `cargo clippy -D warnings` | exit 0, exit 0 |
| Library tests without `inpod::` | 529 passed, 0 failed, 1 ignored |
| Mutation: checkout does not read the deadline | `pooled_transport_takes_no_new_stream_just_before_its_certificate_deadline` fails |
| Mutation: retirement also without a lease | `certificate_deadline_does_not_retire_a_transport_without_a_lease` fails |
| Mutation: the peer's deadline is ignored | `certificate_deadline_is_the_first_of_the_local_and_the_peer_certificate` fails |

Fork CI on `2a1897b`: `Rust Related Checks` `42336135773` succeeded (lint, and `sudo cargo test --benches --tests --bins`;
[extract](tests/ci-rust-checks-2a1897b-extract.txt)). All 3 new tests passed there. The log shows 537 tests `ok`, 37 of
them `inpod`, and 0 `FAILED`. It ends before the step ends, so no total is given. `Image CI Build` `42336135752`
succeeded. `E2E Tests` `42336135782` was skipped on a fork, so this change has no upstream E2E result.

No unit test proves that `new_pool_conn` passes the deadline to a real pool. The pool test fixture has no issuer
profile. The lab soak below is the proof of that path.

## Review

A reviewer on Fable 5.1 read the change. It confirmed that `current_time()` makes the same check as the
`check_current()` it replaced, and that the change does nothing without a lease. It also confirmed that a retired
transport leaves the pool and ends when its streams end. It proposed folding the deadline into `bind_profile`, which
`2a1897b` does.

| Reviewer's point | Decision |
|---|---|
| The server closes at the client's leaf, SPIRE CA, pin or root end, whichever is first. The client reads only its leaf, so a chain that ends first is not seen | Not changed. SPIRE caps an X509-SVID at the end of its parent chain ([`computeX509SVIDLifetime`](https://github.com/spiffe/spire/blob/main/pkg/server/credtemplate/builder.go)). A live chain read at 03:51Z: leaf ends 03:53:43Z, SPIRE CA 2026-11-07T19:20:06Z, intermediate 2027-10-26. The reviewer's fix also moves the local close, which this change must not do |
| If a peer's certificate is 5 s or less from its end, because its renewal is at least 60 s late, each request opens a new connection, one at a time per key, for at most 5 s | Accepted. After that, the handshake with the expired certificate is refused. The cost per handshake was not measured |

## What it does not cover

- A stream still open at the deadline closes. In this lab a long-lived stream lasts at most the 130 s of a certificate.
- A CONNECT response slower than 5 s, or a clock difference above 5 s between two nodes.
- The closes when a workload's Address is published again ([a second reason](../cert-rotation-drills-20261107/README.md#a-second-reason-for-a-connection-to-close)).

## Open

The change needs an image, a rollout, and then the soak and the drills. With the rate of 2 in 13,130 unchanged, a run of
30,000 allowed probes would show 0 failures about 1% of the time, assuming independent failures. At 12 allowed probes
each second that is about 42 minutes.
