# Native policy transition source evidence

This profile qualifies Cilium source `8bb97137fcc92b935171d60e59d7fb8a93714bd8` on Linux ARM64. It does not qualify a deployed image.

The final functional race run passes 403 top-level tests and 1691 subtests. The lockdebug run passes 27 top-level tests and 52 subtests. No selected case fails or skips. Vet passes. Required lint reports zero issues.

`full.sh`, `lockdebug.sh` and `lint.sh` retain the actual one-command invocations. Each script runs its suite automatically. The functional runner owns an isolated etcd container and removes its exact container ID on exit. It does not use a lab node or change cluster objects. Recorded paths and outputs belong to this run; review them before reproduction.

The first three full logs and first lockdebug log retain failed attempts. The final logs record the corrected fixtures and passing suites. The summary contains byte hashes. Gzip preserves the raw bytes.

These checks prove source behavior for native policy withdrawal and typed original-owner draining. They do not prove kernel policy-map reachability, mandatory capture, restore quarantine or workload TLS. See [the current guide](../../../LOCAL_NATIVE_POLICY_TRANSITIONS.md) and [delivery status](../../agile/DELIVERY_STATUS.md).
