# Lost ADD ACK recovery source evidence

The candidate retains exact unresolved ADD bindings and waits for the actual queued-send consumer before selecting a native drain owner. Only a correlated typed receipt can retire the selected history. An explicit NACK permits another retained candidate; timeout, malformed receipt and proxy restart retain quarantine.

The ARM64 actual-etcd race profile passes 416 top-level tests and 1,713 subtests, with vet. The affected lockdebug profile passes 40 top-level tests and 74 subtests. Lint reports 0 issues. Rust's real owner/task/socket recovery profile also passes. See [summary](summary.json) and compressed raw logs/commands.

The broader lockdebug attempt fails in unchanged `TestEgressCIDRTCPPort` on a recursive repository read lock. That failure is preserved. The selected affected run does not qualify the full upstream lockdebug suite.

This is source evidence. No new Cilium image is built or deployed. Kernel policy reachability, persistent restore quarantine, mandatory capture and end-to-end workload mTLS remain open.

A separate clean detached checkout of committed Cilium `3985cc135a` passed the full race/vet profile again: 416 top-level tests and 1,713 subtests, with no selected failures or skips. This excludes the unfinished loader candidate. See `full-clean.jsonl.gz` and `full-clean.sh.gz`.
