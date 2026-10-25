# Native policy-map reachability evidence

Cilium source `07722a595a` passes the real IPv4 policy-map fixture and the broader ARM64 functional/race/vet profile. The affected lockdebug profile also passes. Lint reports zero issues. Read [the machine-readable summary](summary.json) for exact selected test counts and raw log hashes.

The first six kernel attempts remain as diagnostics. The first two used the static test header before generated node configuration. Later attempts exposed missing Hive map defaults, an invalid zero-capacity fixture, and incorrect expected program-to-map references. The fifth attempt reran unchanged code because a proposed patch did not apply. The seventh kernel run passes after those defects were corrected. The full profiles include their original Go JSON events; decompress each `.jsonl.gz` to inspect them.

The general profile retains one skipped upstream standalone verifier complexity benchmark. That skip is not proof. The targeted kernel case and affected lockdebug profile have no selected skips. These source tests do not prove mandatory traffic capture or end-to-end mTLS. The deployed Cilium image remains older; the compatibility guard remains closed.
