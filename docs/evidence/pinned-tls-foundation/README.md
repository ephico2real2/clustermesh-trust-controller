# Pinned workload TLS constructor evidence

Local ARM64 source `ddb255de68cd458945f831cb1ab66f2f3f135d0c`, upstream
`9a17cb0ff35c20977100de3582c1e4435360f618`, builds the isolated constructor
foundation. Read [the root guide](../../../LOCAL_PINNED_TLS_FOUNDATION.md)
for its scope and open production gates.

- `summary.json`, `qualify.sh`, `full.log.gz`: 440 full-suite tests passed,
  zero failed/ignored, format/strict Clippy passed, plus one forced TLS1.2
  rerun with actual negotiated-version assertions.
- `tested-source.patch.gz` (decompress before applying) is the exact pre-commit source tested. Its bytes
  remained unchanged across qualification. Initial compile and typed-error
  assertion failures remain in the compressed diagnostics.
- Build script/logs, clean version output and archive hash identify the
  exact Podman image. The large image archive stays local.
- `loaded-images.json`, four CRI inspections, four version outputs/Pod records
  and `version-job-cleanup.json` prove exact four-node import/execution and
  UID-bound cleanup. The first digest parser failure is preserved; it treated
  a valid synthetic repository@digest as an unqualified raw digest. The final
  parser normalizes both references and checks against CRI configuration and
  repository digest identities.

No live proxy, remote issuer-profile consumer, policy, active-flow withdrawal
or cross-cluster workload mTLS was qualified here. Existing legacy constructor
call sites and the compatibility guard are unchanged. No CI, push or registry
publication occurred.
