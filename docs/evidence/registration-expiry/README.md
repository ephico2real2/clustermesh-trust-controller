# Registration expiry and cleanup checks

This report records local source tests. No candidate image or local deployment is qualified by this report.

SPIRE's registration pruner runs every five minutes. The candidate checks registration expiry when each authorization cache is read. An expired entry cannot authorize itself or its descendants through that cache. An already issued certificate keeps its own validity period. These tests do not prove immediate certificate or connection revocation.

The registrar candidate detects competing registration writers. It can retire the narrowly matched legacy Cilium namespace/service-account entry for an approved identity. Other foreign entries block readiness. The experimental helper still requires the legacy writer to be disabled. The helper does not become the permanent registration owner through this change.

## Results

| Check | Result |
| --- | --- |
| New mismatched-filter cleanup regression before the fix | Fails as expected; exit 1 |
| Registrar package after the fix, with race detection | 16 tests and 28 subtests pass; no failures or skips |
| Initial SPIRE race run across five affected packages | Four packages pass; one size assertion fails |
| Affected authorization-cache race rerun | Passes after the explicit size budget is corrected |
| Vet across five SPIRE packages and the registrar package | Passes |

The new negative test makes a SPIRE list response return a different approved identity from the requested identity. The unfixed helper deletes that registration. The fix validates returned hint, SPIFFE identity and parent filters before cleanup. [The failed run](before.log) and [passing registrar run](after.log) retain the actual output.

The SPIRE candidate adds an eight-byte expiry field to its alias cache record. The existing size assertion expected 72 bytes and observed 80. The corrected test keeps an explicit 80-byte budget and documents the extra field. [The initial failure](spire-race.log) and [affected rerun plus vet](spire-authorized-final.log) remain separate.

## Exact source and commands

[The source manifest](source-results.json) records the base SHAs, nine changed SPIRE files, four changed CMTC files, their hashes and both patch hashes. [The SPIRE patch](spire-qualified-source.patch) and [CMTC patch](cmtc-qualified-source.patch) include the selected source and tests. Other dirty agent files are excluded.

The checks used host Podman, Linux ARM64, two CPUs and a four-GiB memory limit. The tool image configuration is `f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529`. The command JSON files record each exact invocation. The runner scripts record cache mounts and package selection. They use machine-local paths; inspect and adapt them before use on another machine.

The tests preserve normal unexpired and non-expiring entries. They cover expired aliases, expired parents, descendants, renewal, source outage, duplicate writers, denied updates, lost acknowledgments and readiness. The existing SVID service package also passes its race tests in the initial run.

Keep image build, exact running-image verification, actual SPIRE authorization/issuance, restart and recovery checks open. No signer state, Admin socket permission or live cluster resource changed during these tests.
