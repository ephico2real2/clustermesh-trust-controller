# SPIRE stream error source qualification

Source `75843515d549f7928d080801ac3f7e4344f572eb` makes the first delegated SVID stream result authoritative for one request. An error cannot be ignored while waiting for a later certificate on that request. A fresh attested request can recover.

The tests cover explicit empty responses, permission and availability errors, a true pending timeout, process-binding release and fresh-request recovery. Error-first responses reject before bundle fetch. A timeout remains distinct from credential absence and policy denial.

The Linux ARM64 profile passes 518 library, 20 direct and 30 namespace tests. Two diagnostic example tests also pass. No case in those full sets fails or is ignored. Format and strict Clippy pass. `full.sh` records the single automatic invocation.

The raw log contains one NUL byte from namespace subprocess output. Gzip preserves the original bytes. Child-process filtered counts do not replace the final full-suite counts. File hashes are in the summary.

No replacement image, active proxy or runtime withdrawal result follows from these tests. The next fixture needs a still-authorized control workload and explicit empty/unusable target SVID evidence. Delegate permission failure or timeout cannot substitute. See [registration design](../../../SPIRE_REGISTRATION_DESIGN.md) and [current status](../../agile/DELIVERY_STATUS.md).
