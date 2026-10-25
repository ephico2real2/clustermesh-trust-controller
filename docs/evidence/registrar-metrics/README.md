# Registrar metric source tests

Date: 2026-10-25. Status: Linux ARM64 source qualification. **No new image, live collector or workload-mTLS acceptance.**

The primary applied and reviewed a scoped proposal before the user's ownership change. Opus now owns this code and all further implementation. The seven source files remain uncommitted in the primary checkout for Opus to preserve, review and integrate. [The full patch](source.patch) captures tracked and new files. [The source hash manifest](source-sha256.json) matches the tested snapshot.

The instrumentation measures completed registration passes, actual retries, deletion readback, whole-inventory withdrawals and current readback availability/timestamp. It adds an opt-in exact Pod-IP metrics listener on18087. It does not expose the Admin socket, alter its permissions or alias a registration ACK to SPIRE Ready, SVID issuance, TLS, trust consumption or Protected.

[Summary](summary.json):27 top-level/58 total tests pass with race detection, zero failures/skips; vet exits0. The existing actual ten-second retry/readiness/shutdown test ran. New tests exercise lost ACK, retained rows after duplicate-writer refusal, explicit deletion plus absent readback, normal unenrollment, failure/recovery, freshness expiry, cancellation, process reset and bounded labels.

Commands ran in the pinned Go1.27.3 Linux ARM64 Podman toolchain,2CPU/4GiB:

```sh
go test -race -count=1 -timeout=180s -json ./internal/spireregistrar ./cmd/cmtc-spire-registrar
go vet ./internal/spireregistrar ./cmd/cmtc-spire-registrar
```

[Runner](test.sh), [race output](race.jsonl), [vet output](vet.log), [preflight](preflight.log). The original direct repository volume was not visible in the remote VM: its first run selected no tests and failed before finding go.mod. Those outputs remain in [diagnostic-original-mount](diagnostic-original-mount/). A hash-verified source snapshot in the already shared private/tmp directory corrected that fixture. Only the corrected run counts.

Opus must qualify the real component against both existing clusters with one registration writer, collect failure/recovery metric deltas, preserve scrape cluster/node labels, then package and repeat on the exact image. The six new diagnostics do not complete the broader planned SPIRE-readiness or workload-security contracts. No CI or publication ran.
