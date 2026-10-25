# Opus work recovery

The user requested recovery and local commits of all isolated work on 2026-10-25. Claude Code Opus5.5High stopped on its monthly spend limit. The implementation was not complete. Codex now owns continuation. Cursor Grok4.7ExtraHigh reviews the node-name port without source edits.

## Source checkpoints

All four recovery commits use the user's configured identity and include a DCO sign-off. Each isolated worktree was verified clean after its commit. These are WIP checkpoints. They are not releases or evidence of end-to-end workload mTLS.

| Repository | Recovery commit | Local checkout |
| --- | --- | --- |
| cilium | `a7ffbc8c85eeed89d7105704a643633c7d408118` | `/private/tmp/cmtc-opus-final-20261025/cilium` |
| ztunnel | `35a6c9403eb5c00b1b79aafe2851f423cd195540` | `/private/tmp/cmtc-opus-final-20261025/ztunnel` |
| spire | `ff52bdcd8d05f85f893221b604c3113cd47d57ed` | `/private/tmp/cmtc-opus-final-20261025/spire` |
| cmtc | `7a133dc7449173b3e1a15dc6e3b32037ef2b1b91` | `/private/tmp/cmtc-opus-final-20261025/cmtc` |

All four checkpoints are on `feat/opus-mesh-mtls-finalization`. The original base SHAs, complete tracked diffs, untracked file hashes and binary-safe commit patches are retained in the backup manifest. Cilium's incomplete C2 edits are preserved. Its stray dpgen output was moved to `docs/cmtc/recovery/util_generated.go.txt` to avoid adding an unrelated root Go package.

The isolated CMTC dashboard drafts remain historical. They do not replace the qualified primary dashboard sources. The primary registrar source remains at local commit `5ce3db378f72d90d4aba9e3829cba2dfe5850a80`.

## Local backup

Backup directory: `/Users/olasumbo/gitRepos/clustermest-trust-controller/artifacts/recovery/opus-20261025T113157Z`.

Manifest: [manifest.json](/Users/olasumbo/gitRepos/clustermest-trust-controller/artifacts/recovery/opus-20261025T113157Z/manifest.json). Each repository directory contains `tracked.patch`, all original new files and `recovery-commit.patch`.

Archive: [sessions, runners, reviews and test logs](/Users/olasumbo/gitRepos/clustermest-trust-controller/artifacts/recovery/opus-20261025T113157Z/sessions-runners-reviews.tar.gz). SHA-256: `c54fb3a86b56932cf771ed2e2f877734e0ff4f9d6ac82c6d9b169472dca38e71`.

All captured source-file hashes were verified. Every archive member was read successfully. The archive excludes the rebuildable 4GB Go compilation cache. It is a private local artifact and is not staged for publication. The original checkouts and raw logs remain available.

## Evidence and open work

- Cilium C1 run3 passes compilation, generated-config checks, affected race tests (57 top-level/180 total pass,21 integration-dependent skips), vet and48 kernel subtests. Later C2 edits are incomplete and untested.
- ztunnel full-2 passes533 library+20direct+30namespace+2diagnostic tests, with zero failed/ignored, formatting and strict Clippy. Exact-image/live acceptance remains open.
- SPIRE dynamic-role and delegate expiry regressions fail before the checks. Both affected packages pass afterward:17 top-level/151subtests, zero failures/skips, race andvet. Live expiry/recovery remains open.
- Registrar race tests pass16 top-level/28subtests andvet. Live qualification remains open.
- No ztunnel proxy runs in either cluster. Cross-cluster workload mTLS is not yet qualified.

Continue with native Kubernetes Node-name discovery, admission/recovery fixes and actual two-cluster traffic. Use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change**. Preserve security guards, signer state and lab ownership. Keep CI and publication deferred.
