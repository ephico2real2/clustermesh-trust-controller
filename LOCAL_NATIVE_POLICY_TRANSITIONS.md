# Local native policy transitions

Cilium source `8bb97137fcc92b935171d60e59d7fb8a93714bd8` passed the local Linux ARM64 checks below. This increment has no new image or deployment. The clusters still use the earlier Cilium image.

| Check | Recorded result |
| --- | --- |
| Full race suite | 403 top-level tests; 1691 subtests |
| Lock-debug race suite | 27 top-level tests; 52 subtests |
| Failed or skipped cases | 0 in both suites |
| Go vet | Passed |
| Required lint | 0 issues |

See the [result summary and file hashes](docs/evidence/native-policy-transition/summary.json). The [evidence directory](docs/evidence/native-policy-transition/README.md) retains failed attempts and final passing logs.

## What happens when policy changes

A policy change must not leave old proxy connections authorized under an earlier policy.

1. Cilium checks the endpoint, namespace UID, Pod UID and sandbox identity.
2. Cilium changes matching native membership to `Draining` before it waits for network work.
3. Cilium requests a bounded drain from the original ztunnel ADD owner.
4. Ztunnel stops the owned listeners and tasks, drains connections, and returns a typed receipt.
5. Cilium checks the receipt's original binding, execution, generation and nonce.
6. Cilium checks the endpoint identity again before it commits the native policy change.

Cilium waits for the receipt outside the endpoint lock. A generic ACK cannot replace this receipt.

The complete-policy path checks the barrier before it changes desired policy or synchronizes the native map. The incremental path checks under the actual pending-change lock. A rejected incremental update consumes no map changes or selector history. The endpoint manager returns synchronous failures to its caller.

The same workload incarnation remains quarantined after a successful drain. This increment has no release operation. Normal recovery requires a new Pod UID and fresh admission checks. It does not provide seamless policy-update recovery.

Ordinary Observe and platform endpoints retain their native policy lifecycle. The constructor records when this execution created no ZDS owner. That mode cannot excuse prior Required intent or matching retained ownership. No namespace-name whitelist grants an exemption.

## Required state and uncertain ADD requests

Required intent remains restrictive if its public membership copy disappears or changes to `Unenrolled`. Disabled or missing authority cannot turn that intent into an unmanaged endpoint.

The native ownership check examines ADD bindings, replay state and pending send uncertainty. A busy or inconsistent check rejects the update. Generation zero alone does not prove that no ADD reached ztunnel.

Cilium records send uncertainty before it writes an original ADD. The index holds at most 4096 endpoint-incarnation slots. An exact typed retirement cannot erase a successor request in the same slot. An ACK, successful certificate request or populated index does not mean `Protected`.

One recovery gap remains open. After a lost ADD ACK, the uncertainty index can retain the request while the acknowledged binding is absent. The current drain lookup cannot yet recover that binding safely. No test result here claims this gap is fixed.

## Run the suites automatically

The recorded runners are single-command suites. They execute Go assertions automatically; operators do not need to test each line manually.

From this repository root, use the recorded profiles:

```bash
bash docs/evidence/native-policy-transition/full.sh
bash docs/evidence/native-policy-transition/lockdebug.sh
bash docs/evidence/native-policy-transition/lint.sh
```

These scripts retain this run's source mounts, image pins, private Podman socket and output paths. Verify those prerequisites before reproduction. The lint script records the change baseline used during qualification; do not treat a clean current `HEAD` as the same baseline.

The functional runner creates its own isolated etcd container. It runs the selected packages with `go test -race -count=1 -json`, then runs vet. The lock-debug profile uses an explicit test selection. A failed assertion returns a nonzero exit status and stops the script. The exit trap collects etcd diagnostics and removes the exact container it created. The runners do not create clusters or change Kubernetes objects.

Raw output was written under `/private/tmp/cmtc-native-policy-transition-20261025`. Durable copies are stored in [docs/evidence/native-policy-transition](docs/evidence/native-policy-transition/README.md).

## Remaining delivery gates

This profile qualifies source behavior and native receipt correlation. It does not qualify a running proxy or end-to-end workload mTLS.

The following gates remain open:

- Recover the original drain binding after an uncertain ADD ACK.
- Prove that the running programs use the expected kernel policy maps.
- Preserve quarantine through restore, restart and first-packet windows.
- Prove mandatory capture and exact workload identity binding.
- Close any kernel transport grant before a policy transition or authority failure.
- Build, deploy and verify the exact image, then collect real positive and negative traffic evidence.

This change adds no HBONE port 15008 allowance. Application-port authorization remains a separate requirement. The ClusterMesh compatibility guard stays closed. No result in this guide establishes `Protected` status.

See [delivery status](docs/agile/DELIVERY_STATUS.md) for the next unfinished dependency.
