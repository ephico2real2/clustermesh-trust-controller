# CMTC continuation instructions

Continue the active end-to-end mandate. Start with [CODEX_START_HERE](CODEX_START_HERE.md) and [delivery status](../agile/DELIVERY_STATUS.md).

Read the current state in [handover.md](../../handover.md) (the update at the top) and [resume.md](../../resume.md) before source work. [The recovery checkpoint](OPUS_RECOVERY.md) and [NEXT_SESSION](NEXT_SESSION.md) are 2026-10-25 history. It records the active Claude process, local-only commits, compiler/lab ownership, completed checks and the first unfinished dependency.

Read the relevant architecture, backlog and security test matrix. Use the enhanced `ephico2real2/cilium` and `ephico2real2/ztunnel` forks. Verify the actual branch, source SHA and dirty files.

Preserve these decisions:

- Use Go and controller-runtime for CMTC.
- Use Cilium Hive for embedded Go extensions.
- Use SPIRE, cert-manager and public trust bundles.
- Keep the protected root key outside clusters and evidence.
- Keep cluster-bound identities and explicit issuer verification.
- Use node ztunnel for workload TLS.
- Use native Cilium ClusterMesh and xDS delivery.
- Do not add a production CMTC-to-ztunnel mock side channel.
- Use no application sidecars.
- Keep WireGuard/IPsec as a separate transport layer.
- Keep exclusion precedence and platform safety.
- Keep the standard Observe node agent unprivileged.
- Build the CMTC DaemonSet eBPF into the permanent, observe-only per-node measurement plane ([ADR-005](../architecture/adr/ADR-005.md)). It never decides a verdict; Cilium keeps enforcement and the native quarantine gate.
- Treat the separate registrar image as an experimental design change.

Use `cmtc-a` and `cmtc-b`. Keep KVStoreMesh enabled. Preserve the existing Colima runtime and applications.

Use **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change**. This rule applies to Codex, Cursor and Claude. Run Go components directly against explicit kind APIs where supported. Use the Ubuntu toolchain and selected test nodes for Linux datapath work. Coordinate a single live writer. Run tests, lint and vet alongside integration. Then deploy the image that CI publishes to `ghcr.io/ephico2real2`, by digest, and repeat affected checks with the verified running image. Never side-load images (`kind load`, `ctr import`); since 2026-10-27 the labs run only registry images. Commit qualified work under the user's configured identity.

Feature-branch pushes are authorized by the user on 2026-10-25. Keep local qualification first. Manual CI dispatch and registry publication remain deferred. Do not relax the compatibility guard or claim `Protected` from a label, registration, SVID or ACK.

Use agents to unblock research, design and review. Give each agent the actual source, failure and ownership context. Require complete code and negative/recovery tests. The primary agent must implement and validate the chosen fix.

Use [the documentation writing rules](../../DOCUMENTATION_GUIDE.md). Keep sentences direct. Keep one action in each procedural step. Label proposed and historical behavior.

Update delivery status before compaction. Preserve the current story, evidence, next action and actual blocker. Complete a side request, then return to the first unfinished security dependency.
