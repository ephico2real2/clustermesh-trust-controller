# CMTC continuation instructions

Continue the active end-to-end mandate. Start with [CODEX_START_HERE](CODEX_START_HERE.md) and [delivery status](../agile/DELIVERY_STATUS.md).

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
- Qualify the opt-in eBPF prototype before production integration into Cilium.
- Treat the separate registrar image as an experimental design change.

Use `cmtc-a` and `cmtc-b`. Keep KVStoreMesh enabled. Preserve the existing Colima runtime and applications.

Complete each increment locally. Run tests, lint and vet. Build the exact Linux ARM64 image with host Podman. Import it by archive. Verify the running image. Collect real traffic and recovery evidence. Commit qualified work under the user's configured identity.

CI, branch pushes and registry publication are deferred. Do not relax the compatibility guard or claim `Protected` from a label, registration, SVID or ACK.

Use agents to unblock research, design and review. Give each agent the actual source, failure and ownership context. Require complete code and negative/recovery tests. The primary agent must implement and validate the chosen fix.

Use [the documentation writing rules](../../DOCUMENTATION_GUIDE.md). Keep sentences direct. Keep one action in each procedural step. Label proposed and historical behavior.

Update delivery status before compaction. Preserve the current story, evidence, next action and actual blocker. Complete a side request, then return to the first unfinished security dependency.
