# Native node-name port: code and local evidence

Cilium commit: `d040a4bc9aeb045f84477541cbebdbd24ce7c130`. This local commit changes21 files. [The complete patch](cilium-node-discovery.patch) preserves the code and test changes. It is not pushed while CI remains deferred.

The xDS mapper now uses Cilium's discovered node names. It filters the native node table by cluster name and ID. It rejects missing, ambiguous or unsynchronized data. It watches bindings for node-only changes. The ztunnel DaemonSet now receives `NODE_NAME` from Pod.spec.nodeName. There is no NodeIP fallback.

## Measured checks

- Four affected Go packages pass race tests:120 top-level/345 total passed,21 pre-existing integration-dependent skips,zero failures.
- The xDS-only race run passes63 top-level/165 total,zero failures or skips.
- Compilation, generated configuration, BPF permutations, vet and kernel test stages all exit0. Exact counts are in [results.json](results.json).
- [Live inventory validation](live-validation.json) checks35 CiliumEndpoints (18 in cmtc-a,17 in cmtc-b). Every projected name equals the Pod.spec.nodeName and exists in the Kubernetes Node API. Two foreign-cluster node rows per cluster are excluded. [The validation script](validate_node_names.py) records how this was measured.

The inventory check reads the existing deployed node table. It does not prove a new ADS response from the new binary. The agent-and-runtime-BPF development overlay is now deployed on both cmtc-a nodes. [Canary logs and running revisions](canary-cmtc-a/) record the actual new binary. The first attempt was a caught no-op and is not accepted as deployment evidence. The corrected attempt verifies d040a4bc9a on both nodes, with15 worker and7 control-plane endpoints ready. cmtc-b is unchanged. Post-rollout traffic and live BPF inspection remain open. The operator and ClusterMesh server are not rebuilt in that overlay. This is a development check, not a full Cilium release.

## Still open

Grok's [adversarial review](../../research/cursor/GROK_ADVERSARIAL_REVIEW.md) and [complete remediation proposal](../../research/cursor/GROK_REMEDIATION.md) are retained. Opus has received both reports and is adapting the proposed fixes. Native admission lifecycle, release ownership, effective authorization, remote workload projection and exact runtime mTLS qualification remain open. A separate DelegatedIdentity-only listener is source-tested but not activated. The broader SPIRE Admin DAC change remains unapproved. No ztunnel proxy runs in the combined lab. These results do not prove cross-cluster mTLS or Protected status.

## Retained-binding race fixed

Independent primary review and Grok's implemented-code review found that an unrelated new workload batch could hide an earlier node change by replacing its closed watch. [The old-source regression fails](retained-binding-before.log). Cilium commit `dbd2d32bd935b8b271141667e41546c904e74e8a` stages bindings by immutable Pod UID, verifies every retained binding, checks again before sending, and commits state only after a successful send. Exact removals preserve other Pods on the same node.

[The full follow-up patch](retained-binding-race-fix.patch) and [results](retained-binding-results.json) record67 top-level/169 total race passes,zero failures/skips,andvet0. This fix is not yet deployed. The cmtc-a development canary remains at d040a4bc9a with ztunnel disabled. It must receive the qualified fix before strict activation.
