# Native node-name port: code and local evidence

Cilium commit: `d040a4bc9aeb045f84477541cbebdbd24ce7c130`. This local commit changes21 files. [The complete patch](cilium-node-discovery.patch) preserves the code and test changes. It is not pushed while CI remains deferred.

The xDS mapper now uses Cilium's discovered node names. It filters the native node table by cluster name and ID. It rejects missing, ambiguous or unsynchronized data. It watches bindings for node-only changes. The ztunnel DaemonSet now receives `NODE_NAME` from Pod.spec.nodeName. There is no NodeIP fallback.

## Measured checks

- Four affected Go packages pass race tests:120 top-level/345 total passed,21 pre-existing integration-dependent skips,zero failures.
- The xDS-only race run passes63 top-level/165 total,zero failures or skips.
- Compilation, generated configuration, BPF permutations, vet and kernel test stages all exit0. Exact counts are in [results.json](results.json).
- [Live inventory validation](live-validation.json) checks35 CiliumEndpoints (18 in cmtc-a,17 in cmtc-b). Every projected name equals the Pod.spec.nodeName and exists in the Kubernetes Node API. Two foreign-cluster node rows per cluster are excluded. [The validation script](validate_node_names.py) records how this was measured.

The inventory check reads the existing deployed node table. It does not prove a new ADS response from the new binary. Opus is building a compatible agent-and-runtime-BPF development overlay for a one-cluster canary. The operator and ClusterMesh server are not rebuilt in that overlay. This is a development check, not a full Cilium release.

## Still open

Grok is reviewing this exact implemented commit. Native admission lifecycle, release ownership, effective authorization, remote workload projection and exact runtime mTLS qualification remain open. The SPIRE delegated API socket access change remains unapproved. No ztunnel proxy runs in the combined lab. These results do not prove cross-cluster mTLS or Protected status.
