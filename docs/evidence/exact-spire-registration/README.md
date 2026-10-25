# Exact SPIRE registration and credential lifecycle

The eighth automatic trial passed in both persistent clusters. It used registrar source `e39928bc4f79ad6da134e77583945c8e5e9d52bf` and corrected diagnostic source `75843515d549f7928d080801ac3f7e4344f572eb`.

The fixture verified eight exact initial rows and six rows after target namespace withdrawal. All four target Pods received explicit empty/unusable SVID responses. A still-enrolled control on the same node and probe returned a valid approved-signer credential before and after each absence observation. These are credential-availability results, not policy DENY counters.

Both clusters passed reenrollment, same-name Pod replacement, server restart, fresh readback and exact binary checks. The final automatic application suite passed all 36 paths after cleanup. Its report and byte-preserving raw archive are retained separately. Cleanup restored original templates and preserved signer/PVC identity, foreign registration rows and the producer ledger. It removed only owned resources with no cleanup errors.

The 28 focused plan tests and complete 124 host helper tests also passed. The frozen source hashes identify the exact automatic runner. The raw archive contains public certificate output, structured retry/readback logs, per-attempt results and API/image evidence. No private key is exported.

Startup rejected changing API revisions before a later fresh pass succeeded. Those errors remain in the logs. They do not establish an authorization denial or a successful registration. Earlier failed trials remain separate diagnostics.

This increment does not revoke already-issued certificates, close application connections, enable ztunnel, or qualify cross-cluster workload mTLS. Production registration ownership and agent Admin permissions remain separate gates. Read [the workflow guide](../../../SPIRE_REGISTRATION_WORKFLOW.md) and [current status](../../agile/DELIVERY_STATUS.md).
