# ClusterMeshTrust API and reconciler design

<!-- CMTC_DOC_CONTEXT -->
Research scope: findings apply to the source version named in this document. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This note refines the proposed `ClusterMeshTrust` controller and manager
registration sketch into a source-backed implementation contract. It is a
design and issue companion, not a claim that the trust controller already
exists.

The parent architecture is [CMTC-105 issue #13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13): CMTC coordinates trust-domain and public-bundle federation; Cilium owns packet policy and datapath enforcement. The metric contract in [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15) governs any later controller telemetry.

## Current implementation boundary

The Go API in `api/v1alpha1/policy_types.go` registers only
`NamespaceMTLSPolicy` under `security.cmtc.io/v1alpha1`. The installed CRD in
`config/crd/` and controller RBAC in `config/default/rbac.yaml` cover that
observation resource. `config/samples/clustermesh-trust.yaml` labels itself
“Proposed API only”; there is currently no `ClusterMeshTrust` Go type, CRD,
reconciler, or RBAC.

`cmd/cmtc/main.go` registers the existing API scheme, initializes the
controller-runtime manager with its zap-backed logger and metrics registry,
and installs `PolicyReconciler` in controller mode. Controller mode already
owns leader election; a trust reconciler belongs in this manager, not a second
manager or the node-agent mode. The existing health/readiness handlers are
`Ping` checks, not trust readiness. A trust controller must be added after its
API and CRD are defined. The sample alone is not registered with the scheme and
cannot be reconciled. The CRD generator and kustomization currently include
only the namespace policy. The module also does not pin cert-manager or
trust-manager Go API dependencies; typed clients require explicit compatible
dependency pins and scheme registration.

## Responsibilities and trust boundary

The new reconciler should own high-level trust orchestration: validate the
declared trust configuration, reconcile explicitly owned *public* CA bundle
outputs, report their observed digest, and coordinate bundle-consumer readiness
for rotation. It must not write namespace enrollment labels, synthesize
workload identities, authorize traffic, or mark a workload protected. Those
remain separate policy, identity-provider, and Cilium datapath responsibilities.

The API design must decide the resource scope, whether one or multiple trust
objects are allowed, authoritative cluster identifiers, source-bundle contract,
distribution targets, and how each cluster proves its issuer binding. The
example `mesh.example.com` is a SPIFFE trust domain, not proof of cluster
membership. Shared trust-domain, namespace, and service-account strings can
produce the same SPIFFE ID in two clusters. CMTC-105 therefore requires either
explicitly trusted cluster-specific domains or another cryptographically
verified cluster binding; discovery labels and a common root alone do not pass.

CMTC must not read, generate, copy, log, or expose root, intermediate, or
workload private keys. SPIRE and cert-manager own issuance and key operations;
the reconciler consumes and distributes public certificate material only. A
bundle being published is not evidence that SPIRE, ztunnel, or every workload
has loaded it.

## Reconciliation contract

1. Fetch the object using the manager cache. Treat a normal `NotFound` as a
   no-op unless a persisted finalizer records outputs that still require
   cleanup. Transient API errors return to controller-runtime for rate-limited
   retry.
2. Validate the versioned API contract and trust provenance before constructing
   any output. Invalid or unsupported values become a stable `SpecValid=False`
   condition; they are never rewritten into a weaker mode. Admission schema
   validation should reject unsupported enum values before reconciliation.
3. Build a deterministic desired representation containing public trust
   anchors only. Validate PEM encoding, non-empty certificate sets, trust-domain
   syntax, cluster identity/issuer bindings, and target ownership. Never accept
   the SPIFFE URI or cluster name in the spec as cryptographic evidence by
   itself.
4. Reconcile only the selected, version-pinned public-bundle interface (for
   example, a compatible trust-manager resource if that dependency is installed
   and its semantics are verified). Do not copy bytes into arbitrary
   ConfigMaps, overwrite shared objects, or create one output per reconcile.
   Record an owner reference or an equivalent unambiguous ownership marker and
   reject collisions with unowned resources.
5. Persist status with stable `metav1.Condition` values, `ObservedGeneration`,
   and the observed public-bundle digest. Use `meta.SetStatusCondition` and an
   optimistic-lock merge patch based on the fetched object (for the pinned
   controller-runtime v0.24.1, use `client.MergeFromWithOptions` with
   `client.MergeFromWithOptimisticLock{}`). Avoid duplicate conditions,
   unconditional `Status().Update`, and timestamps that change on every pass.
   Compare semantic status before patching; return conflicts so the work queue
   retries safely. Reconcile twice with unchanged inputs must leave output,
   status, and resource version unchanged.
6. Track distinct milestones: `SpecValid`, `BundlePublished`,
   `ConsumersAcknowledged`, and `TrustReloadVerified` (final names are an API
   design decision). A controller has not proved consumer reload merely because
   a Kubernetes object exists or a node agent acknowledged a configuration.
   Rotation must wait for verified consumption by every required cluster before
   switching issuance or retiring an old root.
7. Define deletion semantics before choosing owner references or a finalizer.
   For declarative child resources with no consumer-safety gate, verified owner
   references may be sufficient. If withdrawing trust can break active
   workloads, a finalizer must hold the public bundle until the required,
   authenticated consumer-removal acknowledgments arrive; only then may it
   remove resources owned by this resource UID and release the finalizer. A
   dependency outage must keep deletion visibly blocked rather than deleting
   trust or spinning on an ignored error. Never treat a missing custom resource
   as authority to delete a shared bundle.

Use `ctrl.LoggerFrom(ctx)` with structured fields such as resource key, stage,
generation, bounded result, attempt, elapsed time, and retry delay. Follow the
existing controller-runtime logger and telemetry integration; do not add a
logrus-specific logger field. Metrics must describe real reconcile events with
bounded labels and the semantics defined by issue #15. Do not label with raw
SPIFFE IDs, errors, resource names, or user-controlled cluster strings.

Watch the trust object and owned resources where practical. Let transient
failures use the manager work queue's retry behavior. Permanent invalid input
should set a stable condition and wait for a spec event rather than hot-loop;
missing or temporarily unavailable dependencies should report NotReady and use
a bounded requeue if there is no watchable event. Add timed requeues only where
an external consumer cannot produce an event and the polling interval has a
defined purpose. Avoid unconditional five- or thirty-second status writes.

## Manager integration shape

Once the versioned `ClusterMeshTrust` API exists, register it with the existing
scheme before constructing the manager. In `cmd/cmtc/main.go`, add the
reconciler only in controller mode beside `PolicyReconciler`, using the manager
client and the existing metrics registry. Keep the current zap/logr logger,
leader-election lease, health endpoints, flags, and signal handler. The
illustrative shape is:

```go
if mode == "controller" {
	// After the API types and AddToScheme registration are implemented.
	must((&controller.ClusterMeshTrustReconciler{
		Client:  mgr.GetClient(),
		Metrics: trustMetrics,
	}).SetupWithManager(mgr))
}
```

This is intentionally not paste-ready: `ClusterMeshTrustReconciler`,
`trustMetrics`, and the API type are not present yet. The API type, deep-copy
code, CRD generation/kustomization, dependency pins, least-privilege RBAC, and
reconciler tests must land before this hook can compile. `SetupWithManager`
should own the primary `ClusterMeshTrust` watch and only watch external resource
types supported by the pinned dependency versions. Readiness must not become
true solely because `Ping` responds; controller readiness must not be
described as actual workload protection.

## Corrections to the supplied sketch

- Its imports contain placeholders, it misspells the API package as
  `truestv1alpha1`, and its types and status fields do not exist in this repo.
- It uses `trust.cilium.io`, while the implemented CMTC API group is
  `security.cmtc.io`. Do not silently introduce a second group; settle and
  version the API deliberately.
- It attempts to handle `Strict` in a reconciler even though the current policy
  CRD admits only `Observe`. Silently converting a rejected security request to
  Observe is unsafe and cannot establish enforcement. Preserve schema rejection
  and keep enforcement separate from trust-bundle publication.
- Its `reconcileFederatedBundles` placeholder returns `nil`, after which the
  reconciler reports successful synchronization. That would make status claim
  work that did not happen.
- It appends duplicate conditions, unconditionally writes status, and updates
  `LastSyncedTime` every pass. This creates API churn and hides idempotency
  failures.
- It has no finalizer, owner-reference, or ownership model, yet implies cleanup
  after a NotFound. Define safe deletion and consumer acknowledgment semantics;
  cleanup must be tied to verified ownership and must not remove shared trust.
- Its RBAC grants broad CRD and ConfigMap mutations without defining the actual
  output API, target scope, or ownership safeguards. Generate least-privilege
  permissions from the chosen resource model; do not grant Secret reads or
  namespace writes to this controller.
- It logs through a `logrus.Entry`, while the real manager uses controller-
  runtime's configured zap/logr logger. Use the context logger and existing
  controller conventions.
- The suggested new `cmd/main.go` would replace the real `cmd/cmtc/main.go`
  architecture and scheme. Extend the existing entrypoint and manager; do not
  create a competing executable.
- Its `Ping` readiness check would only prove the HTTP probe responds. Add a
  separate readiness signal for required controller initialization/dependency
  state, without equating it to bundle consumption or protected traffic.

## Local implementation and verification gates

Before writing production code, settle the API and generate its Go types,
deep-copy methods, structural CRD, RBAC, and samples from one source of truth.
Then test:

- valid and invalid API objects, including unsupported enum values rejected by
  admission and malformed trust-domain, cluster, issuer, and PEM inputs;
- successful publication, repeated reconcile with no diff, input rotation,
  optimistic conflict, manager restart, transient API failure, and recovery;
- missing source, empty or malformed public bundle, unknown cluster, untrusted
  issuer, duplicate cluster identity, forged identity text, partial target
  availability, and forbidden RBAC access;
- non-CA, expired, or otherwise invalid certificates; a trust-manager/API
  dependency that is absent or out of its supported version; and multiple
  `ClusterMeshTrust` objects when the chosen API contract permits only one;
- deletion while source or consumers are unavailable, owner-reference or
  finalizer retry according to the selected lifecycle, an unowned output
  collision, and cleanup preserving shared resources and all private keys;
- status-subresource conflict after a child write, child write failure before
  status publication, duplicate reconcile by two manager replicas, leader
  handover, and manager readiness distinct from the `Ping` endpoint;
- bundle overlap, consumer digest acknowledgment, verified reload, delayed or
  lost acknowledgment, partition, issuance switch, drain, rollback, and
  emergency revocation as separate CMTC-103/104 lifecycle cases.

Use unit tests for pure validation/state transitions and an API-backed test
environment for CRD admission, status-subresource and RBAC behavior. Run the
actual selected tests and report counts/skips. Then build the exact CMTC image
with host Podman and qualify it in the owned local fixture before CI. Retain
resource/status diffs, public certificate fingerprints, consumer reload
evidence, structured logs, and negative/recovery output. A unit test, published
bundle, readiness probe, or ACK alone is not workload mTLS evidence.

The implementation work is tracked by [issue #19](https://github.com/ephico2real2/clustermesh-trust-controller/issues/19), linked to the federation boundary in [issue #13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13). Rotation and telemetry remain governed by CMTC-103/104 and [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15).

The follow-on API-backed sample and local Kind acceptance loop are tracked by
[issue #20](https://github.com/ephico2real2/clustermesh-trust-controller/issues/20)
and documented in
[CLUSTERMESHTRUST_SAMPLE_VALIDATION.md](CLUSTERMESHTRUST_SAMPLE_VALIDATION.md).
That work depends on the API and controller contract defined here; the current
sample remains proposal-only.
