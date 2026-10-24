# ClusterMeshTrust sample and local validation

**Status: design-only.** This note refines the proposed sample, application
commands, log output, dashboard assertion, and Cilium pull-request text. It does
not claim that a `ClusterMeshTrust` API, reconciler, mock bridge, or trust metric
exists. The implementation and local acceptance work is tracked by [issue
#20](https://github.com/ephico2real2/clustermesh-trust-controller/issues/20),
which depends on the API/controller contract in [issue
#19](https://github.com/ephico2real2/clustermesh-trust-controller/issues/19)
and the architecture boundary in [issue
#13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13).

## What the repository supports today

The registered API group is `security.cmtc.io/v1alpha1`. Its scheme currently
contains `NamespaceMTLSPolicy` only, and the generated CRD set contains only
`security.cmtc.io_namespacemtlspolicies`. The existing
`config/samples/clustermesh-trust.yaml` is marked **Proposed API only**; there
is no `ClusterMeshTrust` Go type, structural CRD, controller, status contract,
RBAC, or manager registration. The sample cannot be installed or reconciled by
this checkout.

The implemented policy admits `spec.enforcement.mode: Observe`; `Strict` is
rejected by schema validation. That enforcement field belongs to
`NamespaceMTLSPolicy`. A trust-bundle resource coordinates issuer and public
bundle lifecycle; it must not silently become a workload-enforcement API or
rewrite a rejected mode to `Observe`.

`observability/validate.py` checks the currently declared dashboard metrics.
Those include namespace selection intent, node inventory, and policy evaluation;
there are no live `ClusterMeshTrust` reconciliation or consumer-ack metrics.
Creating a trust object therefore cannot truthfully be expected to change
`cmtc_namespaces_selected` to `1`. That gauge measures policy selection intent,
not trust resources or protected namespaces. Metrics must be added to the
contract and validator only when their owning implementation exists and their
semantics are verified.

## Refined sample contract

Do not add a second applyable YAML file yet. Once the API in #19 is implemented,
the expected sample location is
`config/samples/trust_v1alpha1_clustermeshtrust.yaml`, generated or validated
against the same API types and CRD schema. The following is a **shape proposal
only**: its fields are not registered and the file must not be applied today.
The final field names, scope, ownership, and reference kinds are decisions for
the versioned API contract.

```yaml
# PROPOSAL ONLY: no ClusterMeshTrust CRD is installed by this repository yet.
apiVersion: security.cmtc.io/v1alpha1 # candidate group; not a registered kind yet
kind: ClusterMeshTrust
metadata:
  name: orders-mesh-trust
spec:
  clusters:
    - name: cmtc-a
      trustDomain: cmtc-a.mesh.example.com
      publicBundleRef:
        namespace: cmtc-system
        name: cmtc-a-spire-public-bundle
    - name: cmtc-b
      trustDomain: cmtc-b.mesh.example.com
      publicBundleRef:
        namespace: cmtc-system
        name: cmtc-b-spire-public-bundle
  targets:
    - cluster: cmtc-a
      namespaces: [orders]
    - cluster: cmtc-b
      namespaces: [orders]
  rotation:
    requireAllConsumersAcknowledged: true
```

The example uses cluster-specific trust domains to make the identity boundary
visible. That naming choice alone does **not** authenticate a cluster. The
reconciler must verify certificate chains and their authorized cluster/issuer
binding using a reviewed public-bundle contract; user-supplied cluster names,
trust-domain strings, labels, and a common root are not proof. The referenced
material must contain public certificates only. CMTC must not read, create,
copy, log, or distribute signing or workload private keys.

`targetNamespace: default` is intentionally omitted: the API must state whether
a namespace is a local bundle destination, a workload identity scope, or a
policy selector. Those meanings must not be conflated. `pkiReference` to a
cert-manager `ClusterIssuer` is also not, by itself, a public trust bundle or
proof that an observed SVID was issued for the declared cluster. The API design
must select and validate the real public-bundle source. Likewise, do not add an
`enforcementMode` field here; the current policy API owns the separate
Observe-only enforcement setting.

The existing [Observe policy sample](../../config/samples/namespace-mtls-policy.yaml)
remains the applyable example for current policy behavior. The existing
proposal-only [trust sample](../../config/samples/clustermesh-trust.yaml) should
remain clearly marked until the versioned API, generated CRD, and conversion
contract are implemented.

## Local validation sequence after the API exists

### Current checkout: verify the boundary, do not apply the proposed object

The repository files show there is no generated ClusterMeshTrust CRD. Inspect
the target cluster before any future installation and verify the owner/version
if an external CRD happens to exist:

```sh
kubectl --context "$CMTC_CONTEXT" get crd clustermeshtrusts.security.cmtc.io
kubectl --context "$CMTC_CONTEXT" api-resources --api-group=security.cmtc.io
```

The first command is expected to report `NotFound` for a cluster containing
only this repository's current CRDs. Do not apply the proposal YAML or a guessed
`trust.cilium.io` CRD path. The current CRD kustomization and sample inventory
are listed in `config/crd/` and `config/samples/`.

### Future API-backed local loop

After #19 supplies the type, deep-copy/scheme registration, structural CRD,
manager registration, status and RBAC contract, and #20 supplies the sample and
test harness:

1. Run the repository's actual Go checks (`make test build`) and the generated
   schema freshness checks used by the project. Add an explicit generation
   target if the selected API generator requires one; this checkout's Makefile
   does not currently provide `generate` or `manifests` targets.
2. Validate the sample against the generated CRD and manager scheme. Test
   unsupported fields/modes with server-side admission and confirm rejection;
   do not rewrite rejected input.
3. Apply the generated CRD and sample only to the existing isolated CMTC Kind
   fixture, using its recorded contexts and preserving the existing
   `cmtc-a`/`cmtc-b` labs and unrelated applications. Build and deploy the exact
   local CMTC image with Podman before testing. Capture the image/source pin.
4. Record the actual resource, status conditions, `observedGeneration`, child
   ownership, public bundle fingerprints, and controller logs. Reconcile twice
   and compare child resource versions/status to prove no-op idempotency; then
   exercise manager restart, invalid issuer/bundle, API outage, corrected-input
   recovery, and safe deletion/rotation. Never include key material in logs or
   evidence.
5. Use the real Prometheus endpoint documented by
   [`observability/docs/README.md`](../../observability/docs/README.md), for
   example:

   ```sh
   python3 observability/validate.py \
     --prometheus http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom \
     --out artifacts/dashboard-query-evidence.json
   ```

   This currently validates the existing dashboard query contract. Add a
   ClusterMeshTrust metric assertion only after its metric has an implemented
   producer, documented type/labels/event semantics, working scrape, and a
   non-zero query backed by the local test. A successful query of a namespace
   gauge is not proof that the trust reconciler ran.
6. Retain the selected test commands/counts, failed attempts, skipped-case
   count, status diffs, log evidence, bundle fingerprints, and recovery result.
   Keep CI deferred until the user changes the local-first instruction.

Do not paste success logs into a guide before capturing them from the deployed
image. Log messages should be documented from the actual controller logger and
include stable resource key, generation, reconcile stage, outcome, retry, and
elapsed time without secrets. A ready HTTP probe, controller log, published
bundle, or xDS/ZDS ACK does not establish workload mTLS.

## Cilium proposal text in the supplied draft

The included `[WIP] ambient` pull-request description is not ready to publish.
It asserts a `pkg/ambient/mockbridge` Hive cell, native ambient-cache wiring,
three Prometheus metrics, transformer unit tests, and successful two-cluster
injection; those claims need real source changes, selected non-skipped tests,
and exact-image runtime evidence. The current issues [#16](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16),
[#17](https://github.com/ephico2real2/clustermesh-trust-controller/issues/17),
and [#18](https://github.com/ephico2real2/clustermesh-trust-controller/issues/18)
track separate xDS mapping, scraping, and fail-closed test work; they are not
proof that those features exist.

Do not implement the proposed empty-SPIFFE fallback by assigning
`denied.invalid`. A synthetic trust-domain string is not an authorization
decision. Reject invalid source records before xDS publication and prove the
configured receiver denies the connection in negative runtime tests. A mock
injection framework can test serialization but cannot replace authenticated
two-cluster identity, effective policy, or traffic-path acceptance.

## Tracking

Issue [#20](https://github.com/ephico2real2/clustermesh-trust-controller/issues/20)
tracks the API-backed sample and its local Kind acceptance loop as a child of
[#19](https://github.com/ephico2real2/clustermesh-trust-controller/issues/19).
Issue #19 owns the API/controller contract; [#13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13)
owns the wider federation boundary. Neither issue is complete until the
implementation and local evidence gates pass.
