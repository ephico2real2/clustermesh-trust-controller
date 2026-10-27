# Mesh PKI: one root, a named intermediate per cluster

Status: current, revised 2026-10-26. Design decision: [ADR-011](docs/architecture/adr/ADR-011.md).

Every cluster of the mesh trusts one root certificate. Each cluster signs its own certificates with its own
intermediates, and every intermediate carries the cluster's name. So any certificate shows which cluster signed it,
and one cluster's CA can be renewed or revoked without touching the others.

| State | ClusterMesh and ztunnel control-plane certificates | SPIRE workload certificates |
|---|---|---|
| Implemented | `config/lab-pki/*.yaml`, `scripts/lab/pki/mesh-pki.sh`, `charts/cmtc` (`trust.*`), `scripts/lab/up.sh` | Intermediates only (`<cluster>-spire-intermediate`) |
| Tested | Functional test on both labs: refusals, create, rerun, cross-cluster verification, SVID-depth chain ([run 2](docs/evidence/clustermesh-pki-20261026/mesh-pki-test/run-2-cluster-names/result.txt)) | The SVID-depth chain (test B4) verifies against the root |
| Deployed | kind-cmtc-a and kind-cmtc-b, 2026-10-26 12:49-13:51Z ([cutover evidence](docs/evidence/clustermesh-pki-20261026/cutover/)) | Not deployed: SPIRE still signs under `CMTC Lab Organization Root` |
| Traffic-qualified | Matrix after the cutover: 48 requests proven over mTLS, 12 denials as expected | Not yet |

CI (`up.sh`) builds this PKI from the same files. The CI run of this change is still to be checked.

## The chain

The control cluster (cmtc-a in the lab) mints the root with cert-manager. Its Secret, key included, is copied to
every member, as Cilium's Cluster Mesh guide copies `cilium-ca`. Each cluster then signs its own intermediates. The
intermediate keys never leave their cluster.

<!-- markdownlint-disable MD033 -->
<picture>
  <img src="docs/diagrams/mesh-pki/chain.light.png" alt="cmtc-a mints cmtc-mesh-root-ca and copies its Secret to cmtc-b. Each cluster's ClusterIssuer cmtc-mesh-root signs that cluster's ClusterMesh and SPIRE intermediates. The ClusterMesh intermediate signs the seven ClusterMesh and ztunnel leaves. SPIRE moving onto its intermediate is proposed, issue 34.">
</picture>
<!-- markdownlint-enable MD033 -->

*Deployed on both labs: the root, its copy, both intermediates per cluster, and the 7 leaves on each cluster's
ClusterMesh intermediate. The live intermediates have 1-year lifetimes; the repository sets 3 years. The SPIRE
intermediates are Ready but sign nothing yet: SPIRE still gets its CA from ClusterIssuer `cmtc-spire-issuer`
(measured 2026-10-26T23:27Z).*

```text
cmtc-a (control):  Issuer cmtc-mesh-root-bootstrap (selfSigned)
                     -> Certificate cmtc-mesh-root-ca (10 y)  -> Secret, key included --copied--> every member
every cluster:     ClusterIssuer cmtc-mesh-root (on the root Secret)
                     -> <cluster>-clustermesh-intermediate (live 1 y, repo 3 y)  -> 7 ClusterMesh and ztunnel leaves
                     -> <cluster>-spire-intermediate (live 1 y, chart 3 y)       -> SPIRE X509 CA -> SVIDs   [proposed, #34]
                        (today SPIRE's CA comes from ClusterIssuer cmtc-spire-issuer)
trust:             kube-system/cmtc-public-root ca.crt holds the root certificate
```

A leaf's `tls.crt` holds the leaf and its intermediate. The verifier holds only the root. This is the issuer
chaining shown in [Linkerd's cert-manager guide](https://docs.buoyant.io/buoyant-enterprise-linkerd/latest/guides/cert-manager-concepts/).

## Names

Each per-cluster CA has one name. Its Certificate (in `cert-manager`), its Secret, and the ClusterIssuer that signs
with it all use that name.

| Object | Name | Scope |
|---|---|---|
| Root Certificate and Secret | `<prefix>-mesh-root-ca` | Control cluster; Secret copied to members |
| Root signer | Issuer `<prefix>-mesh-root-bootstrap` | Control cluster |
| Issuer on the root | ClusterIssuer `<prefix>-mesh-root` | Every cluster |
| ClusterMesh CA | `<cluster>-clustermesh-intermediate` | One cluster |
| SPIRE CA | `<cluster>-spire-intermediate` | One cluster |

The prefix is `cmtc` in the lab. The cluster names are `cmtc-a`, `cmtc-b`, and for a third cluster `cmtc-c`. The
common names follow the same rule: `cmtc mesh root CA`, `cmtc-a ClusterMesh intermediate CA`,
`cmtc-a SPIRE intermediate CA`.

The live labs also keep the old ClusterIssuer `cmtc-lab-intermediate`. No Certificate refers to it since 13:51Z. It
is deleted once the Helm release values name the new issuer (see [open items](#open-items)).

## Lifetimes

Rule: each CA renews at least one full lifetime of what it signs before it expires. So no certificate outlives the
CA that signed it.

| Certificate | Lifetime | Renewed | Key on renewal | Set in |
|---|---|---|---|---|
| Mesh root | 10 years | 3 years before expiry | kept (`Never`) | `config/lab-pki/root-control.yaml` |
| ClusterMesh and SPIRE intermediates | 3 years | 1 year before expiry | new | `config/lab-pki/clustermesh.yaml`, `charts/cmtc` `trust.spireIntermediate` |
| clustermesh-apiserver server | 365 days | cert-manager default | kept (`Never`): peers pin its key | `up.sh` chart values |
| clustermesh-apiserver clients | 365 days | cert-manager default | new | `up.sh` chart values |
| ztunnel ADS, membership writer, origin reader | 24 hours | 1 hour before expiry | new | lab activation script (to move into the chart) |
| SPIRE X509 CA | 24 hours | SPIRE | new | SPIRE `ca_ttl` |
| Workload SVID | 120 s (registrar) | half-life | new | `internal/spireregistrar/plan.go` |

Reference values, read from each project's own source on 2026-10-26:

| Product | Root or trust anchor | Intermediate or issuer | Leaf or workload |
|---|---|---|---|
| Cilium, without ClusterMesh | CA 1095 days | — | ClusterMesh and Hubble 365 days ([values.yaml](https://github.com/cilium/cilium/blob/main/install/kubernetes/cilium/values.yaml)) |
| Istio | self-signed root `87600h` | plug-in CA per cluster | default `24h`, at most `2160h` ([pilot-discovery](https://istio.io/latest/docs/reference/commands/pilot-discovery/)) |
| Linkerd | trust anchor `8760h` | identity issuer `48h` | rotated automatically ([cert-manager guide](https://linkerd.io/2-edge/tasks/automatically-rotating-control-plane-tls-credentials/)) |
| SPIRE | — | `ca_ttl` 24h | X509-SVID 1h, JWT-SVID 5m ([server reference](https://spiffe.io/docs/latest/deploying/spire_server/)) |

The live labs still run the old leaf lifetimes (24 hours) until the Helm release and the activation resources carry
the new values. The CA lifetimes on the live labs are 1 year (the templates before this change); they reach the new
values at the next reissue.

## What each mTLS peer presents

<!-- markdownlint-disable MD033 -->
<picture>
  <img src="docs/diagrams/mesh-pki/peers.light.png" alt="Each TLS peer sends its leaf and its cluster's intermediate; the verifier checks the chain against the root it trusts. ClusterMesh etcd and ztunnel ADS chain to the mesh root today. Workload SVIDs chain to the host organization root today; the proposed chain ends at the mesh root through the cluster's SPIRE intermediate, and the pins move from the 24-hour SPIRE CA to the intermediate and the root.">
</picture>
<!-- markdownlint-enable MD033 -->

*The ClusterMesh rows are deployed. Today the issuer approval pins the 24-hour SPIRE CA, so each SPIRE CA activation
needs a new approval generation. The proposed row (#34) pins the cluster's SPIRE intermediate and the mesh root.*

```text
ClusterMesh etcd   server leaf -> cmtc-a ClusterMesh intermediate CA -> cmtc mesh root CA (cmtc-public-root)
ztunnel ADS        ADS leaf    -> cmtc-a ClusterMesh intermediate CA -> cmtc mesh root CA (bootstrap-ca.crt)
workload, today    SVID -> SPIRE X509 CA (24 h, pinned by gN) -> cmtc-a SPIRE cluster CA -> CMTC Lab Organization Root (rootPins)
workload, proposed SVID -> SPIRE X509 CA (24 h, not pinned) -> cmtc-a SPIRE intermediate CA (pinned)
                     -> cmtc mesh root CA (pinned, by a root succession)   [#34]
```

## SPIRE certificates and SVIDs

Each cluster's SPIRE gets its 24-hour X509 CA from cert-manager through the SPIRE `UpstreamAuthority "cert-manager"`
plugin. The SPIRE CA signs the workload SVIDs. ztunnel fetches them as a delegate of the SPIRE node agent, and the peer
ztunnel checks them against the pins in the issuer approval. Issue #34 moves SPIRE's CA onto
`<cluster>-spire-intermediate` and the pins onto the mesh root and that intermediate.

<!-- markdownlint-disable MD033 -->
<picture>
  <img src="docs/diagrams/mesh-pki/spire.light.png" alt="In each cluster, ClusterIssuer cmtc-mesh-root signs the Certificate cluster-spire-intermediate, and a ClusterIssuer of the same name signs from its Secret. trust-manager reads the mesh root from that Secret and copies it into ConfigMap cmtc-mesh-root in every namespace labelled trust: enabled. Proposed, issue 34: the SPIRE server gets its 24-hour X509 CA from the SPIRE intermediate instead of cmtc-spire-issuer, and the issuer approval pins the mesh root and the intermediate instead of the 24-hour SPIRE CA. ztunnel fetches the SVIDs as a delegate and the peer ztunnel checks them against the approved pins.">
</picture>
<!-- markdownlint-enable MD033 -->

*Measured on 2026-10-26T23:27Z. The SPIRE intermediate, its ClusterIssuer, the Bundle and the ConfigMap are deployed
on both labs. SPIRE still gets its CA from ClusterIssuer `cmtc-spire-issuer`, and the issuer approval still pins that
CA. The repository already points SPIRE at `<cluster>-spire-intermediate` (`scripts/lab/spire/render_spire.py`), and
the CMTC chart owns the intermediate and the Bundle (`trust.*`). The approval and ztunnel changes are issue #34.*

```text
cert-manager:  ClusterIssuer cmtc-mesh-root -> Certificate <cluster>-spire-intermediate (live 1 y, chart 3 y)
                 -> ClusterIssuer <cluster>-spire-intermediate              Ready, signs nothing yet
SPIRE:         SPIRE server, UpstreamAuthority cert-manager
                 issuer_name today: cmtc-spire-issuer
                 issuer_name proposed (#34, in the repository): <cluster>-spire-intermediate
               -> SPIRE X509 CA (24 h; the next one activates at 20 h) -> workload SVIDs
               -> ztunnel on each node fetches delegated SVIDs (needs its SPIRE delegate entry)
               -> HBONE mTLS to the peer ztunnel
verifiers:     Bundle cmtc-mesh-root (trust-manager, release cmtc-trust) reads ca.crt of <cluster>-spire-intermediate
                 -> ConfigMap cmtc-mesh-root in each namespace labelled trust: enabled   (nothing reads it yet)
               Issuer approval gN, today: pins the 24 h SPIRE CA; a new generation per CA activation
               Issuer approval, proposed (#34): pins the mesh root and the cluster's SPIRE intermediate
               peer ztunnel checks the SVID against the approved pins; a valid SVID alone is not Protected
```

## Troubleshooting

All commands run on Linux and macOS. Use the explicit context of the cluster you inspect.

**Which cluster signed a certificate.**

```sh
kubectl --context kind-cmtc-a -n kube-system get secret clustermesh-apiserver-server-cert \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject -issuer -enddate
# subject=CN=clustermesh-apiserver.kube-system.svc
# issuer=CN=cmtc-a ClusterMesh intermediate CA
```

**What a peer serves on the wire.** From a node of the other cluster, without a client certificate:

```sh
docker exec cmtc-a-control-plane sh -c \
  'echo | openssl s_client -connect cmtc-b-control-plane:32379 -showcerts 2>/dev/null | grep -E "^ *[0-9] s:|i:"'
#  0 s:CN=clustermesh-apiserver.kube-system.svc   i:CN=cmtc-b ClusterMesh intermediate CA
#  1 s:CN=cmtc-b ClusterMesh intermediate CA      i:CN=cmtc mesh root CA
```

**How many certificates each cluster CA issues.**

```sh
kubectl --context kind-cmtc-a get certificates -A -o json | python3 -c '
import json,sys,collections
n=collections.Counter(); c=collections.Counter()
for x in json.load(sys.stdin)["items"]:
    k=x["spec"]["issuerRef"]["name"]; c[k]+=1; n[k]+=x.get("status",{}).get("revision",0)
for k in sorted(c): print(f"{k}: {c[k]} certificates, {n[k]} issuances")'
# cmtc-a-clustermesh-intermediate: 7 certificates, 22 issuances
```

`status.revision` counts every issuance of a Certificate, including issuances before it moved to its current issuer
(22 = 15 under the old chain + 7 after the move). Do not count CertificateRequests: cert-manager keeps one per
Certificate (7 were left for 15 issuances on 2026-10-26), and SPIRE's CA requests leave none.

**Which root a verifier trusts.** Every ClusterMesh verifier and ztunnel reads `kube-system/cmtc-public-root`
`ca.crt`. The [projection check](docs/evidence/clustermesh-pki-20261026/cutover/projections.sh) prints the root
fingerprints in each Pod's projected file, read from the node.

## Build the PKI

CI and a new lab: `scripts/lab/up.sh` runs, after cert-manager is installed in both clusters,

```sh
bash scripts/lab/pki/mesh-pki.sh --root-out "$pki/root.crt" cmtc-a cmtc-b
```

The first cluster is the control cluster. A cluster is `NAME` or `NAME=CONTEXT`; by default its context is
`kind-NAME`. Other names need no file change:

```sh
bash scripts/lab/pki/mesh-pki.sh --prefix acme --root-out root.crt prod-east=eks-east prod-west=eks-west
bash scripts/lab/pki/mesh-pki.sh --render cmtc-c      # print the manifests for one cluster
```

The script is idempotent. Before its first write it refuses a root Secret without its Certificate, and an issuer of
these names that signs from another Secret. It refuses a member that holds a different root. No private key is printed
or written to disk: the root Secret moves between clusters through a pipe.

The Cilium chart then uses `clustermesh.apiserver.tls.auto.certManagerIssuerRef.name=<cluster>-clustermesh-intermediate`
per cluster and puts the root certificate in `tls.caBundle`.

The live labs were moved in place; the procedure as run is in the
[cutover runbook](docs/evidence/clustermesh-pki-20261026/RUNBOOK.md).

## Approval

cert-manager signs a CertificateRequest only after it is approved. The labs use cert-manager's built-in approver
(`disableAutoApproval=false`, the chart default): it approves every request to a cert-manager issuer, so every
Certificate is issued and renewed with no manual step.

Operator decision, 2026-10-27: access to the clusters is gated, and only trusted operators can reach them. That gate
is the operator's to set, so the PKI adds no approval policy of its own. `scripts/lab/up.sh` installs cert-manager with
its defaults (`crds.enabled=true` only).

Deployed on both labs, 2026-10-27, cmtc-b 16:33Z to 16:36Z, then cmtc-a to 16:37Z: cert-manager v1.21.1 upgraded
without `--controllers=-certificaterequests-approver`, trust-manager v0.25.0 upgraded without its policy, the releases
`cmtc-mesh-pki` and `cert-manager-approver-policy` uninstalled and the CRD
`certificaterequestpolicies.policy.cert-manager.io` deleted. After it every Certificate was Ready (11 on cmtc-a, 10 on
cmtc-b), clustermesh-apiserver did not restart, and a new Certificate from a throwaway self-signed Issuer was
`Approved=True`, reason `cert-manager.io`, and issued on each cluster.

Historical: from 2026-10-27T05:40Z (commit `4913117`, an agent session, not an operator request) the built-in approver
was off and approver-policy v0.28.0 approved requests through CertificateRequestPolicies from `charts/cmtc-mesh-pki`,
checked by `scripts/lab/pki/approval-check.sh`. The operator rejected that layer at 16:25Z; the chart, the policies and
the script were removed. The SPIRE CA succession of 10:52Z to 10:55Z ran under those policies
([LOCAL_ISSUER_PROFILE.md](LOCAL_ISSUER_PROFILE.md), Rollout).

## Trust bundle

The trust bundle is part of the mesh PKI: it is how a verifier gets the root it checks peers against. trust-manager
copies the mesh root into the ConfigMap `cmtc-mesh-root` (key `ca.crt`) in each namespace that has **opted in** with the
label `trust: enabled`. A namespace without the label gets no copy. Opt-in is deliberate: a namespace is labelled
because a component in it verifies mesh certificates, and the label is recorded in that namespace's own manifest.

Status:

- **Historical:** deployed on kind-cmtc-a and kind-cmtc-b on 2026-10-26 at 22:15-22:21Z, limited to three namespaces by
  `app.targetNamespaces`.
- **Current, deployed:** the opt-in mode below, on kind-cmtc-a at 22:35:09Z and kind-cmtc-b at 22:35:30Z on
  2026-10-26 (releases `trust-manager` and `cmtc-trust`, revision 2 on both). The repository has since moved the Bundle
  and the SPIRE intermediate into the CMTC chart (`charts/cmtc`, `trust.*`) and removed `charts/cmtc-trust`; the labs
  move to the CMTC chart with issue #34 (see "Move the labs to the CMTC chart" below).
- No component reads the ConfigMap yet.

### How it works

- The source is each cluster's own SPIRE intermediate Secret, `cert-manager/<cluster>-spire-intermediate`, key
  `ca.crt`. That key holds the root that signed the intermediate. Only `ca.crt` is copied. trust-manager's watch still
  receives the whole Secret, private key included ([ADR-011, Accepted risk](docs/architecture/adr/ADR-011.md#accepted-risk)).
- The Bundle `cmtc-mesh-root` selects namespaces with `namespaceSelector.matchLabels: trust: enabled`, as in the
  upstream [trust-manager tutorial](https://cert-manager.io/docs/tutorials/getting-started-with-trust-manager/).
- trust-manager is installed with Helm in `cert-manager`, without `app.targetNamespaces`. The chart then grants one
  ClusterRole for ConfigMaps, so a namespace labelled later gets its copy without a reinstall.
- When the root is re-copied, the ConfigMaps follow without a manual step.

Measured on kind-cmtc-a, 2026-10-26:

- With `app.targetNamespaces` set, a new namespace got no copy while the Bundle still reported `Synced`.
- trust-manager makes no Roles.
- A Bundle written with `metadata.namespace` is stored without one: the Bundle API is cluster-scoped.

### Namespaces that opt in

| Namespace | Component that verifies with the mesh root | Where the label is set |
|---|---|---|
| `kube-system` | Cilium agent and clustermesh-apiserver (`tls.caBundle`), ztunnel | `scripts/lab/up.sh` (no manifest of ours owns this namespace) |
| `cilium-spire` | SPIRE server and SPIRE node agent | `scripts/lab/spire/render_spire.py` |
| `cmtc-system` | CMTC controller (issuer approval) and CMTC node agent | `config/default/namespace.yaml` |

No other namespace is labelled. Application namespaces do not opt in: their workloads get trust from ztunnel, not from
this ConfigMap.

### Opt a namespace in

1. Name the component in the namespace that verifies mesh certificates. If there is none, stop: the namespace does not
   need the root.
2. Add `trust: enabled` to the namespace's labels in the manifest that creates it, and add a row to the table above.
3. Apply the manifest. For a namespace no manifest of ours owns, label it from `scripts/lab/up.sh`:

   ```sh
   kubectl --context kind-cmtc-a label namespace <namespace> trust=enabled
   ```

4. Verify the copy (expected: `CN=cmtc mesh root CA`, SHA-256 starting `6C:12:C7:35`, and no private key):

   ```sh
   kubectl --context kind-cmtc-a -n <namespace> get configmap cmtc-mesh-root -o jsonpath='{.data.ca\.crt}' \
     | openssl x509 -noout -subject -fingerprint -sha256
   kubectl --context kind-cmtc-a -n <namespace> get configmap cmtc-mesh-root -o jsonpath='{.data}' \
     | grep -c 'PRIVATE KEY'
   ```

5. Repeat on kind-cmtc-b.

### Opt a namespace out

1. Switch every reader in the namespace to another trust source first. A verifier that loses its root fails closed.
2. Remove the label from the manifest (or from `scripts/lab/up.sh`) and from the table above.
3. Apply it, or remove the label directly: `kubectl --context kind-cmtc-a label namespace <namespace> trust-`.
4. Check the copy is gone: `kubectl --context kind-cmtc-a -n <namespace> get configmap cmtc-mesh-root` returns
   `NotFound`. Measured on both labs: trust-manager removed the copy by the first check after the label was removed.

### Parts

| Part | Where | Notes |
|---|---|---|
| trust-manager | `config/lab/trust-manager/values.yaml` | Chart and image v0.25.0, image by digest. No public CA package. No `app.targetNamespaces`: one ClusterRole for ConfigMaps. |
| SPIRE intermediate and Bundle `cmtc-mesh-root` | `charts/cmtc`, values `trust.*` (`templates/trust.yaml`) | The CMTC chart owns the cluster's SPIFFE trust: Certificate and ClusterIssuer `<cluster>-spire-intermediate` (3 years, renewed 1 year early, ECDSA P-256, new key at each renewal), signed by ClusterIssuer `cmtc-mesh-root`, and the Bundle. `trust.enabled` is off by default; it needs cert-manager and trust-manager first (the Bundle CRD comes from trust-manager's release). The release namespace carries `trust: enabled`. Tested by `charts/chart_test.go` (`TestTrustIsOwnedByTheChart`). |
| Mesh root and ClusterMesh intermediates | `scripts/lab/pki/mesh-pki.sh`, `config/lab-pki/` | No longer creates the SPIRE intermediate (`config/lab-pki/spire.yaml` removed). |
| Bring-up | `scripts/lab/up.sh` | Installs trust-manager, labels `kube-system`, installs CMTC from its chart with `trust.enabled=true`, and waits for the intermediate to be `Ready` and the Bundle to be `Synced`. |

### Move the labs to the CMTC chart

Planned with issue #34; not done. The labs run CMTC from `config/default` and the Bundle from release `cmtc-trust`;
`<cluster>-spire-intermediate` was applied by `mesh-pki.sh` with `duration: 8760h`. Helm adopts an existing object only
when it carries the release's ownership metadata, so each live object is annotated before `helm upgrade --install cmtc`:

1. Forget release `cmtc-trust` without deleting its Bundle: delete only its Helm release Secrets
   (`kubectl -n default delete secret -l owner=helm,name=cmtc-trust`). `helm uninstall` would delete the Bundle and every
   copy of the ConfigMap.
2. On the Bundle, the SPIRE intermediate Certificate and ClusterIssuer, and the CMTC objects of `config/default`, set
   the label `app.kubernetes.io/managed-by=Helm` and the annotations `meta.helm.sh/release-name=cmtc` and
   `meta.helm.sh/release-namespace=cmtc-system`.
3. `helm upgrade --install cmtc charts/cmtc -n cmtc-system --set trust.enabled=true …`. The Certificate's duration
   changes from 8760h to 26280h, so cert-manager issues a new intermediate with a new key; its `ca.crt`, the mesh root,
   is the same, so the ConfigMaps do not change.
4. Check that the Bundle is `Synced`, the copies are unchanged (SHA-256 `6C:12:C7:35…`), and the intermediate chains to
   the mesh root.

The Bundle uses `trust.cert-manager.io/v1alpha1`, the only Bundle API in trust-manager v0.25.0. trust-manager has
announced a successor, `ClusterBundle`, and the removal of `Bundle` in a later release
([announcement](https://cert-manager.io/announcements/2025/09/05/trust-manager-clusterbundle-future)).

Verified on both labs in the opt-in mode, 2026-10-26 at 22:35Z:

- The controller runs without `--target-namespaces`. The Bundle is `Synced`.
- Copies exist in exactly the labelled namespaces: `kube-system`, `cilium-spire`, `cmtc-system`.
- A namespace created and labelled during the test (`tm-new`) got its copy by the first check: `CN=cmtc mesh root CA`,
  SHA-256 `6C:12:C7:35…`, no private key. Removing the label removed the copy by the first check.
- An unlabelled new namespace (`tm-plain`) and `cf2cnp-lab` got no copy.
- Roles went from 29 to 25 on each cluster: the chart no longer makes `trust-manager-role` in the three namespaces and
  in `cert-manager`. trust-manager keeps two Roles, both in `cert-manager`: `trust-manager` (Secrets) and
  `trust-manager:leaderelection`.
- The only Pod replaced was trust-manager's own (its arguments changed). The probe namespaces and Bundles are removed.

Earlier, in the three-namespace mode (historical), each copy was checked the same way, and `default` and
`cert-manager` had none. Next: switch each verifier to this ConfigMap (Cilium's `tls.caBundle`, then SPIRE and
ztunnel), one at a time with the traffic matrix after each.

## Findings from the cutover

- [A clustermesh-apiserver restart closes same-cluster crossnode admission](docs/evidence/clustermesh-pki-20261026/cutover/07-finding-local-source-watch.md)
  until each Cilium agent restarts (cmtc-a: 10 minutes). The apiserver's etcd is an `emptyDir`, and the agent's
  local source-membership watch resumes at a revision the new etcd has not reached.
- [An origin-reader reissue interrupts cross-cluster traffic](docs/evidence/clustermesh-pki-20261026/cutover/08-finding-origin-reader-renewal.md)
  for 0.4 to 10 seconds (two measurements).

## Open items

1. Persist the Helm values on the live labs (per-cluster issuer name, server key `Never`, 365 days, both roots), with
   the fork chart commit `64a07d46a6`; then delete `cmtc-lab-intermediate`.
2. Remove the disposable root from `cmtc-public-root` before 2026-10-27T19:37Z, with the traffic matrix after.
3. Move the ztunnel ADS, membership-writer and origin-reader Certificates from the lab activation script into the
   chart, with the CA lifetimes above.
4. Move SPIRE onto `<cluster>-spire-intermediate`: `scripts/lab/spire/render_spire.py` issuer per cluster, old and new
   root pins together in `pins.json` and the issuer approval.
5. Decide the SVID TTL (registrar 120 s today; SPIRE default 1 h; Istio 24 h).
6. Fix the local source-membership watch (finding 1).
7. Move the root, the ClusterMesh intermediate and their issuers from `mesh-pki.sh` into a chart (Helm-first, #33).
   The script then copies only the root Secret, which is instance data.

## Diagram sources

The [diagram page](docs/diagrams/mesh-pki/source.html) uses diagram-kit. Render both themes:

```sh
~/.local/share/diagram-kit/.venv/bin/diagram-render docs/diagrams/mesh-pki/source.html docs/diagrams/mesh-pki chain,peers,spire
```

The pictures, their text versions and the page change together.
