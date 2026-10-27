# Local issuer-profile qualification

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](docs/agile/DELIVERY_STATUS.md) and [documentation terms](DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

**Update, 2026-10-27:** generations 2 to 5 followed generation 1 on the same ledger. Generation 5 pinned SPIRE's
24-hour signer and expired at 03:55:28Z; both producers then report `withdrawn SourceExpired`, and ztunnel fails
closed. The next generation uses the SPIRE intermediate mode below (issue #34). The two paragraphs that follow are
historical.

**Historical state (read 2026-10-25T23:13Z):** the issuer-profile producer is enabled on the CMTC controller in both
clusters (`--issuer-profile-producer=true`, source `cmtc-issuer-approval-g1`, minimum generation 1). The controller
now runs `localhost/cmtc:current-46d01e91ce`, which includes the leader-handover fix (`46d01e9`); exact pins are in
[delivery status](docs/agile/DELIVERY_STATUS.md). CMTC policy stays in Observe mode. Ztunnel now runs in both
clusters and mounts the issuer pins and its issuer checkpoint.

**Action needed:** the generation-1 approval in both clusters has `expiresAt` `2026-10-26T03:55:11Z` (read from
`cmtc-system/cmtc-issuer-approval-g1`). Rotate the immutable approval before that time. Do not extend it by
resetting the ledger or version floors. What expiry does to running workload traffic is not tested.

The mutable publication has a lease of at most 30 seconds.
A publication acknowledgment does not prove native consumer acceptance or traffic protection.
[The live publication ledger](docs/evidence/live-issuer-publication/summary.json) records the activation resource
UIDs, image pins and renewal sequences. Its image pins are historical (`f5fe9992da`, below).

The earlier direct-root and approved-parent trials restored their templates and removed their trial resources.
The activation is persistent. Preserve its source, output, RBAC and private host ownership ledger at `~/.local/share/cmtc-issuer-profile/live-a-b/`.
The ledger contains public proof and ownership state. It does not contain CA private keys.

## Persistent activation helper

Use [publish_issuers.py](scripts/lab/issuer-profile/publish_issuers.py) for the persistent activation.
It pins both cluster UIDs, controller UIDs, node UIDs, cluster-parent approval UIDs and the root fingerprint.
It obtains fresh nonce proofs from both exact SPIRE server images before each activation and at final confirmation.
It creates an immutable approval and a mutable output with exact ownership checks.
It validates effective RBAC and verifies the same producer image before it enables the controller arguments.
It confirms publication renewal, current metrics and structured logs.
Its 41 local tests, including the existing helper tests, pass.

[The actual invocation](docs/evidence/live-issuer-publication/publisher-command.json) records all public pins.
It uses the canonical SPIRE manifest digest from [the recovery ledger](docs/evidence/spire-recovery/image-pin.json).
Do not substitute the synthetic Docker archive import digest as a pull reference.
Do not run the old trial cleanup against this persistent activation.
A failed activation uses a resourceVersion-changing rollback fence. It does not adopt foreign resources or remove authority state.

Read [the illustrated PKI flow](PKI_TRUST_FLOW.md) for the full certificate and verification path. Read [the build steps](LOCAL_IMAGE_BUILD.md) for component builds.

## SPIRE intermediate mode (issue #34)

Status: **implemented, tested, deployed and traffic-qualified** (generation 6 on both labs, 2026-10-27T10:27Z;
SPIRE on `<cluster>-spire-intermediate` since 10:55Z; the matrix at 11:12–11:14Z, [Rollout](#rollout-2026-10-27),
step 6).

Signer mode approves SPIRE's active 24-hour CA, so every SPIRE CA rotation needs a new generation. The intermediate
mode approves each cluster's `<cluster>-spire-intermediate` instead, under the mesh root, with `signsSPIRECA: true`
and no chain. The verifiers then accept exactly one CA below that intermediate, for the cluster's trust domain
(CMTC `internal/trustprofile`, the Cilium fork's `pkg/ztunnel/issuerprofile`, the ztunnel fork's
`src/tls/domain_anchors.rs`). SPIRE's rotations need no new generation; the approval lasts up to 30 days
(`--horizon`, the controller's limit).

The evidence comes from public API objects; no Secret is read:

1. The Certificate `cert-manager/<cluster>-spire-intermediate` has the pinned UID (`--intermediate-pin`), is Ready and
   is a CA from ClusterIssuer `cmtc-mesh-root`.
2. Its CertificateRequest of the current revision is Approved and Ready. Its certificate's `notAfter` equals the
   Certificate's status.
3. ClusterIssuer `<cluster>-spire-intermediate` signs from that Certificate's Secret.
4. SPIRE's `server.conf` (`cilium-spire/spire-server`) names that ClusterIssuer as its one cert-manager upstream issuer.
5. The ConfigMap `cmtc-system/cmtc-mesh-root` holds the root that `--root-sha256` pins. trust-manager writes it without
   the final newline; only that newline is added before the strict parse.

The intermediate and the root are checked with the verifiers' own CA rules: critical basic constraints with CA set,
Cert Sign, only the basic-constraints, key-usage and key-identifier extensions, and path depth for the CAs below. CRL
Sign is not required; cert-manager's CAs do not have it.

The move from signer mode is one `--advance`. Only that advance may change the root and replace the SPIRE proof pins
(`--approval-pin`, `--server-image`) with `--intermediate-pin`. Its preflight checks the live producer against the
previous generation's root. Later advances keep the old rule: generation +1 and the controller image only.

Dry run on the live labs, 2026-10-27T06:10Z, read-only: the generation-6 approval built from the live objects has the
mesh root (`6c12c735…`) and one issuer per cluster. CMTC's `trustprofile.Validate` and the Cilium fork's
`issuerprofile.Validate` (`823d30c51b`) accept it for both clusters (digest `ea2aa6dc…`). CMTC refuses it under the old
root pin (`0c28af9e…`).

Before the advance:

- The controller runs an image with `signsSPIRECA` (`c05755d` or later). The advance verifies the image; it does not
  change it.
- The issuer approval must not pin the intermediate while cert-manager still approves every request
  ([MESH_PKI.md, Approval](MESH_PKI.md#approval)).
- Each node's `pins.json` lists the mesh root in `rootPins`. The Cilium agent and ztunnel read that file at startup.
- **Blocker (found 2026-10-27T06:28Z; fix implemented and tested, not deployed):** ztunnel's checkpoint binds the installation's root pins as part of its
  immutable origin (ztunnel fork `1f32bac`, `src/tls/profile_checkpoint.rs`: `Origin.root_pins`, and `validate()`
  refuses "checkpoint independent origin/root scope differs"). Read on the live nodes: the checkpoints are version 2,
  `origin.root_pins` = [`0c28af9e…`] only, authority generation 5. Adding the mesh root to `pins.json` therefore puts
  every existing checkpoint out of scope, and ztunnel fails closed until the checkpoint is reset, which is not allowed.
  `cee26dd` accepts a root succession only when the new root is already an installation root pin, so it does not cover
  a lab installed with one root.

  The fix is ztunnel fork `0e92198` (`feat/spire-intermediate-pin`). On load, a stored origin that differs from the
  installation only by missing root pins is extended in memory, after the integrity check on the stored bytes. Floors,
  anchor history, fences and cutoffs carry over, and the file keeps the narrower origin until the next distinct durable
  commit. A new root still gains authority only through a strictly newer approval generation. Dropping a root pin, or
  adding one together with any other origin change, still fails closed. ztunnel logs
  `stage="installation-root-pin-extension"`. Tested by the fork's CI (Rust Related Checks, run 40462405566: format,
  build, `cargo test --benches --tests --bins` passed, with the new
  `installation_root_pin_extension_continues_the_checkpoint`). Clippy with `-D warnings` passed locally.

  Order per cluster, as run on 2026-10-27: write the wider `pins.json` on every node, roll the Cilium agent (it reads the
  file only at startup, one node at a time), then replace each ztunnel Pod with an image built from `0e92198` or later.
  The ztunnel Pods are `OnDelete` and also read the file only at startup, so the old ztunnel keeps its narrower origin
  until it is replaced; only a restart of the old image in that window would fail closed on the wider file.

### Rollout, 2026-10-27

Run by the live-writer session under the operator's permission, cmtc-b first, then cmtc-a. Evidence:
`/private/tmp/cmtc-opus-final-20261025/review/g6-rollout/` (ledger, pins before and after) and
`review/issuer-rotation/live/lifecycle/advance-g6/` (advance command, output, ledger before).

1. 10:19–10:21Z: approval by policy ([MESH_PKI.md, Approval](MESH_PKI.md#approval)). cert-manager runs
   `--controllers=-certificaterequests-approver`; every CertificateRequestPolicy is Ready; the four refusal cases of
   `approval-check.sh` pass on each cluster. clustermesh-apiserver did not restart. (Historical: the operator removed
   approval by policy at 16:25Z; cert-manager's built-in approver approves every request again.)
2. 10:25Z: the CMTC controller and node agent to `cmtc@sha256:113b94c09da2…e0ac312` (`5e5d6308f2`, `signsSPIRECA`).
3. 10:26:40–10:27:13Z: `publish_issuers.py --spire-intermediate --advance --generation 6 --horizon 2505600` (29 days,
   one day under the controller's limit for clock skew). Both publications are `published`, `Validated`, generation 6,
   root `6c12c735…`.
4. Per cluster: each node's `pins.json` gains the mesh root (the Lab Org Root stays; the old file is kept at
   `/etc/cmtc/ztunnel-issuer-pins-before-g6.json`); the Cilium agent's issuer-profile Role
   (`cmtc-system/cilium-ztunnel-issuer-profile`) names `cmtc-issuer-approval-g6`; the Cilium agent rolls to
   `cilium-dev@sha256:c77bdc52d2f3…ac8a447` and reads the wider file at startup; then each ztunnel Pod, worker
   first, is replaced with `cmtc-ztunnel@sha256:6f1ae6891782…d4f4f4a` and gets its exact SPIRE delegate entry.
   Every new ztunnel logged `stage="installation-root-pin-extension"` (added `6c12c735…`), then
   `stage="approval-source-succession"` from g5 to g6 and a durable commit at generation 6. No checkpoint was reset.
   clustermesh-apiserver did not restart on either cluster.

The Role step is the one the earlier advances also needed: the Cilium agent reads the approval object that the
publication names, and its Role lists names. Without it the agent logged `configmaps "cmtc-issuer-approval-g6" is
forbidden`.

Traffic after the rollout, 10:33Z: every probe fails with curl 56. ztunnel logs `no approved direct issuer for domain
cmtc-a.mesh.example` (`src/tls/domain_anchors.rs`, `UnauthorizedIssuer`). The client's chain, read from ztunnel's
config dump, is SVID → `cmtc-a SPIRE CA` (valid 2026-10-26T15:55:33Z to 2026-10-27T15:55:33Z) → `cmtc-a SPIRE
cluster CA` → Lab Org Root: SPIRE's active CA is still from the old upstream, and g6 pins only the new intermediate.
This is correct fail-closed behavior.

Why SPIRE had not moved: SPIRE prepares the next CA at half of the current CA's lifetime and activates it at five
sixths (SPIRE `pkg/server/ca/manager/manager.go`, divisors 2 and 6). The SPIRE server restarted with the
cert-manager upstream at 04:08Z, after the current CA's preparation threshold (03:55Z), and logged no "X509 CA
prepared"; its rotator prepares only when the next slot is empty (`pkg/server/ca/rotator/rotator.go`). `localauthority
x509 show` confirmed it at 10:49Z: on both clusters the prepared CA's upstream key ID was the old upstream's
(`9c3af0aa…` on cmtc-a, `14d636dc…` on cmtc-b), not the intermediate's (`78dee534…`, `53d3ad70…`). Left alone, the
first CA from the intermediate would have activated at about 23:55Z.

5. SPIRE moved on demand, with the operator's permission (10:48Z), by
   [`local_authority.py rotate`](#spire-local-authority-operations), cmtc-b at 10:52:42Z, cmtc-a at 10:54:07Z.
   `prepare` replaced the waiting old-chain CA with one from the intermediate; approver-policy logged `Approved by
   CertificateRequestPolicy: "cmtc-b-spire-ca"` (and `"cmtc-a-spire-ca"`), the first live approval by policy. The
   SPIRE bundle held the mesh root at once; after 60 seconds `activate` made the new CA the signer
   (`a1348ce4…` on cmtc-b, `04f6c9ee…` on cmtc-a). Within two minutes the workload certificates in ztunnel's config
   dump chained to `cmtc mesh root CA`. From here SPIRE rotates on its own under the intermediate: next preparation at
   about 22:52Z, activation at about 06:52Z on 2026-10-28.
6. 11:12–11:14Z: the mTLS matrix (`scripts/evidence/run_mtls_matrix.sh`,
   [evidence](docs/evidence/spire-intermediate-20261027/matrix-g6/README.md)). 95 of 96 allowed probes are joined by
   client socket to a ztunnel mTLS connection with both SPIFFE identities, in every scope; 36 of 36 unregistered
   probes are dropped at `bpf_lxc.c:2381`. The 96th returned HTTP 200 from the expected Pod; NAT gave its socket a new
   source port, so it is joined by destination and time (one candidate) instead.

### Approval renewal

Status: the host renewal job is **removed** (`renew_approval.py`, its tests and `renewal-schedule.sh`; operator,
2026-10-27T12:21Z; no `io.cmtc.issuer-approval-renewal` launchd job is loaded on the operator's host, checked
2026-10-27T17:50Z). Its replacement, the issuer approval arbiter in the CMTC controller, is **proposed** in
[ADR-012](docs/architecture/adr/ADR-012.md), **implemented and unit-tested** (controller, node agent, chart values
`controller.issuerApproval` and `nodeAgent.trustReport`), and in live qualification on the labs
([runbook](docs/development/ARBITER_QUALIFICATION_RUNBOOK.md)).

An approval lasts at most 30 days: the controller refuses a longer one (`internal/trustprofile/profile.go:316`).
Generation 6 expires 2026-11-25T10:26:41Z. Until the arbiter is deployed, nothing renews it, and the labs lose
workload mTLS at that time; the operator accepted that outage (2026-10-27T12:21Z).

The arbiter also settles the intermediate's own renewal: with `rotationPolicy: Always` the renewed intermediate has a
new key, and the arbiter approves the old and the new key during the overlap (ADR-012, State machine).

Historical: on 2026-10-27 a host-side renewal (`renew_approval.py`, a launchd job) was written, installed at 12:03Z and
removed at 12:21Z at the operator's decision. A host job is a lab stopgap, not the production method. The advance's
agent Role step from that work stays (`set_agent_access` in `publish_issuers.py`): the Cilium agent's Role
(`cmtc-system/cilium-ztunnel-issuer-profile`) names the new source before the producer publishes from it.

### SPIRE local authority operations

[local_authority.py](scripts/lab/spire/local_authority.py) runs `spire-server localauthority x509` for one cluster,
through the SPIRE server's private socket in its Pod (container `register-agent-node`, the one `entry create` uses). No
socket is exposed and no Secret is read. It needs only `kubectl` and `openssl`.

| Command | What it does | Checked first |
| --- | --- | --- |
| `show` | the active, prepared and old authorities | — |
| `prepare` | mints the next CA now, from the configured upstream | after: its upstream key ID is the current `<cluster>-spire-intermediate`'s Subject Key ID; `server.conf` names that issuer |
| `activate --authority-id ID` | makes the prepared CA the signer now | ID is the prepared one, from the intermediate; the SPIRE trust bundle holds the mesh root |
| `rotate` | `prepare` (kept when the prepared CA is already from the intermediate), wait for the mesh root in the bundle, wait `--propagation` seconds (60), `activate` | as above |
| `taint --authority-id ID` | marks the old authority tainted, so agents and workloads move off it | ID is the old authority, not the active or prepared one |
| `revoke --authority-id ID` | removes a tainted old authority from the bundle | same |

`taint` and `revoke` are never part of `rotate`: they are for a compromised key. `prepare` discards a prepared CA that
was never active.

```sh
scripts/lab/spire/local_authority.py --kube-system-uid <uid> --ledger <file> cmtc-b show
scripts/lab/spire/local_authority.py --kube-system-uid <uid> --ledger <file> cmtc-b rotate
```

Tested by `test_local_authority.py` (8 tests, with a fake SPIRE; removing the upstream check or the old-authority
check fails them) and on both labs, `rotate` on 2026-10-27 ([Rollout](#rollout-2026-10-27), step 5).

## What the producer does

The administrator supplies an immutable ConfigMap with approved public certificates.
Configuration pins the source UID, output UID, cluster name, root fingerprint and minimum approval generation.
The producer reads the API directly. It validates certificates and the approved cluster-to-trust-domain mapping.
It writes a bounded publication to an existing output ConfigMap.
The output contains public material, provenance, version floors and a short lease.

A hash detects changed content. It is not an authority signature.
Verified Kubernetes TLS, restricted permissions and independent configuration provide the API boundary.
No root private key is placed in either cluster or the evidence.

## Exact build and deployment (historical, 2026-10-24)

| Item | Qualified value |
| --- | --- |
| Source | `f5fe9992da855a22660c07b141e19feee50310ba` |
| Image | `localhost/cmtc:lineage-f5fe9992da` |
| Configuration ID | `sha256:3f5839e26f82395d820cd2fc4439648a7e9fa3957544c705b53092031d7c9be7` |
| Platform | Linux ARM64 |
| Toolchain | Go 1.27.3 |
| Runtime | Pinned distroless Debian 13 |
| Runtime provider | Existing Colima `cmtc-cilium` Docker provider |
| Build provider | Host Podman, explicit `cmtc-ubuntu-build` connection |

[The image ledger](docs/evidence/approved-issuer-lineage/image.json) records the builder, runtime digest, archive hash and binary hashes.
[The build command](docs/evidence/approved-issuer-lineage/build-command.json) records the exact argument list.
The builder configuration ID is local to this host. It is not a portable registry reference.
[The Podman guide](docs/development/PODMAN_LOCAL_VALIDATION.md) describes the prepared environment.

Podman built the image from an exported, committed source tree.
The exported Go files matched the tested source hashes.
The archive was imported into all four existing kind nodes.
CRI checks verified the configuration ID, source label and ARM64 platform.
Running Pod digests matched the imported image manifests.
Each running binary matched the recorded SHA-256.

[The rollout ledger](docs/evidence/approved-issuer-lineage/baseline-rollout.json) covers all six containers.
Only their image field changed. Their service accounts, privileges and arguments stayed intact.

## Local test loop

1. Build the image with host Podman.
2. Export the image as a Docker archive.
3. Import the archive into `cmtc-a`.
4. Import the archive into `cmtc-b`.
5. Verify each node's imported image.
6. Run the issuer-profile helper.
7. Verify central metrics.
8. Run the application regression tests.

The helper is [test-issuer-profile.py](scripts/lab/issuer-profile/test-issuer-profile.py).
It requires the full source, configuration and binary hashes.
It uses the existing controller and service account.
It creates only owned ConfigMaps, a restricted Role and its RoleBinding.
It restores the exact controller template before deleting those resources.
UID and resourceVersion preconditions protect cleanup.

The public fixture generator retains no signing keys.
Its certificates test publication. They are not a production workload authority.

## Completed direct-root trial (historical)

These results apply to source `7e606195f5`. The evidence remains available.

- CMTC unit/race tests: 52 top-level tests and 150 subtests passed. Vet passed.
- Helper checks: 22 tests passed after correcting two rollout/scrape timing errors.
- Both clusters passed publication, idle stability, lease renewal and restart-floor checks.
- Both clusters passed source deletion, UID replacement and generation rollback checks.
- Both clusters rejected wrong roots, duplicate issuer keys and expired approvals.
- Both clusters preserved corrupt output and missing-output boundaries.
- Both clusters recovered after explicit administrator repair.
- Real logs contain stage, attempt, elapsed time, deadline and retry fields.
- All four metric families were scraped locally.
- Fresh B-to-A remote-write samples were verified centrally.
- Cleanup restored both controllers and left zero owned resources.
- The deployed baseline passed the existing API/policy and 36 application-path checks.

[Cluster A report](docs/evidence/issuer-profile-producer/cmtc-a-report.json) and [Cluster B report](docs/evidence/issuer-profile-producer/cmtc-b-report.json) contain actual results.
[Central query evidence](docs/evidence/issuer-profile-producer/central-b.json) records sample timestamps.
The comparison allows 10 ms for target timestamps with nanoseconds and samples with milliseconds.
[Raw evidence](docs/evidence/issuer-profile-producer/raw-evidence.tar.gz) retains commands, outputs, logs and the initial failures.

## Metric meaning

The four `cmtc_issuer_profile_` families measure producer attempts, write responses and timestamps.
They are absent when the producer is disabled.
A write acknowledgment does not prove consumption by Cilium or ztunnel.
A source-read timestamp does not prove valid approval.
A publication lease does not prove protected traffic.
[The metric contract](observability/METRICS.md) defines each family.

## Security gates

At the producer qualification (2026-10-24) the Cilium consumer, the ztunnel decoder and the ClusterMesh-plus-ztunnel
startup guard were still closed. That state is historical: the Cilium guard was replaced by capability validation
(`37d5fce0f7`), and ztunnel now runs with issuer pins in both clusters. Still open: per-connection peer-certificate
evidence, the behavior at approval expiry, recovery on the current images and WireGuard/IPsec composition. No mTLS or
`Protected` claim follows from producer tests. Read [delivery status](docs/agile/DELIVERY_STATUS.md).

## Approved cluster-intermediate support (historical, source `f5fe9992da`)

The producer source increment accepts the intended Option A hierarchy:
organization root → cluster intermediate → explicitly pinned SPIRE CA → workload SVID.
The existing direct-root form remains supported.
The cluster intermediate is public approved lineage. It is not a workload signer.

Approval includes exactly one parent certificate in `chainPEM`.
The verifier checks its exact root signature, key usage, validity and path depth.
It rejects missing, extra, cyclic, substituted and reused cross-cluster parents.
The parent expiry bounds the publication lease.
SPIRE's optional CA URI SAN must equal the independently approved trust domain.
It cannot contain a workload path or additional names.

The complete CMTC race suite passes 57 top-level tests and 172 subtests.
No test failed or was skipped. Three packages contain no tests.
Formatting and vet pass on the same ARM64 source snapshot.
[The source ledger and raw log](docs/evidence/approved-issuer-lineage/root-summary.json) retain the checks.
The new ARM64 image was deployed in all six containers. Their running binaries matched the source ledger.
The API/policy and 36 app paths pass after rollout. Both real clusters pass parented-profile publication, renewal, restart, invalid-input and recovery checks.
Fresh B-to-A producer telemetry is verified. Cleanup reports no errors.
[Cluster A report](docs/evidence/approved-issuer-lineage/cmtc-a-report.json), [Cluster B report](docs/evidence/approved-issuer-lineage/cmtc-b-report.json) and [raw evidence](docs/evidence/approved-issuer-lineage/raw-live-evidence.tar.gz) retain the actual output.
[Application output](docs/evidence/approved-issuer-lineage/baseline-test.log) retains the actual responses.
Live SPIRE certificates, matching Cilium/ztunnel consumers and actual traffic protection still need qualification.
