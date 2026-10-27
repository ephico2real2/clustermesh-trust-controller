# Arbiter live qualification on the labs, kind-cmtc-b first

<!-- CMTC_DOC_CONTEXT -->
Runbook for the **proposed** behavior of [ADR-012](../architecture/adr/ADR-012.md) (acceptance gate 4). Read
[current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

**Status:** written 2026-10-27 from the branch `feat/arbiter-qualification`; **not executed**. Every value below was
read from the labs on 2026-10-27 with read-only `kubectl get` and `helm list` (`--kubeconfig
/private/tmp/cmtc-a-b-20261024.kubeconfig`, never printed; no Secret read). The executor records each step's actual
output under `docs/evidence/approval-arbiter-<date>/` and updates the delivery status.

## Ownership and prerequisites

- Owner: the live-writer session, with the operator's go for every step marked **outage risk**.
- Clusters: `kind-cmtc-a` and `kind-cmtc-b`, ClusterMeshed, workload mTLS on; the 96/96 matrix of 2026-10-27T16:57Z is the
  baseline (`docs/evidence/local-activation-20261025/live-tests/`).
- Tools: `kubectl`, `helm` v4.3.0 (`--take-ownership`), `gh`, `cmctl`, Python 3; the repository at the final commit of
  `feat/approval-follows-cert-manager` plus this branch, checked out and clean.
- Rules: no hand-applied objects (`/helm-first`); the CMTC image by GHCR digest from CI (`/registry-first`); the
  kubeconfig is never printed; no Secret is ever printed; no SPIRE Admin socket is exposed; checkpoints, floors and
  bootstrap markers are never reset.

## What the labs are today (read 2026-10-27, 17:25-17:40Z)

| Fact | kind-cmtc-a | kind-cmtc-b |
|---|---|---|
| Nodes (UID) | `cmtc-a-control-plane` (`1e707131-badc-45d7-b543-758f6267f1d6`), `cmtc-a-worker` (`35a6f095-90e9-41ff-a713-216cde5596f0`), v1.36.4 | `cmtc-b-control-plane` (`aa856ae0-f1e6-4ece-bca7-266a9d7a03d2`), `cmtc-b-worker` (`fcbbc49e-268c-411b-9083-1346f53bbb88`), v1.36.4 |
| API endpoint for the peer's Pods | `https://172.18.0.3:6443` (`kubectl get endpoints kubernetes`) | `https://172.18.0.4:6443` |
| `<cluster>-spire-intermediate` Certificate UID, revision, notAfter | `2935a275-f8d9-4dc0-be9a-1dc05ddece31`, 1, `2027-10-26T12:49:41Z` | `9e6d7081-af84-4f6d-a89f-eab1b15b8554`, 1, `2027-10-26T12:49:42Z` |
| Mesh root Certificate (`cmtc-mesh-root-ca`) | `f5242956-0c5f-400e-a1e9-73be3a4f8cca`, notAfter `2036-10-23T12:49:41Z` | same object class, `rotationPolicy: Never` |
| Root pin (SHA-256) | `6c12c7353967466f9177847c3c1e3c0acdb54af6eaef94b126f0449bf636275f` | same |
| Adopted approval `cmtc-issuer-approval-g6` UID, created, expires | `e8320c32-79ff-4382-8702-78da8ef14567`, `2026-10-27T10:26:41Z`, `2026-11-25T10:26:41Z` | `cf026f16-e023-4d88-8dd7-30f1e1e5c1b8`, `2026-10-27T10:26:55Z`, same expiry |
| Publication `cmtc-issuer-publication` UID (accepted generation 6, digest `5560480d…6bd9`) | `fbc7b3c2-00f1-4787-a149-fca76e274c4e` | `cb6e0317-d887-49be-b265-d24d896c35ef` |
| SPIRE intermediate SPKI pinned in g6 | `2dee6086e79ab8ff277646f0cc745c494136f9b51962eb1e7d94bb34f689e3d5` | `b9075e425be5f66294d2234f1418e31d809655b920dd57efaeff4e550bb9a006` |
| SPIRE `server.conf` | no `ca_ttl` line, so the CA bound is SPIRE's default 24 h (`internal/controller/approval_evidence.go:40-42`, `:59-60`) | same |
| CMTC image deployed | `ghcr.io/ephico2real2/cmtc@sha256:113b94c09da2cd0683a5e9f7af01c526941c928129f7cbb3679026a2ce0ac312` | same |
| Controller args | `--issuer-profile-source=cmtc-issuer-approval-g6 … --issuer-profile-minimum-generation=6` (no arbiter) | same |
| Node agent args | `--mode=node --cluster-name=cmtc-a` (no trust report) | same |
| Helm releases | cert-manager, cilium (rev 8), cmtc-trust, trust-manager. **No `cmtc` release**: every CMTC object carries `kubectl.kubernetes.io/last-applied-configuration` and no Helm metadata | same |
| ztunnel pins and checkpoint on the nodes | `/etc/cmtc/ztunnel-issuer-pins/pins.json`, `/var/lib/cmtc/ztunnel-issuer-checkpoint` (ztunnel DaemonSet env and hostPaths) | same |
| SPIRE registrar | not deployed: `spire-server` StatefulSet runs `spire-server` and a busybox `register-agent-node`; no `cmtc-spire-registrar` image on either cluster | same |
| `NodeTrustReport` and `IssuerApproval` CRDs | absent | absent |

The Cilium agent reads the approval through the lab Role `cilium-ztunnel-issuer-profile` (managed-by
`cmtc-local-qualification`; `get` on `cmtc-issuer-approval-g6` and `cmtc-issuer-publication`). The chart renders
`cmtc-issuer-profile-readers` for `kube-system/cilium` with `g6`, both slots and the publication, so the Cilium agent can
follow the slots; the lab Role is left in place.

## Order, and why

1. **kind-cmtc-a, no behavior change:** adopt the hand-applied objects into a Helm release and add what cmtc-b's arbiter
   needs from cmtc-a: the `NodeTrustReport` CRD and the node agents' reports (the gate reads every node of every
   cluster), and the `cmtc-peer-reader` identity. The arbiter stays off; the producer keeps `g6` as its source.
2. **kind-cmtc-b, the arbiter on:** adopt, install the peer credential of cmtc-a, enable the arbiter with
   `adoptSource` = `g6`. The first write is generation 7 with the same issuers (`ReasonAdopt`:
   `internal/controller/issuer_approval.go:684` sets `Force` when the publication is live and no slot is current;
   `internal/trustprofile/plan.go:329-330`). ztunnel's trust does not change: same root, same two intermediate keys.
3. **kind-cmtc-a, the arbiter on**, the same way, with cmtc-b's credential.
4. The forced intermediate renewal on cmtc-b, the overlap, the retirement, the recovery tests.

Each step is one action with its command and its expected output. Stop at the first unexpected output.

## Step 1: publish the image of the final commit

The images workflow runs on push to `main` or `ci/images`, or by `workflow_dispatch` with `source_sha`, which GitHub
runs only from the default branch (`.github/workflows/images.yaml:6-16`). The final commit is not on `main`, so:

1. `git push origin <final-sha>:refs/heads/ci/images` — expected: the push is accepted; `gh run list --workflow
   images.yaml --limit 1` shows a run for `<final-sha>` and it ends `completed success`.
2. `gh run download <run-id> -n cmtc-images-<final-sha> -D /tmp/cmtc-lock` — expected: `/tmp/cmtc-lock/images.lock.json`
   exists.
3. `python3 -c 'import json; print(json.load(open("/tmp/cmtc-lock/images.lock.json"))["images"]["cmtc"]["image"])'` —
   expected: `ghcr.io/ephico2real2/cmtc@sha256:<64 hex>`. Export it: `CMTC_IMAGE=<that value>`;
   `IMAGE_VALUES=(--set "image.repository=${CMTC_IMAGE%@*}" --set "image.digest=${CMTC_IMAGE#*@}")` (the form
   `scripts/lab/up.sh:120-121` uses).

## Step 2: kind-cmtc-a, adoption and the reader identity (no behavior change)

The chart values are `config/lab/cmtc/values-cmtc-a.yaml` (UIDs from the table above). For this step the arbiter is
off, so override it on the command line.

The CMTC objects were applied with `kubectl apply` and `kubectl patch`, so those managers own fields that the release
changes (the image, the node agent's args, its security context). `helm upgrade --dry-run=server` does not send the
apply and shows no conflict (`/helm-first`); `scripts/lab/cmtc_adopt.py` does the server-side dry run as manager `helm`
and gives `helm` the kubectl managers' fields first. `A=(cmtc-a config/lab/cmtc/values-cmtc-a.yaml --kubeconfig
/private/tmp/cmtc-a-b-20261024.kubeconfig --set "image.repository=${CMTC_IMAGE%@*}" --set
"image.digest=${CMTC_IMAGE#*@}" --set controller.issuerApproval.enabled=false)`.

1. Plan the adoption: `venv/bin/python scripts/lab/cmtc_adopt.py plan "${A[@]}"` — expected on the first run: `Apply
   failed with … conflicts` naming `kubectl-client-side-apply` and `kubectl-patch` (measured 2026-10-27T17:56Z: the
   agent's args, env, `runAsNonRoot`, `runAsUser` and image; the controller's image).
2. Transfer the fields: `venv/bin/python scripts/lab/cmtc_adopt.py transfer "${A[@]}" --backup-dir <review dir>` —
   expected: one line per object, `fields of … given to helm`; only `metadata.managedFields` changes.
3. Plan again — expected: `0 kubectl manager entr(ies) left; 0 refusal(s)`; the spec changes are only the image on
   both workloads, the node agent's trust-report args, mounts and uid 0, and the controller's pod annotation
   `security.cmtc.io/live-issuer-owner` (the host publisher's marker) removed; the controller args are unchanged; new
   objects: the two CRDs, the reader identity, the report policy.
4. Apply it: `helm upgrade --install cmtc charts/cmtc -n cmtc-system --kube-context kind-cmtc-a -f
   config/lab/cmtc/values-cmtc-a.yaml "${IMAGE_VALUES[@]}" --set controller.issuerApproval.enabled=false
   --server-side=true --take-ownership --wait --timeout 5m` — expected: `STATUS: deployed`, `REVISION: 1`.
5. `kubectl --context kind-cmtc-a get crd nodetrustreports.security.cmtc.io issuerapprovals.security.cmtc.io` — expected:
   both listed.
6. `kubectl --context kind-cmtc-a -n cmtc-system rollout status ds/cmtc-node-agent deploy/cmtc-controller` — expected:
   both `successfully rolled out`; the controller log's first line has `issuerApprovalArbiter=false`,
   `nodeTrustReport=false` for the controller and the node agent's has `nodeTrustReport=true managePins=false`
   (`cmd/cmtc/main.go:148`).
7. `kubectl --context kind-cmtc-a get nodetrustreports -o yaml` — expected: two reports, named after the nodes;
   `status.pins.state: ReadOnly` with `rootSHA256` [`6c12c735…`] (the retired Lab Org Root `0c28af9e…` was removed
   from every node's pins file on 2026-10-27,
   [evidence](../evidence/root-pin-retirement-20261027/README.md); the step-2 run at 17:55Z, before that, read both
   roots). `managePins` stays off, the chart default: the administrator writes the pins file, and `accepts` in
   `internal/controller/approval_evidence.go:303` takes `ReadOnly`. `status.ztunnel.state: Accepted`,
   `acceptedGeneration: 6`, `trustedIssuers` with the two SPKIs of the table, `observedAt` advancing every 30 s.
8. `kubectl --context kind-cmtc-a -n cmtc-system get cm cmtc-issuer-publication -o jsonpath='{.data.profile\.json}' | python3 -c 'import json,sys; p=json.load(sys.stdin); print(p["state"], p["acceptedGeneration"], p["source"]["name"])'`
   — expected: `published 6 cmtc-issuer-approval-g6` (unchanged).
9. `bash scripts/evidence/run_mtls_matrix.sh docs/evidence/approval-arbiter-<date>/matrix-step2` — expected: 96/96
   allowed, 36/36 denied, as the baseline.

## Step 3: kind-cmtc-b, the peer credential of kind-cmtc-a

One scripted administrator step, `scripts/lab/pki/peer-reader-credential.sh` (first run 2026-10-27T19:43Z): a
durable `kubernetes.io/service-account-token` Secret for `cmtc-peer-reader` on the source (revoked by deleting it), a
kubeconfig with the source's CA and the endpoint the target's Pods reach, checked (`auth can-i get certificates` yes,
`get secrets` no) and installed as the target's peer Secret. Nothing of the token is printed.

1. `KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig bash scripts/lab/pki/peer-reader-credential.sh --source kind-cmtc-a --target kind-cmtc-b --server https://172.18.0.3:6443 --secret cmtc-peer-cmtc-a`
   — expected: one line `installed cmtc-system/cmtc-peer-cmtc-a on kind-cmtc-b: cmtc-peer-reader of kind-cmtc-a at
   https://172.18.0.3:6443 (token Secret cmtc-system/cmtc-peer-reader-token on kind-cmtc-a)`.
2. Reachability of the endpoint from a Pod on cmtc-b, with the CA only (the script cannot reach a kind node IP from the
   host): `kubectl --context kind-cmtc-b -n cmtc-system run peer-probe --rm -i --restart=Never --image=curlimages/curl:8.11.1 --overrides='{"spec":{"volumes":[{"name":"peer","secret":{"secretName":"cmtc-peer-cmtc-a"}}],"containers":[{"name":"peer-probe","image":"curlimages/curl:8.11.1","command":["sh","-c","python3 -V >/dev/null 2>&1; sed -n \"s/.*certificate-authority-data\\\": \\\"\\([^\\\"]*\\)\\\".*/\\1/p\" /peer/kubeconfig | base64 -d > /tmp/ca.crt; curl -s -o /dev/null -w \"%{http_code}\\n\" --cacert /tmp/ca.crt https://172.18.0.3:6443/version"],"volumeMounts":[{"name":"peer","mountPath":"/peer","readOnly":true}]}]}}'`
   — expected: `200` (TLS verified against cmtc-a's CA; `/version` is public: the ClusterRole
   `system:public-info-viewer` is bound to `system:unauthenticated`). `000` or a certificate error means the endpoint
   or the CA is wrong: stop. The token itself is exercised by the arbiter in step 4.

## Step 4: kind-cmtc-b, the arbiter on

1. Steps 2.1 to 2.3 on cmtc-b: `B=(cmtc-b config/lab/cmtc/values-cmtc-b.yaml --kubeconfig
   /private/tmp/cmtc-a-b-20261024.kubeconfig --set "image.repository=${CMTC_IMAGE%@*}" --set
   "image.digest=${CMTC_IMAGE#*@}")`, plan, transfer, plan — expected: no conflict, no refusal; the Deployment args end
   with `--issuer-approval-config=/etc/cmtc/issuer-approval/config.json` and carry no `--issuer-profile-source`; volumes
   `issuer-approval-config` and `peer-cmtc-a`; the producer Role names `g6` and both slots.
2. `helm upgrade --install cmtc charts/cmtc -n cmtc-system --kube-context kind-cmtc-b -f config/lab/cmtc/values-cmtc-b.yaml
   "${IMAGE_VALUES[@]}" --server-side=true --take-ownership --wait --timeout 5m` — expected: `STATUS: deployed`,
   `REVISION: 1`.
3. `kubectl --context kind-cmtc-b -n cmtc-system logs deploy/cmtc-controller | head -3` — expected:
   `starting experimental CMTC … issuerApprovalArbiter=true`; no `peer cmtc-a kubeconfig` error (`cmd/cmtc/main.go:183`).
4. `kubectl --context kind-cmtc-b get nodetrustreports` — expected: `cmtc-b-control-plane`, `cmtc-b-worker`.
5. Within two passes (15 s each) plus one heartbeat (30 s; ADR-012, Lifecycle):
   `kubectl --context kind-cmtc-b -n cmtc-system get issuerapproval cmtc -o yaml` — expected, in order:
   `EvidenceReady=True` for both clusters; `NodesConverged=True`; then `status.pending` names
   `cmtc-issuer-approval-a` with generation 7, reason `Adopt`; then `status.current` is that slot and
   `status.pending` is empty once the publication names it (phase `Distributing` then `Converged`). `Blocked=True`
   with a reason names the gate that refuses: record it and stop.
6. `kubectl --context kind-cmtc-b -n cmtc-system get cm cmtc-issuer-approval-a -o jsonpath='{.data.approval\.json}' | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a["generation"], a["expiresAt"], [(c["clusterID"], [i["spkiSHA256"] for i in c["issuers"]]) for c in a["clusters"]])'`
   — expected: `7 <now + 696h, UTC, whole seconds> [('cmtc-a', ['2dee6086…e3d5']), ('cmtc-b', ['b9075e42…a006'])]`:
   the same issuers as g6. Record `expiresAt`: generation 7 is the **renewal of g6**; the next renewal is due 168 h
   before that time (`renewBefore`, `plan.go:331-333`).
7. The publication follows: the command of step 2.8 on cmtc-b — expected: `published 7 cmtc-issuer-approval-a`.
8. The nodes accept it: step 2.7 on cmtc-b — expected: `acceptedGeneration: 7` on both reports, `Accepted`,
   `trustedIssuers` unchanged.
9. `kubectl --context kind-cmtc-b -n kube-system logs ds/ztunnel-cilium --since=10m | grep -c 'lease fenced'` —
   expected: `0` (the promotion is a publication with a new generation, not a lease gap).
10. The matrix (step 2.9, out dir `matrix-step4`) — expected: 96/96, 36/36.
11. The node report write restriction, on the lab: a Pod under the `cmtc-node-agent` ServiceAccount on `cmtc-b-worker`
    writes another node's report:
    `kubectl --context kind-cmtc-b -n cmtc-system run agent-probe --rm -i --restart=Never --image=curlimages/curl:8.11.1 --overrides='{"spec":{"serviceAccountName":"cmtc-node-agent","nodeName":"cmtc-b-worker","containers":[{"name":"agent-probe","image":"curlimages/curl:8.11.1","command":["sh","-c","T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -o /tmp/out -w \"%{http_code}\\n\" --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H \"Authorization: Bearer $T\" -H Content-Type:application/json -X POST https://kubernetes.default.svc/apis/security.cmtc.io/v1alpha1/nodetrustreports -d \"{\\\"apiVersion\\\":\\\"security.cmtc.io/v1alpha1\\\",\\\"kind\\\":\\\"NodeTrustReport\\\",\\\"metadata\\\":{\\\"name\\\":\\\"not-my-node\\\"},\\\"status\\\":{\\\"cluster\\\":\\\"cmtc-b\\\",\\\"observedAt\\\":\\\"2026-01-01T00:00:00Z\\\",\\\"pins\\\":{\\\"state\\\":\\\"Absent\\\"},\\\"ztunnel\\\":{\\\"state\\\":\\\"Absent\\\"}}}\"; grep -o \"denied request: [^\\\"]*\" /tmp/out"]}]}}'`
    — expected: `403` and `denied request: a CMTC node agent may write only the NodeTrustReport named after the node
    its token is bound to` (the policy answers `Forbidden` since this branch; the kind record of 2026-10-27 shows 422
    for the earlier render, ADR-012 "Node report write enforcement"). Then
    `kubectl --context kind-cmtc-b get nodetrustreport not-my-node` — expected: `NotFound`.

## Step 5: kind-cmtc-a, the arbiter on

1. Step 3 with the clusters swapped: `--source kind-cmtc-b --target kind-cmtc-a --server https://172.18.0.4:6443
   --secret cmtc-peer-cmtc-b`, and the probe from a Pod on cmtc-a against `https://172.18.0.4:6443/version` — expected
   as in step 3.
2. `helm upgrade cmtc charts/cmtc -n cmtc-system --kube-context kind-cmtc-a -f config/lab/cmtc/values-cmtc-a.yaml "${IMAGE_VALUES[@]}" --wait --timeout 5m`
   (the arbiter is on in the values file; no overrides) — expected: `REVISION: 2`.
3. Steps 4.3 to 4.10 on cmtc-a — expected: generation 7 in `cmtc-issuer-approval-a` of cmtc-a, reason `Adopt`, the
   same issuers; both clusters' records `Converged`; the matrix 96/96 (`matrix-step5`).

From here the delivery status records: implemented, deployed on both labs by digest `<CMTC_IMAGE>`, adoption
traffic-qualified by `matrix-step5`.

## Step 6: the forced intermediate renewal on kind-cmtc-b (outage risk: none expected; the operator's go)

`cmtc-b-spire-intermediate` has `rotationPolicy: Always` (`charts/cmtc/templates/trust.yaml:24`): the renewal has a new
key. cert-manager's built-in approver approves it. SPIRE keeps signing with its current CA under the old key until
it prepares and activates the next one (ADR-012, "Problem, as measured"), so both keys must stay approved for at least
`ca_ttl` = 24 h after the arbiter first read the new one.

1. Before: `kubectl --context kind-cmtc-b -n cert-manager get certificate cmtc-b-spire-intermediate -o jsonpath='{.status.revision} {.status.notAfter}{"\n"}'`
   — expected: `1 2027-10-26T12:49:42Z`.
2. `cmctl --context kind-cmtc-b renew cmtc-b-spire-intermediate -n cert-manager` — expected: `Manually triggered
   issuance of Certificate cert-manager/cmtc-b-spire-intermediate`.
3. `kubectl --context kind-cmtc-b -n cert-manager wait certificate/cmtc-b-spire-intermediate --for=condition=Ready --timeout=2m`,
   then step 6.1 — expected: `2 <new notAfter, about now + 8760h>`. Record the time `T_renew`.
4. Within one pass: step 4.5 on cmtc-b — expected: `status.pending` generation 8 in `cmtc-issuer-approval-b`, reason
   `IssuerAdded`; then `status.current` = slot b; the ledger entry of the old cmtc-b key has `retireAfter` =
   (first pass that read the successor) + 24 h + 1 h (`retirementMargin`), so about `T_renew + 25h`. Record it.
5. Step 4.6 on slot b — expected: generation 8; cmtc-b has **two** issuers: `b9075e42…a006` and the new SPKI; cmtc-a
   unchanged.
6. The nodes: step 2.7 on both clusters — expected: `acceptedGeneration: 8` on cmtc-b; cmtc-a's arbiter follows with
   its own generation 8 (`IssuerAdded`, both cmtc-b keys) and cmtc-a's nodes accept it; every `trustedIssuers` lists
   three SPKIs.
7. The matrix (`matrix-step6-overlap`) — expected: 96/96 while SPIRE still signs under the old key.
8. SPIRE's CA under the new key: `kubectl --context kind-cmtc-b -n cilium-spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server bundle show -format spiffe`
   (the server's own CLI on its local socket; no Admin socket exposed) — expected: the bundle's x509 authorities
   change from one to two CAs within `ca_ttl`/2 = 12 h (prepare) and the new one becomes the signer by 24 h (activate).
   Record when the ztunnel logs first show a peer SVID chained to the new intermediate (the ztunnel log view,
   `scripts/evidence/ztunnel_log_view.py`).
9. The matrix again after the activation (`matrix-step6-new-ca`) — expected: 96/96 with the new chain.
10. Retirement, due at `retireAfter` (about `T_renew + 25h`) **and** every node of both clusters reporting the
    successor among its `trustedIssuers`: step 4.5 on cmtc-b — expected: generation 9 in slot a, reason
    `IssuerRetired`; cmtc-b back to one issuer (the new SPKI); phase `Converged`; cmtc-a follows with its generation 9.
    Before `retireAfter` the record shows `Blocked` with `RetirementWaiting` (ADR-012, planner test
    `TestUnknownCATTLHoldsRetirementAfterAKnownBound` for the bound's semantics).
11. The matrix after retirement (`matrix-step6-retired`) — expected: 96/96, 36/36.

## Step 7: recovery tests (each on kind-cmtc-b, after step 6 or during its overlap)

1. **Controller restart.** `kubectl --context kind-cmtc-b -n cmtc-system rollout restart deploy/cmtc-controller && kubectl --context kind-cmtc-b -n cmtc-system rollout status deploy/cmtc-controller`
   — expected: rolled out; the publication lease is never missed: step 4.9 — expected `0` fence lines (the leader
   releases its lease on stop and the successor publishes within 8 s + 1 s + its first pass,
   `internal/controller/issuer_profile.go:20-33`); the record returns to its phase after one heartbeat (30 s) with no
   new generation (`status.current` unchanged). Record the gap between the last and the first `sequence` of the
   publication across the restart (`kubectl get cm cmtc-issuer-publication` twice).
2. **Node agent restart.** `kubectl --context kind-cmtc-b -n cmtc-system rollout restart ds/cmtc-node-agent` —
   expected: the reports' `observedAt` pause and resume; `resourceVersion` changes; no generation is written; with a
   report older than `reportMaxAge` (2 min) the record shows `Blocked` (`NodesConverged=False`) and recovers when the
   agent reports again. Traffic unaffected (matrix optional).
3. **Peer unreachable.** Deny the controller's egress to cmtc-a's API for 3 min with a NetworkPolicy, then remove it:
   `kubectl --context kind-cmtc-b -n cmtc-system apply -f - <<'EOF'` … a `NetworkPolicy` named `cmtc-qualify-no-peer`
   selecting `app.kubernetes.io/name: cmtc-controller`, `policyTypes: [Egress]`, egress to everything except
   `172.18.0.3/32` (`ipBlock` with `except`) … `EOF` — expected within one pass: `EvidenceReady=False` with reason
   `EvidenceUnavailable` for `cmtc-a` on cmtc-b's record; `status.current` unchanged; no slot written; the matrix
   96/96 (a peer down never changes what is approved, ADR-012 Lifecycle). `kubectl --context kind-cmtc-b -n cmtc-system delete networkpolicy cmtc-qualify-no-peer`
   — expected: `EvidenceReady=True` within one pass plus one heartbeat.

## Renewal of generation 6 before 2026-11-25

Generation 6 (expires `2026-11-25T10:26:41Z`) is superseded at step 4.6 by generation 7, whose expiry is the write
time + 696 h (29 days; capped by the intermediates' `notAfter` of 2027-10-26 and the root's, `plan.go:183-185`,
`:294-295`). The arbiter renews every generation when less than 168 h remains (`renewBefore`; `plan.go:331-333`): for a
step-4 write on 2026-10-28, generation 7 expires about 2026-11-26 and its renewal is written about 2026-11-19, as
`ReasonRenewal` into the free slot, with the same issuers. Nothing is scheduled by hand; the evidence of each renewal is
the slot's `approval.json` and the record's `status.current`. A renewal that waits (`RenewalWaitsForEvidence`) with
a peer down is the fail-closed path: the approval then expires and workload mTLS stops within 30 s (ADR-012,
"Approval expiry, as coded"), so a peer that is down for more than 168 h before an expiry is the operator's alert.

## Not run, and open

- This runbook has not been executed; `scripts/lab/pki/peer-reader-credential.sh` has not been run (syntax checked
  only). Step 3.2 and 4.11 use `curlimages/curl:8.11.1` from Docker Hub: a pull on the lab.
- The forced renewal (step 6) makes SPIRE sign under the new key only after it prepares and activates its next CA
  (up to 24 h); the retirement is due about 25 h after the renewal. The runbook spans two days.
- What an expired approval does is answered from the code, not measured (ADR-012, Lifecycle). Measuring it stops the
  lab's traffic: the operator's call.
