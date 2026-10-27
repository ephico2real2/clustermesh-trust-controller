# Issuer approval arbiter: live qualification on kind-cmtc-a and kind-cmtc-b, 2026-10-27

Record of [the runbook](../../development/ARBITER_QUALIFICATION_RUNBOOK.md), run by the live-writer session. Image:
`ghcr.io/ephico2real2/cmtc@sha256:a3efbe8c98249fbe931498edd9d35ab821bd7a506f6bbf33fbc0fb3ba7623719` (CI run 40554526163,
source `bb3cfd5`, artifact `cmtc-images-bb3cfd5…`).

## Step 2: kind-cmtc-a adopted into Helm, the arbiter off (17:56-18:01Z)

- First `cmtc_adopt.py plan`: the server-side apply fails with 6 conflicts (`kubectl-client-side-apply`: agent args,
  env `NODE_NAME`, `runAsNonRoot`, `runAsUser`; `kubectl-patch`: agent and controller image).
- `cmtc_adopt.py transfer`: 14 objects, managedFields only; first managedFields kept in
  `/private/tmp/cmtc-opus-final-20261025/review/cmtc-adoption-20261027T1800Z/`.
- Second plan: 87 changes, 0 kubectl manager entries left, 0 refusals. Spec changes: the image on both workloads; the
  node agent's trust-report args, mounts and uid 0; the controller's pod annotation `security.cmtc.io/live-issuer-owner`
  removed. Controller args unchanged.
- `helm upgrade --install cmtc … --server-side=true --take-ownership`: `STATUS: deployed`, `REVISION: 1` at 17:57:32Z.
- Controller log: `issuerProfileProducer=true issuerApprovalArbiter=false`; node agents `nodeTrustReport=true
  managePins=false`.
- NodeTrustReports `cmtc-a-control-plane`, `cmtc-a-worker`: pins `ReadOnly` with roots `0c28af9e…` and `6c12c735…`;
  ztunnel `Accepted`, generation 6, digest `5560480d…6bd9`, trusted issuers `2dee6086…e3d5` (cmtc-a) and
  `b9075e42…a006` (cmtc-b).
- Publication: `published 6 cmtc-issuer-approval-g6`, sequence 17797 at 17:58:27Z. ztunnel `lease fenced` lines in the
  5 minutes after the install: 0 on both nodes.
- [matrix-step2](matrix-step2/join.txt): 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed
  (probes 17:58:49-18:00:49Z).

Found: every node's pins file still holds the retired Lab Org Root `0c28af9e…`. With `managePins` the node agent
reports `WriteFailed`, which the arbiter refuses, so the lab values keep it off; the root is retired in the ztunnel fork
next (`/private/tmp/cmtc-opus-final-20261025/review/root-retirement/BRIEF.md`).

The root was retired on every node at 19:05-19:21Z
([root-pin-retirement-20261027](../root-pin-retirement-20261027/README.md)): the cmtc-a NodeTrustReports now read pins
`ReadOnly` with `6c12c735…` only; `managePins` stays off.

## Step 3: the peer credential of kind-cmtc-a on kind-cmtc-b (19:42-19:44Z)

- First run, 19:42:44Z: the script stopped after it created the token Secret on cmtc-a. Its go-template for the CA,
  `{{(index .clusters 0).cluster "certificate-authority-data"}}`, calls a field with an argument ("cluster is not a
  method but has arguments"). Fixed to `{{index (index .clusters 0).cluster "certificate-authority-data"}}`, checked
  first by decoding the CA alone (`CN=kubernetes`, to 2036-10-21).
- Second run, 19:43:14Z, exit 0: `installed cmtc-system/cmtc-peer-cmtc-a on kind-cmtc-b: cmtc-peer-reader of
  kind-cmtc-a at https://172.18.0.3:6443 (token Secret cmtc-system/cmtc-peer-reader-token on kind-cmtc-a)`. The token
  Secret is `kubernetes.io/service-account-token` for `cmtc-peer-reader`, filled; the reader's checks (Certificates
  yes, Secrets no) passed before the install. Nothing of the token was printed.
- Probe from a Pod on cmtc-b with cmtc-a's CA only: `/version` returned `200`, not the `401` the runbook expected.
  The expectation was wrong: on cmtc-a the ClusterRole `system:public-info-viewer` (`/healthz`, `/livez`, `/readyz`,
  `/version`) is bound to `system:unauthenticated`. `/apis` without a token returned `403` (the API server allows
  anonymous requests; RBAC refuses `system:anonymous`). Both prove TLS to `172.18.0.3:6443` verified with cmtc-a's CA.
  The runbook now expects `200`.

