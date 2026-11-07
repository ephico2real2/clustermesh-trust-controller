# Fork CI, 2026-11-07

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Result: each failure on the Cilium and ztunnel forks whose cause was found came from a missing upstream resource, not
from CMTC or fork code; two causes were not determined (below). GitHub had also stopped Actions on the ztunnel fork, which held back the
image for the [ztunnel certificate fix](../ztunnel-cert-refresh-20261104/README.md).

State: **measured** on 2026-11-06 and 2026-11-07. All times are UTC.

## ztunnel fork: GitHub had stopped Actions

No run started on `ephico2real2/ztunnel` after 2026-10-27, for the pushes on 2026-11-04 and 2026-11-05. The fork's
Actions page, when logged in, said:

> Workflows are not currently being run on this fork due to the scale of GitHub Actions usage.

The API did not show this: `actions/permissions` said enabled, and each workflow said `active`. Only one sign was
visible there: the commits had a `claude` check suite and no `github-actions` one. The operator re-enabled workflows on
that page. The next push (2026-11-07 02:25:18Z) started a run within 2 seconds. Pushes made while workflows were off did
not run later.

Not determined: what triggered the notice, and whether the Cilium fork's usage below contributed to it.

## ztunnel fork: failing jobs

Up to 2026-10-27, `Image CI Build` failed at `Get a quay.io robot token via OIDC`, and `E2E Tests` waited 30 minutes for
that image and was cancelled. The Quay robot is federated with `cilium/ztunnel` only. Fork commit `be2b197` adds
`if: github.repository == 'cilium/ztunnel'` to the image push and to the wait. On a fork the binaries are still built
and the Rust checks still run; E2E does not.

## Cilium fork: upstream's schedules

256 runs from 2026-11-03 ([runs](cilium-runs.tsv)), none on a feature branch:

| Trigger | Failed | Cancelled | Passed | Unfinished |
|---|---|---|---|---|
| Scheduled, on `main` (`51170b1`) | 87 | 135 | 17 | 0 |
| Dispatched by Ariane, on `v1.18`, `v1.19`, `v1.20` | 14 | 0 | 2 | 1 |

The failed step of each workflow's newest failed or cancelled run was read ([inventory](cilium-inventory.json)); logs
were read for seven workflows:

| Cause | Examples |
|---|---|
| Cloud or bot login, no credentials on the fork | `Login to Azure`, `Set up AWS CLI credentials`, `Set up gcloud credentials`, `Get token` (Renovate) |
| Waiting for an image never built for this commit | `Wait for images` runs 30 minutes; `quay.io/cilium/cilium-cli-ci:51170b12…` does not resolve |
| A repository variable the fork does not have (0 variables) | `integration-test`: `runs-on: ${{ vars.UBUNTU_2604_AMD64_4CPU_16GB }}`, 0 successes ever |
| Dispatch to a workflow already disabled | `ariane-scheduled`: HTTP 422 |

Not determined: why `Install Cilium` and `Install cert-manager` failed in `conformance-clustermesh` on `v1.20`. That
workflow also failed on `v1.19`, and passed on `v1.18`. Whether those branches hold only upstream code was not checked.

The operator disabled [33 workflows](disable-list.tsv) on 2026-11-07, leaving 51 active and 45 disabled. The auto-mode
classifier refused the same command from the assistant. Left on: `cmtc-development-images`, `cmtc-ztunnel-protocol`,
`tests-datapath-verifier` (9 passes, 1 flaky Go download), `close-stale-issues`, and the scheduled workflows with no run
in the window. To restore them:

```sh
docs/evidence/fork-ci-20261107/cilium-fork-workflows.sh enable docs/evidence/fork-ci-20261107/disable-list.tsv
```

To check: read the fork's Actions page, logged in, before relying on the API when a fork's pushes start no run.
