# CMTC working agreements

Start with `docs/handover/CODEX_MASTER_PROMPT.md` and the current handover/agile backlog.

- Use **Podman from the MacBook host for image builds** and containerized local checks. Set the Linux target architecture explicitly and verify the resulting image/source pin.
- Finish affected local tests, required lint/vet, the image build and applicable integration/load/packet/screenshots before pushing changes that trigger CI, dispatching workflows or publishing images. Reproduce failures locally before another CI run.
- Preserve existing kind labs and their runtime provider. Transfer Podman-built images by archive into the owned cluster; verify the deployed image ID. Inspect shared-machine resources and preserve unrelated running applications.
- The reusable personal skill is `$cmtc-podman-local-validation`; apply it for CMTC/Cilium image and local qualification work.
- Use Cilium's injected `*slog.Logger`, standard logfields and Hive health/jobs for Cilium Go extensions. Preserve CMTC's controller logging integration. Retry logs must identify stage, attempt, elapsed time, backoff/deadline and error; never expose keys or credentials.
- Readiness, authenticated SPIRE responses, registrations, SVID validation, xDS ACKs and actual traffic protection are separate evidence. Keep the existing security gates and never infer `Protected` from a label or ACK.
- For Grafana presentation, apply the user's [diagram-kit dashboard skill](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/skill/dashboard/SKILL.md): inventory actual metrics, explain counter/window semantics, use fixed Tableau colours and lower legends, validate real queries, and inspect both-theme screenshots after load. Keep attempts, policy rejections, HTTP requests and TLS handshakes distinct; pie outcomes must partition one stated denominator without double counting.

## Active end-to-end delivery mandate — October 24, 2026

Continue the full CMTC security implementation autonomously through the existing agile stories and their acceptance gates. Dashboard completion is one delivered increment, not completion of CMTC. Complete each story locally first: meaningful unit/race and failure tests, required lint/vet, Podman image build, deployment of that exact image, real positive/negative traffic and applicable packet/identity/logging evidence. Commit qualified increments under the user's identity and continue to the next dependency. CI is deferred for now at the user's explicit request; do not push branches that trigger CI or dispatch workflows while this local qualification mandate is active. Preserve the existing local fixtures and unrelated applications. Keep unmet gates open and do not relax guards or report Protected from intent or acknowledgments.
