# CMTC working agreements

Start with `docs/handover/CODEX_MASTER_PROMPT.md` and the current handover/agile backlog.

- Use **Podman from the MacBook host for image builds** and containerized local checks. Set the Linux target architecture explicitly and verify the resulting image/source pin.
- Finish affected local tests, required lint/vet, the image build and applicable integration/load/packet/screenshots before pushing changes that trigger CI, dispatching workflows or publishing images. Reproduce failures locally before another CI run.
- Preserve existing kind labs and their runtime provider. Transfer Podman-built images by archive into the owned cluster; verify the deployed image ID. Inspect shared-machine resources and preserve unrelated running applications.
- The reusable personal skill is `$cmtc-podman-local-validation`; apply it for CMTC/Cilium image and local qualification work.
- Use Cilium's injected `*slog.Logger`, standard logfields and Hive health/jobs for Cilium Go extensions. Preserve CMTC's controller logging integration. Retry logs must identify stage, attempt, elapsed time, backoff/deadline and error; never expose keys or credentials.
- Readiness, authenticated SPIRE responses, registrations, SVID validation, xDS ACKs and actual traffic protection are separate evidence. Keep the existing security gates and never infer `Protected` from a label or ACK.
