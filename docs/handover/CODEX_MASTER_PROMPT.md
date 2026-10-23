# Copy/paste into Codex

You are continuing the CMTC project. First read README.md, docs/handover/BACKGROUND_AND_DECISIONS.md, docs/handover/CODEX_START_HERE.md, docs/architecture/END_TO_END_DESIGN.md, docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md, docs/agile/BACKLOG.md, docs/agile/STORY_BACKGROUND_AND_GHERKIN.md, and docs/research/VERIFICATION_QUEUE.md. Review all nine proposed ADRs and the observability folder.

Preserve decisions: no Linkerd/Istio, Go + Cilium Hive where embedded, controller-runtime for operator, SPIRE/cert-manager Option A, protected shared root with cluster intermediates, trust-manager, namespace auto-labeling via existing LOB/mnemonic metadata, exclusion precedence, Kubernetes/OpenShift control-plane safety, lightweight DaemonSet, optional WireGuard/IPsec, no silent downgrade, and nine Grafana dashboards.

FIRST TASK: inspect the actual repository and pinned Cilium source, identify verified versus speculative interfaces and gaps, propose an incremental implementation plan and first design PR. Do not claim the CRDs, dashboards or cross-cluster mTLS work until implemented/tested. Do not distribute CA private keys. Never mark a namespace Protected from its label alone. Add CI, tests, source citations, Go module and CRD schemas only after confirming the architecture. Use feature/epic/story/subtask backlog and explicit acceptance criteria.
