# Remote Workload xDS Observability Design Note

This note records the mock-injection telemetry proposal for [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15). It is a design review, not an implementation recipe: the pasted Go is illustrative and must not be copied into the Cilium fork as-is. The test-only xDS probe is tracked in [issue #14](https://github.com/ephico2real2/clustermesh-trust-controller/issues/14); the native discovery and federated mTLS work is tracked in [issue #13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13).

## Existing observability contract

The current inventory has nine historical domains, 31 unique planned metric names across 36 domain assignments, and two consolidated dashboard pages: `operations.json` and `workload-security.json`. All nine original dashboard definitions remain in place. `capabilities.json` maps domain coverage; `metrics.json` and `METRICS.md` describe metric contracts and implementation status; `build.py` generates the consolidated dashboards; and `validate.py` checks the dashboard schema and can query a live Prometheus endpoint.

The dashboards must continue to distinguish inventory, control-plane acceptance, workload identity verification, authorization decisions, and actual traffic outcomes. Missing telemetry remains unavailable. A mock xDS resource or ACK is not evidence that a workload has a valid SVID, that an inbound connection authenticated, or that policy protected the traffic.

## Proposal captured

The submitted snippet proposes three counters:

| Proposed metric | Intended observation | Safe interpretation |
| --- | --- | --- |
| `cmtc_mock_engine_endpoints_injected_total` | Test fixture translated and submitted to an xDS test path | Test-only fixture activity. It cannot represent production workload discovery or protection. Count it only after a named, test-only boundary succeeds; distinguish validation, serialization, send, and ACK rather than calling all of them “injected.” |
| `cmtc_xds_cache_sync_errors_total` | xDS cache or stream synchronization failure | Add only after the real owner and failure boundary are identified. Conversion rejection, proxy NACK, send failure, timeout, and disconnected stream are distinct outcomes and should not be collapsed into one ambiguous counter. |
| `cmtc_workload_security_policy_violations_total` | An actual unauthenticated or unauthorized connection rejected by enforcement | Emit only from the real authorization or datapath rejection path. Rejecting an invalid mock before it reaches that path is fixture validation, not a policy denial. |

The pasted example also sketches a Hive provider, a controller loop that builds mock workload objects, and a Prometheus query check. Its central idea—use the existing dashboards and local Prometheus loop to catch regressions—is useful. The code is not ready to compile or deploy.

## Code review and required corrections

- The import paths in the pasted Go are placeholders (`"://github.com"`), and the proposed `pkg/ambient/mockbridge` location does not match the test-only ztunnel xDS probe scope described in issue #14. Resolve actual types and extension points against the pinned Cilium checkout before implementing anything.
- `prometheus.MustRegister` uses global registration and can panic on duplicate collectors. The controller's `Start` and `Stop` methods are not connected to Hive lifecycle merely by being declared. Use the Cilium package's existing metric and lifecycle wiring, with injected dependencies and bounded startup/shutdown behavior.
- The snippet increments “injected” before checking the SPIFFE ID, then calls a missing-ID fixture a cache-sync error and a policy violation. These counters would report the wrong events. Emit metrics only after the exact event represented by the metric has happened.
- A string such as `mockWl.ClusterName + ".mesh"` is supplied by the fixture. It is not a verified SPIFFE trust domain or cluster binding. An xDS serializer must validate the fixture against the test's explicit trust configuration; it must never create production trust from a mock field.
- The proposed `spiffe_id`, `remote_cluster`, namespace, and free-form error labels can create unbounded cardinality or expose workload identity. Prefer bounded outcome enums and fixed test scenarios. Keep workload-specific detail in structured logs or test artifacts, with credentials and private keys excluded.
- `[]interface{}` and a constructed `ambient.Workload` do not demonstrate that a real proxy accepted the resource. Tests must use the pinned protobuf/API and observe send, ACK/NACK, timeout, and reconnect behavior separately.
- The three proposed names are not present in the current `observability/metrics.json` contract. Do not add them to production dashboards or mark planned panels live until a real exporter and scrape establish their type, unit, labels, owner, reset semantics, and missing-data behavior.

## Implementation and validation gates

1. Keep the mock bridge test-only and explicitly disabled in normal agent operation. Prefer a test result artifact over a production Prometheus collector when a counter would only report fixture mechanics.
2. If a metric is needed, define the event boundary and bounded label set first. Count fixture validation, translation, stream delivery, and proxy ACK/NACK separately when those distinctions matter. Count policy denials only where real enforcement rejects traffic.
3. Extend the existing `metrics.json`, `METRICS.md`, `capabilities.json`, dashboard generator, and validator only when a metric is backed by a real collector. Preserve the two consolidated dashboards and all nine source dashboards. Do not create a parallel telemetry catalog.
4. Start with `python3 observability/build.py --check` and the existing static checks. For live validation, use `validate.py` with the actual local Prometheus URL and its required `--out` evidence path. Require non-zero values only for events deliberately exercised; an idle error or denial counter can correctly remain zero, and absent telemetry must remain unavailable.
5. Build the exact Cilium image with the documented Podman workflow and deploy it to the owned local kind fixture. Test valid and invalid xDS inputs, ACK/NACK and recovery paths, then verify allowed and rejected application traffic using independent proxy, identity, policy, packet, and Prometheus evidence. Do not use mock injection as a substitute for end-to-end mTLS.
6. Inspect the current scrape configuration before adding a ServiceMonitor. Add one only if the real collector endpoint is not already discovered and scraped; avoid duplicate scrape jobs and do not expose an endpoint solely to make a planned panel non-empty.
7. Capture dashboard screenshots after representative real load and retain the query evidence. CI remains deferred under the current local-first mandate.

## Related work

- [#13 — Native ClusterMesh workload discovery and federated mTLS](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13)
- [#14 — Test-only remote Workload xDS injection probe](https://github.com/ephico2real2/clustermesh-trust-controller/issues/14)
- [#15 — Qualify remote xDS telemetry against the observability contract](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15)
- [#16 — Map verified remote workloads into native ztunnel xDS resources](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16), documented in [REMOTE_WORKLOAD_XDS_MAPPING.md](REMOTE_WORKLOAD_XDS_MAPPING.md)
- [#17 — Qualify Cilium agent metrics scraping in the local lab](https://github.com/ephico2real2/clustermesh-trust-controller/issues/17), documented in [CILIUM_AGENT_METRICS_SCRAPING.md](CILIUM_AGENT_METRICS_SCRAPING.md)
- [#18 — Add fail-closed regression tests for remote Workload xDS mapping](https://github.com/ephico2real2/clustermesh-trust-controller/issues/18), documented in [REMOTE_WORKLOAD_XDS_TRANSFORMER_TESTS.md](REMOTE_WORKLOAD_XDS_TRANSFORMER_TESTS.md)
