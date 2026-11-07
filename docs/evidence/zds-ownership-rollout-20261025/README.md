# ZDS ownership fixes: live rollout, 2026-10-25

Deployed to `kind-cmtc-a` and `kind-cmtc-b` between 20:50 and 21:01 UTC by the
single live writer (Claude Code session b744973a). The adversarial review of
the two ZDS fixes was still running; the operator asked for the rollout.

## What was deployed

| Component | Image | Identity check |
| --- | --- | --- |
| Cilium agent | `localhost/cilium:dev-overlay-bc2c9639c5` | Pod `imageID` = Podman ID `249ff5db9f20…` on all four nodes |
| ztunnel | `localhost/cmtc-ztunnel@sha256:b27235a4b7ec…` (tag `native-a3afcb7001`) | Config `sha256:83bca098a88c…` on all four nodes; manifest hashed and pinned by [`pin_digest.py`](pin_digest.py) |

Source: Cilium `bc2c9639c5` (a refused bound ADD is not uncertainty) on top of
`0ed63bf906` (UID-only ZDS peer check); ztunnel `a3afcb7` (a snapshot omission
completes the bound owner it drains).

Both agent templates were changed with test-guarded JSON patches
([cmtc-a](cmtc-a-cilium-template-patch.json), [cmtc-b](cmtc-b-cilium-template-patch.json)).
cmtc-b's patch also removed the interim agent `hostPID`; cmtc-a's had been
removed with `0ed63bf906`. Agents were replaced one node at a time with
[`roll_agent_node.sh`](roll_agent_node.sh), then proxies with the
`rollout_ztunnel.py` tool ([ledger](ztunnel-rollout.jsonl)). Order per cluster:
worker agent, control-plane agent, then both proxies, worker first.

## J2 stranding: cleared on the live cluster

Before the rollout, `client-worker` and `server-worker` on `cmtc-a-worker` had
been quarantined since an agent restart at 20:18Z.

- **Agent half** ([j2-agent-half.txt](j2-agent-half.txt)). The fixed agent
  against the old proxy (`a75d885`) was refused 264 times ("old workload must
  complete its exact drain before replacement") with 0 uncertainty-history
  exhaustions. Admission kept retrying; the workloads stayed quarantined
  (fail closed).
- **Proxy half** ([j2-proxy-half.txt](j2-proxy-half.txt)). The worker proxy was
  replaced at 20:56:17.24Z. `client-worker` was released at 20:56:18.39Z;
  `server-worker` was re-admitted (attempt 7, 4 m 12 s after the restart) and
  released at 20:56:18.92Z. After every later proxy replacement, both workloads
  on that node were quarantined and released within about 1 s, with 0 refusals
  and 0 failed admissions.

## Source membership lock is freed by lease expiry, not released

[source-lock-handover.txt](source-lock-handover.txt). Every outgoing agent's
last logged line is "Stopping reconciler", about 10 ms after SIGTERM; none logs
a release. All four agent Pods run with `terminationGracePeriodSeconds: 1`. The
successor acquired the lock 20.8 to 27.3 s after the predecessor's SIGTERM,
which matches the 25 s etcd lease TTL. Workload admission does not wait on it,
but source-membership publication on that node pauses for that window. Open.

## Traffic matrix after the rollout

[matrix-20261025T2101Z.tsv](matrix-20261025T2101Z.tsv). The column
`matchedProbeExpectation` says only whether the result matched what the probe
was told to expect.

| Scope (each cluster) | Probes | Result | Mission status |
| --- | --- | --- | --- |
| Same node, Pod IP, ports 80/8080/31337 (×3) | 18 | All HTTP 200 with the expected serving cluster | Works |
| Unregistered client (negative) | 6 | All refused | Works |
| Cross node, Pod IP | 6 | All refused | **Fails** |
| Cross cluster, Pod IP | 12 | All refused | **Fails** |
| Global Service | not run | the first cross-node probe of `--scope all` stopped the run | **Fails** (same cause) |

The handshake succeeds across nodes; authorization denies it
([cross-node-deny.txt](cross-node-deny.txt)). The destination ztunnel logs
`no allow policies matched` for a peer whose SPIFFE identity it verified. The
compiled effective policy for `server-control-plane` allows `mesh-client` only
from `10.10.0.2/32`, the same-node client. `reconcile()` in
`pkg/ztunnel/xds/effective_policy.go` builds each plan's sources from the
local agent's registry and endpoint manager only, so no remote source ever
enters a plan. No network policy selects `cmtc-live-mtls`; native Cilium
allows this traffic. Introduced with `ada009a5f0` (compiled effective policy
publication); the design note on `ZtunnelL4Plan` in `pkg/policy/ztunnel_l4.go`
marks remote source-egress delivery as unimplemented. The last full matrix
that passed (36/36 per cluster) ran at 16:36Z; which agent build it ran
against is not recorded here, and every later probe in that ledger (17:30Z,
17:43Z) failed while workloads were quarantined.

`securityReasonVerified` is false for every probe: these rows are traffic
verdicts, not proof of the reason (see the security matrix).
