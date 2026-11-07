# SPIRE server outage from a zombie leak, 2026-10-28

Result: on kind-cmtc-a and kind-cmtc-b, the SPIRE server Pod became not Ready at 06:37:01Z (cmtc-a) and 06:37:02Z
(cmtc-b). The `spire-server` Service then had no ready endpoint, every SPIRE agent lost the server, and workload mTLS
failed closed. Operator decision (06:55Z): accept the outage until the fix is built; no container restart.

State: **fixed, deployed, traffic-qualified and committed** (#41). The fix, its tests and this record are in one
commit on `feat/end-to-end-enforcement`. At 07:31-07:35Z all 96 allowed probes went over mTLS on certificates from
the SPIRE CAs that activated during the outage, and again at 13:48-13:52Z. The sidecar showed no zombie for 7.3 hours
on both clusters ([#41 acceptance](#41-acceptance)); #41 is closed.

## What happens

1. The `register-agent-node` sidecar of StatefulSet `cilium-spire/spire-server` runs
   `/opt/cmtc/register-agent-node.sh` (ConfigMap `spire-helpers`, rendered by `scripts/lab/spire/render_spire.py`).
   After it confirms the node alias, the script runs `exec tail -f /dev/null`, so `tail` becomes the container's PID 1.
2. The readiness probe runs the same script every 5 s with `SPIRE_CHECK_ONLY=1`. The script calls the SPIRE CLI through
   busybox `timeout -s KILL`. Each probe leaves one `timeout` process that `tail` never reaps (a zombie).
3. After about 26.5 hours (19,096 zombies at one per 5 s), the container reaches its process limit. The probe cannot
   start (`runc init: unable to spawn stage-2: Resource temporarily unavailable`), the Pod becomes not Ready, and its
   endpoint is removed from the Service.

## Measurements

| Item | cmtc-b | cmtc-a |
|---|---|---|
| Processes on the server's node | 19,204 (cmtc-b-worker; cmtc-b-control-plane: 83) | 19,210 (cmtc-a-worker; cmtc-a-control-plane: 77) |
| Zombie `timeout` processes, parent `tail -f /dev/null` | 19,091 (06:50Z) | not counted; same node total |
| Sidecar container `pids.current` / `pids.max` / `pids.events max` | 19,094 / 19,096 / 1,688 | |
| SPIRE server container `pids.current` | 14 (no refusals) | |
| Pod `Ready=False` since | 06:37:02Z | 06:37:01Z |
| Endpoint of Service `spire-server` | `ready: false` | `ready: false` |
| SPIRE agents | `dial tcp 10.21.78.61:8081: connect: no route to host`, `Could not reattest agent` | `dial tcp 10.11.161.194:8081: ...`, `Could not reattest agent` |

Every SPIRE CLI operation that execs into the sidecar is blocked as well: `scripts/lab/spire/local_authority.py` and
the hand registration of ztunnel delegate entries.

## The SPIRE CA activation during the outage

The server activated its prepared X.509 CA on schedule; the agents could not receive it.

| Cluster | Activated | Local authority | Upstream authority (renewed SPIRE intermediate) |
|---|---|---|---|
| cmtc-b | 06:52:42Z | `93fead964e77…` | `52d271bde9a9…` |
| cmtc-a | 06:54:12Z | `b393af1b609c…` | `78dee534936d…` |

## Traffic

[matrix-0656](matrix-0656/join.txt), 06:55:44-06:59:49Z: 0 proven over mTLS, 36 dropped by Cilium (the expected
denials), 10 failed. Every allowed scope on both clusters failed at its first probe with curl exit 56 (connection reset)
or 52 (empty reply). No probe got a plaintext answer. The ztunnel logs in the window hold no error line.

The previous matrix, [cilium-ingress-20261028](../cilium-ingress-20261028/README.md) at 04:21-04:25Z, was 96 proven,
36 dropped, 0 failed.

## The fix

`scripts/lab/spire/render_spire.py` (REGISTER_SCRIPT, `finish`): the script no longer runs `exec tail -f /dev/null`.
The shell stays PID 1 and waits in a loop (`hold`). In busybox ash, `wait` blocks in `waitpid(-1)`
(`shell/ash.c:4345`), which also reaps the orphaned `timeout` processes. `scripts/lab/spire/test_render_spire.py`
adds `ReapingTests` (3 tests, one runs the pinned busybox image with a control): 21 of 21 tests pass, and the 3 new
tests fail on HEAD `e566bef`. Re-run before the commit (14:33Z, `venv/bin/python scripts/lab/spire/test_render_spire.py`):
`OK`, 21 tests; with the renderer of `e566bef` in a copy, 18 pass and the 3 `ReapingTests` fail.

## Deploy

1. The `cilium-spire/spire-helpers` ConfigMap was replaced with the new render, then
   `kubectl rollout restart statefulset/spire-server`.
2. The rollout did not replace the Pod. The StatefulSet uses the `OrderedReady` Pod management policy, so it waits for
   every Pod to be Ready before it updates one, and the not Ready Pod was the one to replace (the deadlock that the
   Kubernetes StatefulSet documentation describes under "Forced rollback"). On cmtc-a the restart timed out.
3. `kubectl delete pod spire-server-0` on each cluster. The new Pods were Ready at 07:20:45Z (cmtc-a) and 07:21:50Z
   (cmtc-b). PID 1 of the sidecar is `sh`; the node alias check passed.

## Recovery

| Time (UTC) | Event |
|---|---|
| 07:19:34Z / 07:20:21Z | Last `Could not reattest agent` on the worker SPIRE agents (cmtc-a / cmtc-b) |
| 07:20:00Z / 07:20:34Z | Last `Synchronize failed` on the same agents |
| 07:22:41-07:26:45Z | [matrix-after-fix](matrix-after-fix/join.txt): 0 proven, 36 dropped, 10 failed |
| 07:30:49Z | One probe, cmtc-a `client-worker` to `10.10.1.37:80`: HTTP 200, ztunnel access line without an error |
| 07:31:04-07:35:09Z | [matrix-0731](matrix-0731/join.txt): 95 proven, 36 dropped, 1 failed (see below): 96 of 96 allowed probes over mTLS |

In matrix-after-fix, every failure is on an outbound connection from a worker node, with
`no approved direct issuer for domain cmtc-a.mesh.example` (07:22:45-07:22:47Z) or `... cmtc-b.mesh.example`
(to 07:23:44Z). The ztunnel verifier returns this error when no approved issuer accepts the peer's chain, and also
when the leaf has expired. The time between the agents' recovery and usable workload certificates in ztunnel is not
measured: ztunnel logs no certificate fetch at info level, the hub has no ztunnel certificate metric, and the ztunnel
logs of 07:22-07:30Z were rotated out by 07:37Z (the `Fetching PID` lines fill the log in about 10 minutes). The
measured bound is: failing at 07:26:45Z, working at 07:30:49Z.

The failed row of matrix-0731 is a join miss, not a failure of mTLS. The probe (cmtc-b `name`, `client-worker` to
`server-worker.cmtc-live-mtls.svc.cluster.local:31337`, 07:32:11.837-.903Z) returned HTTP 200 from
`X-CMTC-Pod: server-worker` (`curlRC` 0). curl reported its socket as `10.20.1.242:41520`, the port that a
crossnode probe used at 07:32:09Z. ztunnel logged the connection from `10.20.1.242:7472`, below the ephemeral range
(32768-60999): the source port was rewritten. That line (07:32:11.906Z) is the only outbound line from
`client-worker` to `10.20.1.116:31337` in the window, it is mTLS to
`spiffe://cmtc-b.mesh.example/ns/cmtc-live-mtls/sa/rebel-base`, and no probe claims port 7472. Step 6 of
[approval-arbiter-20261027](../approval-arbiter-20261027/README.md) recorded the same case. In the access logs
saved under `docs/evidence`, 8 of 4,724 `connection complete` lines have a source port below 32768.

## Certificates after the recovery

ztunnel config dumps, 07:36Z, all four nodes (public certificates only; no private key block). Every workload leaf
(`mesh-client` and `rebel-base` on each node, lifetime 130 s, state `Available`) is signed by the CA that activated
during the outage:

| Cluster | Leaf issuer (SPIRE CA SKI) | SPIRE CA issuer (intermediate SKI) |
|---|---|---|
| cmtc-a | `b393af1b…` | `78dee534…` (`cmtc-a-spire-intermediate`, revision 1) |
| cmtc-b | `93fead96…` | `52d271bd…` (`cmtc-b-spire-intermediate`, revision 2, renewed) |

## Zombies after the fix

07:32Z, 12 minutes (about 140 readiness probes) after the new Pods: 0 zombie `timeout` processes on the four nodes.
The remaining zombies are `bash` children of `cilium-agent`: cmtc-a-worker 3, cmtc-a-control-plane 2, cmtc-b-worker
12, cmtc-b-control-plane 11, about one per hour. That is a separate leak and is not part of #41.

## #41 acceptance

Measured at 13:48Z, 6.5 hours after the new Pods, and again at 14:36-14:39Z, 7.3 hours after them. At one zombie per
5 s, the old script would have left about 4,700 and 5,300 by these times. The acceptance criterion of #41 (no zombie
for 60 minutes on both labs) is met.

| Check | 13:48Z | 14:36-14:39Z |
|---|---|---|
| Zombie `timeout` processes on the four kind nodes (`docker --context colima-cmtc-cilium exec <node> ps -eo stat=,comm=,ppid=`) | 0, 0, 0, 0 | 0, 0, 0, 0 |
| Sidecar `register-agent-node`: PID 1 and its child, both clusters | `sh`, `sleep` | `sh`, `sleep` |
| Sidecar cgroup `pids.current` / `pids.max`, both clusters | 3 / 19096 | 4 / 19096 (the fourth is the shell of the measurement) |
| `spire-server-0` container restarts, cmtc-a / cmtc-b | 0 / 0 | 0 / 0 |
| Other zombies: `bash`, parent `cilium-agent` (a-cp, a-w, b-cp, b-w) | 4, 5, 1, 1 | 5, 6, 2, 2 |

[matrix-1349](matrix-1349/join.txt), 13:48:26-13:52:30Z, the second full matrix on the fixed sidecar: 132 probes
joined to 96 ztunnel connections; 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed. The
certificate renewals in that window are recorded in [cert-renewal-20261028](../cert-renewal-20261028/README.md).

The SPIRE node agent on cmtc-a-control-plane (`spire-agent-xfl5s`) restarted once: its container exited with code 1
at 07:20:17Z, during the recovery, and has 0 restarts since. The other three agents have 0 restarts. In the last
hour before 14:38Z no agent logged `Could not reattest`.

The deployed helpers equal the committed source. At 14:35Z the render of the committed `render_spire.py`
(`<cluster> --format yaml`) was applied as a server-side dry run on both clusters (`kubectl apply --server-side
--dry-run=server`, no `--force-conflicts`): ConfigMap `cilium-spire/spire-helpers` and the 15 other non-workload
objects show 0 differences in set fields and no conflict; the live `register-agent-node.sh` is the rendered one, byte
for byte (7,105 bytes, `hold()` present). The StatefulSet and the DaemonSet differ from the renderer's defaults in
fields that earlier rollouts set by hand (the SPIRE fork images and the delegated agent template; `server.conf` is
equal); those differences predate #41 and are recorded in the
[rollout runbook](../../../LOCAL_ISSUER_PROFILE.md#rolling-out-a-change-to-the-spire-server-or-its-helpers). Nothing
was applied or restarted for this acceptance.

## Findings that remain

- A SPIRE outage breaks workload mTLS within minutes: the leaves live 130 s (`X509SvidTtl` 120 s).
- The `OrderedReady` StatefulSet blocks the rollout of a fix to its own not Ready Pod.
- The `Fetching PID` log lines of ztunnel (about 319,000 in 10 minutes) leave about 10 minutes of ztunnel logs.
- The `bash` zombies under `cilium-agent`.
