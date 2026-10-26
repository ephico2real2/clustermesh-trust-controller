# Prove mTLS for each request from ztunnel logs

This tutorial shows how to turn a traffic matrix into per-connection mTLS evidence.

A probe that returns HTTP 200 proves only that traffic got through. To show that the traffic used workload mTLS, you
join each probe to the ztunnel connection that carried it. For that connection you check four things:
- both ztunnels logged it: the client side (outbound) and the server side (inbound);
- it used the HBONE port, 15008;
- the peer identity is the client's expected SPIFFE ID;
- the destination identity is the server's expected SPIFFE ID.

A probe that is denied or fails gives no connection to join. For it, a capture of the Cilium drop events of the same
time can name the component that dropped the traffic.

The run in this folder is the worked example: 2026-10-25, Cilium agents at `6090aa6eff`. Its results are in the
[evidence record](README.md).

## Why the peer identity is proof

On the server side, ztunnel accepts the TLS connection and reads the client certificate. It writes the identity
from that certificate as `src.identity` on the inbound access line. Source: ztunnel fork `f221f29b59`,
`src/proxy/inbound.rs:131-135`:

```rust
let src_identity = {
    let x509_cert = tls::certificate_from_connection(ssl);
    tls::identity(&x509_cert)
};
```

So an inbound line that names `spiffe://cmtc-b.mesh.example/ns/cmtc-live-mtls/sa/mesh-client` means one thing: a
mutual TLS handshake completed, and the client presented a certificate with that SPIFFE ID. The outbound line alone
does not prove this. It records what the client side intended.

## Why the drop capture adds its own time

The Cilium agent reports drops with `cilium-dbg monitor --type drop`. This line was measured on cmtc-a-worker:

```text
xx drop (Policy denied) flow 0xe380ae81 to endpoint 0, ifindex 403, file bpf_lxc.c:1626, , identity 69042->66322: 10.10.1.205:46029 -> 10.10.0.193:53 udp
```

The line has no time, and no output form of the monitor has one. Source: Cilium fork at `6090aa6eff`, the deployed
agents:
- The text form (the default) prints the fields of the drop notification, which has no time field
  (`pkg/monitor/datapath_drop.go:66`, `DropNotify`; line 198, `DumpInfo`).
- The JSON form (`-j`) prints `DropNotifyVerbose` (line 252), also without a time. The agents have no `-o json`
  flag; `cilium-dbg monitor --help` lists `-j, --json`.
- The event that the agent sends to the monitor holds only `Data`, `CPU`, `Lost` and `Type`
  (`pkg/monitor/payload/monitor_payload.go:52`).
- Hubble puts a time on each event, but `cilium-dbg status` reports `Hubble: Disabled` on the lab agents.

The JSON form names the BPF source file only by a number. In a sample from cmtc-a-worker at 23:42Z, one drop is
`"Line":2373,"File":2` in JSON and `file bpf_lxc.c:2373` in the text form. So the capture keeps the text form.

In the agent container, the capture puts the container's clock time (UTC) in front of each line as the line arrives.
The monitor flushes its output after each event (`pkg/monitor/format/format.go:72`). In a 6 s read-only capture on
cmtc-a-worker at 23:51Z, the monitor's own log line carried `23:51:48.446515242Z` and arrived at
`23:51:48.446620Z`.

## The tools

All six are in [`scripts/evidence/`](../../../scripts/evidence/). They use only the Python standard library and
`bash`.

| Tool | What it does |
| --- | --- |
| `extract_ztunnel_logs.sh` | Copies each node's ztunnel log for a time window into one file per node. Keeps only lines that match a filter. Writes a `# coverage` header. |
| `ztunnel_log_view.py` | Parses ztunnel logs. Shows an overview, the peer identities, the flows, a timeline of every connection, and grouped errors. |
| `capture_cilium_drops.sh` | Captures each node's Cilium drop events for a fixed time into one file per node. Puts the arrival time in front of each line. Writes a `# coverage` header. |
| `cilium_drop_view.py` | Parses drop captures. Shows the time each capture covers, lost events, and the drops grouped by flow, reason and BPF source location. |
| `join_probes_to_ztunnel.py` | Joins each probe to its connection, and gives each probe a verdict. With `--drops`, it also joins each denied or failed probe to the drops of its flow. |
| `dns_check.sh` | Resolves one name with `nslookup` from named Pods, and records the answer or the error. |

There is one parser for each format. `ztunnel_log_view.py` parses ztunnel logs and `cilium_drop_view.py` parses drop
captures. `join_probes_to_ztunnel.py` imports both, so every tool reads a line the same way.

## Prerequisites

- The kind contexts `kind-cmtc-a` and `kind-cmtc-b`, and `KUBECONFIG` set to the lab kubeconfig.
- The Docker context that runs the kind nodes. The default is `colima-cmtc-cilium`; set `DOCKER_CONTEXT` to change
  it.
- Python 3.11 or later.
- For the drop capture: `bash` 5 and GNU `timeout` in the Cilium agent container. The agent image
  `localhost/cilium:dev-overlay-6090aa6eff` has bash 5.3.9 and `/usr/bin/timeout`.

## Step 1: start the drop capture

Start the capture before the probes. Give it an output folder, a duration in seconds that covers the whole probe run,
and every node as `CONTEXT/NODE`:

```sh
scripts/evidence/capture_cilium_drops.sh <run-dir>/cilium-drops 300 \
  kind-cmtc-a/cmtc-a-control-plane kind-cmtc-a/cmtc-a-worker \
  kind-cmtc-b/cmtc-b-control-plane kind-cmtc-b/cmtc-b-worker &
```

Start the probes after it prints `capturing drops on 4 node(s) for 300s`. The capture is read-only. `timeout` in the
agent container stops each monitor after the duration, also when you interrupt the script.

Each output file starts like this (the 6 s capture on cmtc-a-worker):

```text
# cilium drop capture: node cmtc-a-worker, agent Pod kube-system/cilium-b98gm in kind-cmtc-a, cilium-dbg monitor -n -t drop for 6s
# each line: the agent container clock (UTC) when the line arrived, then the line of the monitor
# coverage 2026-10-25T23:51:43.884441Z 2026-10-25T23:51:48.869529Z
2026-10-25T23:51:42.884441Z Press Ctrl-C to quit
```

The coverage starts 1 s after the monitor printed `Press Ctrl-C to quit`. The monitor prints that line just before it
connects to the agent (`cilium-dbg/cmd/monitor.go:248`). The coverage ends when `timeout` stopped the monitor. If the
monitor stops early, or reports `connection closed`, the coverage ends there and the script exits 1.

## Step 2: run the probes

Run the fixture runner for each cluster and scope. Each run writes a JSON file of probe rows: `at`, `context`,
`client`, `url`, `expect` and `curlRC`.

```sh
python3 live_mtls_fixture_runner.py --cluster cmtc-a --out <run-dir> --scope all probe --execute
python3 live_mtls_fixture_runner.py --cluster cmtc-b --out <run-dir> --scope all probe --execute
```

Write down the start and end time of the run, in UTC. Then wait for the drop capture to end (`wait`).

To record what each Pod's resolver does, run `dns_check.sh` while the drop capture runs. It sends DNS queries from the
Pods, so run it only when you hold the lab:

```sh
scripts/evidence/dns_check.sh <run-dir>/dns-check.txt kubernetes.default.svc.cluster.local \
  kind-cmtc-a/cmtc-live-mtls/client-worker kind-cmtc-a/cmtc-live-mtls-unauth/unregistered-control-plane
```

Each line records the Pod's nameserver, the `nslookup` exit status and its output. A drop from the Pod to that
nameserver on port 53, in the drop capture of the same time, names the component that dropped the query.

## Step 3: capture the ztunnel logs

Run the extractor soon after the probes. Give it the window, a filter, and every node:

```sh
scripts/evidence/extract_ztunnel_logs.sh <run-dir>/ztunnel-access \
  2026-10-25T23:00:00Z 2026-10-25T23:13:00Z \
  'cmtc-live-mtls|src\.addr=10\.(10|20)\.[01]\.' \
  cmtc-a-control-plane cmtc-a-worker cmtc-b-control-plane cmtc-b-worker
```

Use the extractor, not `kubectl logs`. In this run kubelet rotated the control-plane ztunnel logs at 23:02:30Z and
23:02:51Z. After that, `kubectl logs` returned nothing from before the rotation, so the 23:00Z matrix was missing.
The extractor reads every log file under `/var/log/pods` on the node, oldest first.

The extractor stops with an error if a node's log does not reach back to the window start and forward to its end.
Each output file starts like this:

```text
# ztunnel log extract: node cmtc-a-worker, source /var/log/pods/kube-system_ztunnel-cilium-z9bdj_…/istio-proxy (0.log.20261025-225836 0.log )
# filter: lines between 2026-10-25T23:00:00Z and 2026-10-25T23:13:00Z matching /cmtc-live-mtls|src\.addr=10\.(10|20)\.[01]\./
# source spans 2026-10-25T21:46:57.783136Z .. 2026-10-25T23:30:12.181324Z
# coverage 2026-10-25T23:00:00Z 2026-10-25T23:13:00Z
```

The `# coverage` line matters. The filter drops lines, so the first and last kept lines do not show which times the
file covers. The join uses this line before it counts a missing line as evidence.

## Step 4: write the Pod map

The join must know each fixture Pod's IP, node and service account. Write one line per Pod:

```sh
for c in cmtc-a cmtc-b; do for ns in cmtc-live-mtls cmtc-live-mtls-unauth; do
  kubectl --context kind-$c get pods -n $ns --no-headers \
    -o custom-columns=NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,SA:.spec.serviceAccountName,UID:.metadata.uid \
    | sed "s/^/$c $ns /"
done; done > <run-dir>/fixture-pods.txt
```

Write the map while the probed Pods still run. A replaced Pod gets a new IP.

## Step 5: read the logs

```sh
scripts/evidence/ztunnel_log_view.py <run-dir>/ztunnel-access/*.log --brief
```

On this run, the overview says:

```text
▌ Overview  what these logs contain

  inputs      4 file(s), nodes: cmtc-a-control-plane, cmtc-a-worker, cmtc-b-control-plane, cmtc-b-worker
  window      2026-10-25 23:00:41.812Z → 23:12:22.000Z  (11m40s)
  lines       240 parsed: 216 info, 24 error
  connections 72 · 72 over HBONE :15008 · 72 seen by both ztunnels · 72 with the peer identity read from its certificate
  problems    24 lines in 1 group(s)
```

How to read each section:

| Section | What it tells you |
| --- | --- |
| Overview | How many connections used HBONE, how many both ztunnels saw, and the time each node's log covers. A connection that did not use HBONE is listed in red. |
| Peer identities | Each client identity a server-side ztunnel read from a certificate, and which servers accepted it. |
| Flows | Connections grouped by caller, destination and path (same node, cross node, cross cluster), with the ports used. `BOTH SIDES` and `POLICY` count connections with an inbound line and an `allow policy match` line. |
| Timeline | One row per connection. `SEEN BY` shows which lines exist. `BYTES` shows request bytes (↑) and response bytes (↓), as the server counted them. |
| Problems | Errors and warnings, grouped by message with the per-connection IDs removed, with counts per minute and per workload. |

A timeline row (`--only timeline --limit 3`):

```text
  TIME          FROM                     TO                           PORT    PATH           SEEN BY                     PEER IDENTITY                    BYTES     TOOK
  23:10:33.881  cmtc-b/client-worker  →  cmtc-a/server-control-plane  :80     cross cluster  ✓ client ✓ server ✓ policy  mesh-client@cmtc-b.mesh.example  75↑ 362↓   0ms
```

Useful options:
- `--since 23:00 --until 23:02`: limit the time window. Times are UTC.
- `--workload client-worker`: show only that workload.
- `--json`: print connections and problems as JSON.
- `--fail-on-problems`: exit 1 if there is any error or warning.
- `kubectl logs … | scripts/evidence/ztunnel_log_view.py --node <node> -`: read a live log from stdin.

Color is on when the output is a terminal. Use `--color never` or set `NO_COLOR` to turn it off.

Read the drop captures the same way:

```sh
scripts/evidence/cilium_drop_view.py <run-dir>/cilium-drops/*.log
```

It shows the time each capture covers, the lost events, and the drops grouped by node, flow, reason and BPF source
location. Add `--json` for one object per drop.

## Step 6: join the probes

```sh
scripts/evidence/join_probes_to_ztunnel.py <run-dir>/probes \
  --pods <run-dir>/fixture-pods.txt \
  --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \
  --logs <run-dir>/ztunnel-access/*.log \
  --drops <run-dir>/cilium-drops/*.log \
  --since 2026-10-25T23:00:00Z --out <run-dir>/join.json
```

`--drops` is optional. Without it, no verdict uses drops.

You give the trust domains on the command line. The tool does not read them from the logs, so the check is not
circular. The expected identity is `spiffe://<trust domain>/ns/<namespace>/sa/<service account>`.

On this run, which has no drop capture:

```text
  CLUSTER  SCOPE         EXPECT  PROBES  RESULT
  cmtc-a   crosscluster  allow       12  mTLS proven
  cmtc-a   crossnode     allow        6  mTLS proven
  cmtc-a   global        allow        1  FAIL: curl exit 28 ("Resolving timed out"); the target is a DNS name; no ztunnel connection from the client to a backend on port 80 in the window
  cmtc-a   negative      deny         6  no response, no ztunnel line
  cmtc-a   same          allow        6  mTLS proven
  cmtc-b   crosscluster  allow       12  mTLS proven
  cmtc-b   crossnode     allow        6  mTLS proven
  cmtc-b   global        allow        1  FAIL: curl exit 28 ("Resolving timed out"); the target is a DNS name; no ztunnel connection from the client to a backend on port 80 in the window
  cmtc-b   negative      deny         6  no response, no ztunnel line
  cmtc-b   same          allow        6  mTLS proven

  48 proven over mTLS · 12 unanswered with no ztunnel line · 2 failed
```

The command exits 1 here, and that is correct: the two Global Service probes by name failed. For both, curl reported
`Resolving timed out after 3001 milliseconds`. curl writes this only when its timeout expires while it is still
resolving the name (curl 8.14.1, `lib/multi.c:1642`). No ztunnel connection from the client to a backend on port 80
is in the window. Add `--rows` to see one row per probe. `join.json` keeps every verdict with its log lines.

What each verdict means:

| Verdict | Meaning |
| --- | --- |
| `mTLS proven` | Both lines of one connection exist, inside the probe's window. The outer port is 15008. The peer identity and the destination identity equal the expected SPIFFE IDs. |
| `dropped by Cilium: <reason> at <file:line>` | A probe expected to be denied got no response, no ztunnel logged its caller's IP, and a drop capture has a drop of the same flow. The drop is from the caller's IP to the probed IP and port over TCP (for a Service address, to it or to a fixture backend). It is inside the probe's window and inside its capture's coverage. Needs `--drops`. |
| `no response, no ztunnel line` | A probe expected to be denied got no response, and no ztunnel logged its caller's IP. The logs cover the window on every node. With `--drops`, `dropSearch` in `join.json` says why no drop matched: no drop in captures that cover the window, captures that do not cover it, or lost events. |
| `FAIL: the logs of … do not cover this probe` | A log does not cover the probe's window. The probe is not judged. |
| `FAIL: curl exit N ("…"); the target is a DNS name; …` | The probe's URL names a host, not an IP address, and curl failed. The verdict quotes curl's error without its variable tail. It says whether a ztunnel connection from the client to a backend on the port is in the window. With `--drops`, it adds any Cilium drop of DNS traffic (port 53) from the client. |
| `FAIL: …` (other) | The reason: a missing line, a wrong identity, a non-HBONE port, a failed curl, or a denied caller that ztunnel saw. With `--drops`, a failed curl adds any drop of its flow. |

A probe's window ends at its `at`, which the runner writes after curl returns. The window starts at the row's
`startedAt` when it has one, else 3 s (`--window`) before `at`. The rows in this folder have no `startedAt`.

A Service address (ClusterIP) is translated to a backend Pod before ztunnel sees the traffic. The join then matches
the port, and the backend that served it.

## Try it on this folder

```sh
E=docs/evidence/g1-destination-sources
scripts/evidence/ztunnel_log_view.py $E/ztunnel-access/*.log
scripts/evidence/join_probes_to_ztunnel.py $E/probes --pods $E/fixture-pods.txt \
  --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \
  --logs $E/ztunnel-access/*.log --since 2026-10-25T23:00:00Z --rows
```

Without `--since`, the 22:57Z baseline probes are refused: the logs in this folder start at 23:00Z.

## Limits

- **"No ztunnel line" is not proof of a drop.** It shows that no ztunnel accepted the caller. It does not show which
  component dropped the packets. For that, capture the drops during the probes
  ([Step 1](#step-1-start-the-drop-capture)) and join with `--drops`. The run in this folder has no drop capture.
- **A missing drop is not a verdict.** The monitor can lose events (`CPU NN: Lost N events`). The join reports lost
  events and coverage gaps in `dropSearch`, and never changes a verdict because a drop is missing.
- **Drop times are arrival times on the node's clock.** Probe times are on the clock of the host that ran the runner.
  The join compares them directly, as it does with ztunnel times.
- **The join matches by time.** It matches client IP and destination within the window, not by a request ID. A
  fixture that probes the same client, destination and port twice inside 3 s cannot be told apart.
- **The proof is per connection, not per packet.** Use a packet capture to show the bytes on the wire.
- **Workload mTLS is not transport encryption.** This evidence says nothing about WireGuard or IPsec.

## Tests

```sh
python3 -m unittest scripts/evidence/test_evidence_tools.py -v
```

The 46 tests use synthetic ztunnel lines, synthetic Cilium drop lines and a stubbed `kubectl`. They cover:
- the ztunnel parser, CRI-prefixed lines and the coverage header;
- connection pairing, path classification and error grouping;
- the drop parser: the measured drop line, reasons with parentheses, IPv6 and ICMP summaries, lost events, and a
  capture without a coverage header;
- every join verdict: wrong identity, non-HBONE port, missing line, ClusterIP backend, failed curl, a denied caller
  that ztunnel saw, and logs that do not cover the probe;
- the drop join: a matching drop, other ports, protocols, callers, destinations and times, a drop outside its
  capture's coverage, lost events, `startedAt`, a Service address, and a failed curl with a drop;
- the DNS name verdicts: curl's error, a backend connection in the window, and a DNS drop from the client;
- `capture_cilium_drops.sh` (a clean capture, a monitor that stops early) and `dns_check.sh` (an answer, a failed
  exec). These tests need `bash` 5 and GNU `timeout` on `PATH`; without them they are skipped.

These are unit tests. The capture ran once on the lab, for 6 s on two cmtc-a agents, read-only. It has not yet been
used in a probe run.
