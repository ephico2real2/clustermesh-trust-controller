# Prove mTLS for each request from ztunnel logs

This tutorial shows how to turn a traffic matrix into per-connection mTLS evidence.

A probe that returns HTTP 200 proves only that traffic got through. To show that the traffic used workload mTLS, you
join each probe to the ztunnel connection that carried it. For that connection you check four things:
- both ztunnels logged it: the client side (outbound) and the server side (inbound);
- it used the HBONE port, 15008;
- the peer identity is the client's expected SPIFFE ID;
- the destination identity is the server's expected SPIFFE ID.

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

## The tools

All three are in [`scripts/evidence/`](../../../scripts/evidence/). They use only the Python standard library and
`bash`.

| Tool | What it does |
| --- | --- |
| `extract_ztunnel_logs.sh` | Copies each node's ztunnel log for a time window into one file per node. Keeps only lines that match a filter. Writes a `# coverage` header. |
| `ztunnel_log_view.py` | Parses ztunnel logs. Shows an overview, the peer identities, the flows, a timeline of every connection, and grouped errors. |
| `join_probes_to_ztunnel.py` | Joins each probe to its connection, and gives each probe a verdict. |

`ztunnel_log_view.py` holds the parser. `join_probes_to_ztunnel.py` imports it, so both tools read a line the same
way.

## Prerequisites

- The kind contexts `kind-cmtc-a` and `kind-cmtc-b`, and `KUBECONFIG` set to the lab kubeconfig.
- The Docker context that runs the kind nodes. The default is `colima-cmtc-cilium`; set `DOCKER_CONTEXT` to change
  it.
- Python 3.11 or later.

## Step 1: run the probes

Run the fixture runner for each cluster and scope. Each run writes a JSON file of probe rows: `at`, `context`,
`client`, `url`, `expect` and `curlRC`.

```sh
python3 live_mtls_fixture_runner.py --cluster cmtc-a --out <run-dir> --scope all probe --execute
python3 live_mtls_fixture_runner.py --cluster cmtc-b --out <run-dir> --scope all probe --execute
```

Write down the start and end time of the run, in UTC.

## Step 2: capture the ztunnel logs

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

## Step 3: write the Pod map

The join must know each fixture Pod's IP, node and service account. Write one line per Pod:

```sh
for c in cmtc-a cmtc-b; do for ns in cmtc-live-mtls cmtc-live-mtls-unauth; do
  kubectl --context kind-$c get pods -n $ns --no-headers \
    -o custom-columns=NAME:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName,SA:.spec.serviceAccountName,UID:.metadata.uid \
    | sed "s/^/$c $ns /"
done; done > <run-dir>/fixture-pods.txt
```

Write the map while the probed Pods still run. A replaced Pod gets a new IP.

## Step 4: read the logs

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

## Step 5: join the probes

```sh
scripts/evidence/join_probes_to_ztunnel.py <run-dir>/probes \
  --pods <run-dir>/fixture-pods.txt \
  --trust-domain cmtc-a=cmtc-a.mesh.example --trust-domain cmtc-b=cmtc-b.mesh.example \
  --logs <run-dir>/ztunnel-access/*.log \
  --since 2026-10-25T23:00:00Z --out <run-dir>/join.json
```

You give the trust domains on the command line. The tool does not read them from the logs, so the check is not
circular. The expected identity is `spiffe://<trust domain>/ns/<namespace>/sa/<service account>`.

On this run:

```text
  CLUSTER  SCOPE         EXPECT  PROBES  RESULT
  cmtc-a   crosscluster  allow       12  mTLS proven
  cmtc-a   crossnode     allow        6  mTLS proven
  cmtc-a   global        allow        1  FAIL: curl exit 28, no connection to join
  cmtc-a   negative      deny         6  no response, no ztunnel line
  cmtc-a   same          allow        6  mTLS proven
  cmtc-b   crosscluster  allow       12  mTLS proven
  cmtc-b   crossnode     allow        6  mTLS proven
  cmtc-b   global        allow        1  FAIL: curl exit 28, no connection to join
  cmtc-b   negative      deny         6  no response, no ztunnel line
  cmtc-b   same          allow        6  mTLS proven

  48 proven over mTLS · 12 unanswered with no ztunnel line · 2 failed
```

The command exits 1 here, and that is correct. The two Global Service probes by name failed because DNS failed. Add
`--rows` to see one row per probe. `join.json` keeps every verdict with its two log lines.

What each verdict means:

| Verdict | Meaning |
| --- | --- |
| `mTLS proven` | Both lines of one connection exist, inside the probe's window (default 3 s before `at`). The outer port is 15008. The peer identity and the destination identity equal the expected SPIFFE IDs. |
| `no response, no ztunnel line` | A probe expected to be denied got no response, and no ztunnel logged its caller's IP. The logs cover the window on every node. |
| `FAIL: the logs of … do not cover this probe` | A log does not cover the probe's window. The probe is not judged. |
| `FAIL: …` (other) | The reason: a missing line, a wrong identity, a non-HBONE port, a failed curl, or a denied caller that ztunnel saw. |

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
  component dropped the packets. For that, record the Cilium drop event of the same flow
  (`cilium-dbg monitor --type drop`) during the probe.
- **The join matches by time.** It matches client IP and destination within the window, not by a request ID. A
  fixture that probes the same client, destination and port twice inside 3 s cannot be told apart.
- **The proof is per connection, not per packet.** Use a packet capture to show the bytes on the wire.
- **Workload mTLS is not transport encryption.** This evidence says nothing about WireGuard or IPsec.

## Tests

```sh
python3 -m unittest scripts/evidence/test_evidence_tools.py -v
```

The 22 tests use synthetic ztunnel lines. They cover:
- the parser, CRI-prefixed lines and the coverage header;
- connection pairing, path classification and error grouping;
- every join verdict: wrong identity, non-HBONE port, missing line, ClusterIP backend, failed curl, a denied caller
  that ztunnel saw, and logs that do not cover the probe.
