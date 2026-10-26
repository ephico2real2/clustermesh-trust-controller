#!/usr/bin/env python3
"""Tests for the evidence tools, on synthetic ztunnel lines, Cilium drop lines and stubbed kubectl."""
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cilium_drop_view as drops  # noqa: E402
import join_probes_to_ztunnel as join  # noqa: E402
import ztunnel_log_view as view  # noqa: E402

A, B = "cmtc-a.mesh.example", "cmtc-b.mesh.example"
CLIENT = f"spiffe://{A}/ns/fx/sa/client"
SERVER_B = f"spiffe://{B}/ns/fx/sa/server"
PODS = """# CLUSTER NAMESPACE NAME POD_IP NODE SERVICE_ACCOUNT UID
cmtc-a fx client 10.10.1.5 a-worker client u1
cmtc-a fx-unauth stranger 10.10.1.9 a-worker stranger u2
cmtc-b fx server 10.20.0.7 b-cp server u3
"""


def access(at, direction, src_port, hbone="10.20.0.7:8080", outer="15008", src_id=CLIENT, dst_id=SERVER_B,
           src_ip="10.10.1.5"):
    return (f"2026-10-25T{at}Z\tinfo\taccess\tconnection complete\tsrc.addr={src_ip}:{src_port} "
            f'src.workload="client" src.namespace="fx" src.identity="{src_id}" src.cluster="cmtc-a" '
            f"dst.addr={hbone.rsplit(':', 1)[0]}:{outer} dst.hbone_addr={hbone} "
            f'dst.workload="server" dst.namespace="fx" dst.identity="{dst_id}" dst.cluster="cmtc-b" '
            f'direction="{direction}" bytes_sent=80 bytes_recv=360 duration="2ms"')


def policy(at, peer):
    return (f"2026-10-25T{at}Z\tinfo\tstate:proxy{{wl=fx/server}}:inbound{{id=abc peer={peer}}}\t"
            'allow policy match\tpolicy="fx/cilium_l4_effective_0123"')


HANDSHAKE = ("2026-10-25T{at}Z\terror\tproxy::h2::client:proxy{{wl=fx/client}}:outbound{{id={id}}}\t"
             'Error in HBONE connection handshake: Error {{ kind: Io(Custom {{ kind: PermissionDenied, error: '
             '"authenticated issuer profile/session expired or changed" }}) }}\t')
COVER = "# coverage 2026-10-25T23:00:00Z 2026-10-25T23:10:00Z"
# The line measured with `cilium-dbg monitor` on cmtc-a-worker (agents 6090aa6eff), with the capture's time in front.
MEASURED_DROP = ("2026-10-25T23:00:49.123456Z xx drop (Policy denied) flow 0xe380ae81 to endpoint 0, ifindex 403, "
                 "file bpf_lxc.c:1626, , identity 69042->66322: 10.10.1.205:46029 -> 10.10.0.193:53 udp")


def drop(at, src="10.10.1.9:41000", dst="10.20.0.7:8080", proto="tcp SYN", reason="Policy denied",
         where="bpf_lxc.c:2373"):
    return (f"2026-10-25T{at}Z xx drop ({reason}) flow 0x1 to endpoint 7, ifindex 9, file {where}, , "
            f"identity 100->200: {src} -> {dst} {proto}")


class Logs:
    """Writes per-node log files into a temporary directory."""

    def __init__(self, nodes):
        self.dir = tempfile.TemporaryDirectory()
        self.paths = []
        for node, lines in nodes.items():
            path = Path(self.dir.name, f"{node}.log")
            path.write_text("\n".join(lines) + "\n")
            self.paths.append(str(path))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.dir.cleanup()


class ParseTests(unittest.TestCase):
    def test_access_line_fields_and_quoted_values(self):
        r = view.parse_line(access("23:01:00.000100", "inbound", 4444), "b-cp")
        self.assertEqual((r.level, r.module, r.message), ("info", "access", "connection complete"))
        self.assertEqual(r.fields["src.identity"], CLIENT)
        self.assertEqual(r.fields["dst.hbone_addr"], "10.20.0.7:8080")
        self.assertEqual(r.fields["duration"], "2ms")

    def test_cri_prefix_is_removed(self):
        line = "2026-10-25T23:01:00.1Z stdout F " + access("23:01:00.000100", "inbound", 4444)
        self.assertEqual(view.parse_line(line, "n").fields["direction"], "inbound")

    def test_spans_and_module(self):
        r = view.parse_line(policy("23:01:00.000200", "10.10.1.5:4444"), "b-cp")
        self.assertEqual(r.module, "state")
        self.assertEqual(r.workload, "fx/server")
        self.assertEqual(r.spans["inbound"]["peer"], "10.10.1.5:4444")

    def test_non_records_are_skipped(self):
        for line in ("", "starting ztunnel", "# comment", "not-a-time\tinfo\tx\ty"):
            self.assertIsNone(view.parse_line(line, "n"))

    def test_coverage_header_overrides_first_and_last_line(self):
        with Logs({"a-worker": [COVER, access("23:05:00.0", "outbound", 1)]}) as logs:
            _, coverage = view.read_logs(logs.paths)
        start, end = coverage["a-worker"]
        self.assertEqual((start.minute, end.minute), (0, 10))

    def test_coverage_defaults_to_first_and_last_record(self):
        with Logs({"n": [access("23:05:00.0", "outbound", 1), access("23:06:00.0", "outbound", 2)]}) as logs:
            _, coverage = view.read_logs(logs.paths)
        self.assertEqual(coverage["n"][1] - coverage["n"][0], timedelta(minutes=1))


class ConnectionTests(unittest.TestCase):
    def build(self, nodes):
        with Logs(nodes) as logs:
            records = view.read_records(logs.paths)
        return view.connections(records), records

    def test_outbound_and_inbound_pair_into_one_cross_cluster_connection(self):
        conns, _ = self.build({
            "a-worker": [access("23:01:00.010", "outbound", 5555)],
            "b-cp": [access("23:01:00.012", "inbound", 4444), policy("23:01:00.011", "10.10.1.5:4444")],
        })
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual((c.scope, c.app_port, c.outer_port, c.peer_identity), ("cross cluster", "8080", "15008", CLIENT))
        self.assertEqual(c.policy, "fx/cilium_l4_effective_0123")

    def test_lines_too_far_apart_do_not_pair(self):
        conns, _ = self.build({"a-worker": [access("23:01:00.0", "outbound", 1)],
                               "b-cp": [access("23:01:05.0", "inbound", 2)]})
        self.assertEqual(len(conns), 2)
        self.assertEqual(sorted(bool(c.inbound) for c in conns), [False, True])

    def test_outbound_only_has_no_peer_identity(self):
        conns, _ = self.build({"a-worker": [access("23:01:00.0", "outbound", 1)]})
        self.assertIsNone(conns[0].peer_identity)

    def test_same_cluster_scope_uses_the_nodes_of_both_sides(self):
        same = access("23:01:00.0", "outbound", 1).replace('dst.cluster="cmtc-b"', 'dst.cluster="cmtc-a"')
        inbound = access("23:01:00.001", "inbound", 2).replace('dst.cluster="cmtc-b"', 'dst.cluster="cmtc-a"')
        self.assertEqual(self.build({"n1": [same], "n2": [inbound]})[0][0].scope, "cross node")
        self.assertEqual(self.build({"n1": [same, inbound]})[0][0].scope, "same node")

    def test_problems_group_by_message_without_ids(self):
        _, records = self.build({"a-worker": [HANDSHAKE.format(at="23:02:00.000", id="0" * 32),
                                              HANDSHAKE.format(at="23:02:09.001", id="1" * 32)]})
        probs = view.problems(records)
        self.assertEqual(len(probs), 1)
        self.assertEqual(len(probs[0].records), 2)
        self.assertIn('PermissionDenied, "authenticated issuer profile/session expired or changed"', probs[0].summary)

    def test_cli_renders_every_section_and_json(self):
        lines = {"a-worker": [access("23:01:00.010", "outbound", 5555), HANDSHAKE.format(at="23:02:00.0", id="2" * 32)],
                 "b-cp": [access("23:01:00.012", "inbound", 4444)]}
        with Logs(lines) as logs:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(view.main(logs.paths + ["--color", "always", "--fail-on-problems"]), 1)
            for title in ("Overview", "Peer identities", "Flows", "Timeline", "Problems"):
                self.assertIn(title, out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                view.main(logs.paths + ["--json"])
        self.assertEqual(json.loads(out.getvalue())["connections"][0]["peerIdentity"], CLIENT)


class DropParseTests(unittest.TestCase):
    def test_measured_drop_line(self):
        d = drops.parse_line(MEASURED_DROP, "cmtc-a-worker")
        self.assertEqual((d.reason, d.location, d.proto), ("Policy denied", "bpf_lxc.c:1626", "udp"))
        self.assertEqual((d.src_ip, d.src_port, d.dst_ip, d.dst_port), ("10.10.1.205", "46029", "10.10.0.193", "53"))
        self.assertEqual((d.src_identity, d.dst_identity, d.at.second), ("69042", "66322", 49))

    def test_reason_with_parentheses_and_ip_trace_id(self):
        line = drop("23:01:00.0", reason="No tunnel/encapsulation endpoint (datapath BUG!)").replace(
            ", , identity", ",  [ ip-trace-id = 5 ], identity")
        d = drops.parse_line(line, "n")
        self.assertEqual((d.reason, d.location, d.dst_port), ("No tunnel/encapsulation endpoint (datapath BUG!)",
                                                              "bpf_lxc.c:2373", "8080"))

    def test_ipv6_and_icmp_summaries(self):
        v6 = drops.parse_line(drop("23:01:00.0", src="[fd00::1]:4000", dst="[fd00::2]:80"), "n")
        self.assertEqual((v6.src_ip, v6.dst_ip, v6.dst_port), ("fd00::1", "fd00::2", "80"))
        icmp = drops.parse_line(drop("23:01:00.0", src="10.0.0.1", dst="10.0.0.2", proto="icmp EchoRequest"), "n")
        self.assertEqual((icmp.proto, icmp.dst_ip, icmp.dst_port), ("icmp", "10.0.0.2", ""))

    def test_lost_events_and_other_lines(self):
        lost = drops.parse_line("2026-10-25T23:01:00.0Z CPU 02: Lost 7 events", "n")
        self.assertEqual((type(lost), lost.count), (drops.Lost, 7))
        for line in ("2026-10-25T23:01:00.0Z Press Ctrl-C to quit", "2026-10-25T23:01:00.0Z CMTC_MONITOR_EXIT=124",
                     '2026-10-25T23:01:00.0Z time=x level=info msg="Initializing dissection cache..."', "# x", ""):
            self.assertIsNone(drops.parse_line(line, "n"))

    def test_capture_without_coverage_is_refused(self):
        with Logs({"n": [MEASURED_DROP]}) as logs, self.assertRaises(SystemExit):
            drops.read_drops(logs.paths)

    def test_cli_renders_coverage_drops_and_json(self):
        with Logs({"cmtc-a-worker": [COVER, MEASURED_DROP, "2026-10-25T23:00:50.0Z CPU 01: Lost 2 events"]}) as logs:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(drops.main(logs.paths + ["--color", "never"]), 0)
            self.assertIn("2 event(s) lost", out.getvalue())
            self.assertIn("bpf_lxc.c:1626", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                drops.main(logs.paths + ["--json"])
        self.assertEqual(json.loads(out.getvalue())[0]["dst"], "10.10.0.193:53")


class JoinCase:
    """Runs the join on synthetic logs, probes and drop captures. A mixin, so that its subclasses share no tests."""

    def run_join(self, nodes, probes, drop_nodes=None):
        with Logs(nodes) as logs, Logs(drop_nodes or {}) as captures, tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pods.txt").write_text(PODS)
            Path(tmp, "probes.json").write_text(json.dumps(probes))
            out = Path(tmp, "join.json")
            with contextlib.redirect_stdout(io.StringIO()):
                code = join.main([str(Path(tmp, "probes.json")), "--pods", str(Path(tmp, "pods.txt")),
                                  "--trust-domain", f"cmtc-a={A}", "--trust-domain", f"cmtc-b={B}",
                                  "--logs", *logs.paths, "--out", str(out), "--color", "never"]
                                 + (["--drops", *captures.paths] if drop_nodes else []))
            return code, json.loads(out.read_text())

    @staticmethod
    def probe(at="2026-10-25T23:01:00.050000+00:00", url="http://10.20.0.7:8080/?q=1", client="client",
              namespace="fx", expect="allow", rc="0"):
        return {"at": at, "context": "kind-cmtc-a", "namespace": namespace, "client": client, "url": url,
                "expect": expect, "scope": "crosscluster", "curlRC": rc}

    def good_logs(self, **overrides):
        return {"a-worker": [COVER, access("23:01:00.010", "outbound", 5555, **overrides)],
                "b-cp": [COVER, access("23:01:00.012", "inbound", 4444, **overrides)]}

class JoinTests(JoinCase, unittest.TestCase):
    def test_allowed_probe_is_proven(self):
        code, rows = self.run_join(self.good_logs(), [self.probe()])
        self.assertEqual((code, rows[0]["result"], rows[0]["servedBy"]), (0, join.PROVEN, "cmtc-b/server"))

    def test_wrong_peer_identity_fails(self):
        code, rows = self.run_join(self.good_logs(src_id=f"spiffe://{A}/ns/fx/sa/other"), [self.probe()])
        self.assertEqual(code, 1)
        self.assertIn("peer identity", rows[0]["result"])

    def test_plaintext_outer_port_fails(self):
        code, rows = self.run_join(self.good_logs(outer="8080"), [self.probe()])
        self.assertIn("not HBONE", rows[0]["result"])

    def test_missing_server_side_line_fails(self):
        logs = {"a-worker": [COVER, access("23:01:00.010", "outbound", 5555)], "b-cp": [COVER]}
        _, rows = self.run_join(logs, [self.probe()])
        self.assertIn("no server-side (inbound) line", rows[0]["result"])

    def test_service_address_joins_to_the_backend_that_served_it(self):
        _, rows = self.run_join(self.good_logs(), [self.probe(url="http://10.21.0.50:8080/")])
        self.assertEqual((rows[0]["result"], rows[0]["servedBy"]), (join.PROVEN, "cmtc-b/server"))

    def test_failed_curl_is_a_failure(self):
        _, rows = self.run_join(self.good_logs(), [self.probe(rc="28")])
        self.assertIn("curl exit 28", rows[0]["result"])

    def test_unanswered_caller_with_no_ztunnel_line(self):
        deny = self.probe(client="stranger", namespace="fx-unauth", expect="deny", rc="28")
        code, rows = self.run_join(self.good_logs(), [deny])
        self.assertEqual((code, rows[0]["result"]), (0, join.DENIED))

    def test_denied_caller_seen_by_ztunnel_fails(self):
        logs = self.good_logs()
        logs["b-cp"].append(access("23:01:00.020", "inbound", 9, src_ip="10.10.1.9"))
        deny = self.probe(client="stranger", namespace="fx-unauth", expect="deny", rc="28")
        _, rows = self.run_join(logs, [deny])
        self.assertIn("saw the denied caller", rows[0]["result"])

    def test_denied_caller_that_got_a_response_fails(self):
        deny = self.probe(client="stranger", namespace="fx-unauth", expect="deny", rc="0")
        _, rows = self.run_join(self.good_logs(), [deny])
        self.assertIn("got a response", rows[0]["result"])

    def test_probe_outside_log_coverage_is_not_judged(self):
        _, rows = self.run_join(self.good_logs(), [self.probe(at="2026-10-25T22:57:00+00:00",
                                                              client="stranger", namespace="fx-unauth",
                                                              expect="deny", rc="28")])
        self.assertIn("do not cover this probe", rows[0]["result"])


class DropJoinTests(JoinCase, unittest.TestCase):
    """--drops: Cilium drop captures name the component that dropped a probe."""

    def deny(self, **overrides):
        return self.probe(client="stranger", namespace="fx-unauth", expect="deny", rc="28", **overrides)

    def test_denied_probe_with_a_matching_drop_is_attributed(self):
        code, rows = self.run_join(self.good_logs(), [self.deny()],
                                   {"b-cp": [COVER, drop("23:00:59.000"), drop("23:01:00.000")]})
        self.assertEqual((code, rows[0]["result"]), (0, "dropped by Cilium: Policy denied at bpf_lxc.c:2373"))
        self.assertEqual(len(rows[0]["drops"]), 2)

    def test_without_drops_the_verdict_stays(self):
        _, rows = self.run_join(self.good_logs(), [self.deny()])
        self.assertEqual(rows[0]["result"], join.DENIED)
        self.assertNotIn("dropSearch", rows[0])

    def test_other_flows_and_times_do_not_match(self):
        captures = {"b-cp": [COVER,
                             drop("23:00:59.0", dst="10.20.0.7:80"),            # another port
                             drop("23:00:59.0", proto="udp"),                    # another protocol
                             drop("23:00:59.0", src="10.10.1.5:41000"),          # another caller
                             drop("23:00:59.0", dst="10.20.0.8:8080"),           # another destination
                             drop("23:00:50.0")]}                                # before the window
        code, rows = self.run_join(self.good_logs(), [self.deny()], captures)
        self.assertEqual((code, rows[0]["result"]), (0, join.DENIED))
        self.assertEqual(rows[0]["dropSearch"], "no matching Cilium drop in the captures of b-cp")

    def test_a_drop_outside_the_capture_coverage_does_not_count(self):
        early = "# coverage 2026-10-25T23:00:00Z 2026-10-25T23:00:59.5Z"
        _, rows = self.run_join(self.good_logs(), [self.deny()], {"b-cp": [early, drop("23:00:59.8")]})
        self.assertEqual(rows[0]["result"], join.DENIED)
        self.assertIn("the drop captures of b-cp do not cover this probe", rows[0]["dropSearch"])

    def test_lost_events_weaken_the_absence_of_a_drop(self):
        _, rows = self.run_join(self.good_logs(), [self.deny()],
                                {"b-cp": [COVER, "2026-10-25T23:01:05.0Z CPU 01: Lost 3 events"]})
        self.assertIn("reported 3 lost event(s)", rows[0]["dropSearch"])

    def test_started_at_opens_the_window(self):
        captures = {"a-worker": [COVER, drop("23:00:56.000")]}
        _, rows = self.run_join(self.good_logs(), [self.deny()], captures)
        self.assertEqual(rows[0]["result"], join.DENIED)
        _, rows = self.run_join(self.good_logs(), [self.deny() | {"startedAt": "2026-10-25T23:00:55+00:00"}], captures)
        self.assertEqual(rows[0]["result"], "dropped by Cilium: Policy denied at bpf_lxc.c:2373")

    def test_a_drop_to_a_service_backend_matches_a_service_address(self):
        _, rows = self.run_join(self.good_logs(), [self.deny(url="http://10.21.0.50:8080/")],
                                {"b-cp": [COVER, drop("23:00:59.0")]})
        self.assertTrue(rows[0]["result"].startswith(join.DROPPED))

    def test_failed_ip_probe_with_a_drop(self):
        _, rows = self.run_join(self.good_logs(), [self.probe(rc="28")],
                                {"b-cp": [COVER, drop("23:00:59.0", src="10.10.1.5:41000")]})
        self.assertEqual(rows[0]["result"], "FAIL: curl exit 28, no connection to join; "
                                            "dropped by Cilium: Policy denied at bpf_lxc.c:2373")


class DnsNameTests(JoinCase, unittest.TestCase):
    """A failed probe of a DNS name says what the data shows: the name, curl's error, and the connections seen."""

    def named(self, port=80, **overrides):
        return self.probe(url=f"http://server.fx.svc.cluster.local:{port}/?cmtc=1", rc="28",
                          **overrides) | {"stderr": "curl: (28) Resolving timed out after 3001 milliseconds\n"}

    def test_failed_name_probe_says_the_target_is_a_dns_name(self):
        code, rows = self.run_join(self.good_logs(), [self.named()])
        self.assertEqual(code, 1)
        self.assertEqual(rows[0]["result"], 'FAIL: curl exit 28 ("Resolving timed out"); the target is a DNS name; '
                                            "no ztunnel connection from the client to a backend on port 80 in the "
                                            "window")
        self.assertEqual(rows[0]["targetName"], "server.fx.svc.cluster.local")

    def test_a_backend_connection_in_the_window_is_reported(self):
        _, rows = self.run_join(self.good_logs(), [self.named(port=8080)])
        self.assertIn("a ztunnel connection from the client to a backend on port 8080 is in the window",
                      rows[0]["result"])

    def test_curl_errors_lose_only_their_variable_tail(self):
        for stderr, said in (("curl: (6) Could not resolve host: server.fx\n", "Could not resolve host: server.fx"),
                             ("curl: (28) Failed to connect to 10.0.0.1 port 80 after 2005 ms: Timeout was reached",
                              "Failed to connect to 10.0.0.1 port 80"),
                             ("", None)):
            self.assertEqual(join.curl_error({"stderr": stderr}), said)

    def test_a_dns_drop_from_the_client_is_reported(self):
        captures = {"a-worker": [COVER, drop("23:00:59.0", src="10.10.1.5:46029", dst="10.11.0.10:53", proto="udp",
                                             where="bpf_lxc.c:1626")]}
        _, rows = self.run_join(self.good_logs(), [self.named()], captures)
        self.assertTrue(rows[0]["result"].endswith(
            "; Cilium dropped DNS traffic from the client: Policy denied at bpf_lxc.c:1626"))
        self.assertEqual(len(rows[0]["drops"]), 1)

    def test_runner_curl_timings_travel_with_the_row(self):
        timings = {"time_namelookup": "0.000000", "remote_ip": "", "exitcode": "28"}
        _, rows = self.run_join(self.good_logs(), [self.named() | {"curl": timings}])
        self.assertEqual(rows[0]["curl"], timings)


def _bash5_and_timeout() -> bool:
    if shutil.which("timeout") is None or shutil.which("bash") is None:
        return False
    probe = subprocess.run(["bash", "-c", "echo ${EPOCHREALTIME:-}"], capture_output=True, text=True)
    return bool(probe.stdout.strip())


STUB_KUBECTL = """#!/usr/bin/env bash
# kubectl stub: "get" names one agent Pod; "exec ... -- CMD" runs CMD here. STUB_STREAM_SECONDS cuts the exec stream
# after that time, as a lost API connection does: the remote side never sends its exit line.
while [ $# -gt 0 ]; do case $1 in get) echo cilium-stub; exit 0;; --) shift; break;; esac; shift; done
[ -n "${STUB_STREAM_SECONDS:-}" ] || exec "$@"
"$@" | timeout "$STUB_STREAM_SECONDS" cat
exit 1
"""
def kill_group(pid):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)


STUB_MONITOR = """#!/usr/bin/env bash
echo "Press Ctrl-C to quit" >&2
[ "${STUB_MODE:-}" = now ] && exit 3
sleep 1.3
if [ "${STUB_MODE:-}" = split ]; then
  # One line in two writes, 1.5 s apart: the reader's 1 s heartbeat times out in the middle of it.
  printf "xx drop (Policy denied) flow 0xe380ae81 to endpoint 0, ifindex 403, file bpf_lxc.c"
  sleep 1.5
else
  printf "xx drop (Policy denied) flow 0xe380ae81 to endpoint 0, ifindex 403, file bpf_lxc.c"
fi
echo ":1626, , identity 1->2: 10.10.1.205:46029 -> 10.10.0.193:53 udp"
[ "${STUB_MODE:-}" = exit ] && exit 3
exec sleep 30
"""


@unittest.skipUnless(_bash5_and_timeout(), "needs bash 5 and GNU timeout on PATH, as in the Cilium agent image")
class CaptureScriptTests(unittest.TestCase):
    """capture_cilium_drops.sh against a stubbed kubectl, with the agent container's commands run locally."""

    def capture(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            stubs = Path(tmp, "bin")
            stubs.mkdir()
            for name, body in (("kubectl", STUB_KUBECTL), ("cilium-dbg", STUB_MONITOR)):
                Path(stubs, name).write_text(body)
                Path(stubs, name).chmod(0o755)
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", STUB_MODE=mode)
            run = subprocess.run(["bash", str(HERE / "capture_cilium_drops.sh"), str(Path(tmp, "out")), "2",
                                  "kind-x/node-a"], env=env, capture_output=True, text=True, timeout=30)
            found, coverage, _ = drops.read_drops([str(Path(tmp, "out", "node-a.log"))])
            return run, found, coverage["node-a"]

    def test_a_clean_capture_declares_its_coverage(self):
        run, found, (start, end) = self.capture("clean")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual([d.location for d in found], ["bpf_lxc.c:1626"])
        self.assertTrue(start < found[0].at < end, (start, found[0].at, end))
        self.assertTrue(timedelta(0) < end - start <= timedelta(seconds=1.1), end - start)

    def test_a_monitor_that_stops_early_fails_and_its_coverage_ends_there(self):
        run, found, (start, end) = self.capture("exit")
        self.assertEqual(run.returncode, 1)
        self.assertIn("exited with 3 before the timeout", run.stderr)
        self.assertTrue(start < found[0].at <= end < start + timedelta(seconds=0.9), (start, found[0].at, end))

    def test_a_monitor_that_stops_before_its_coverage_starts_covers_nothing(self):
        run, _, (start, end) = self.capture("now")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(start, end)

    def start(self, tmp, seconds="30", **env):
        stubs = Path(tmp, "bin")
        stubs.mkdir()
        for name, body in (("kubectl", STUB_KUBECTL), ("cilium-dbg", STUB_MONITOR)):
            Path(stubs, name).write_text(body)
            Path(stubs, name).chmod(0o755)
        env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", STUB_MODE="clean", **env)
        proc = subprocess.Popen(["bash", str(HERE / "capture_cilium_drops.sh"), str(Path(tmp, "out")), seconds,
                                 "kind-x/node-a"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        self.addCleanup(kill_group, proc.pid)
        self.assertIn("capturing drops on 1 node(s)", proc.stderr.readline())
        return proc

    def test_an_interrupted_capture_keeps_its_lines_and_a_true_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.start(tmp)
            time.sleep(2.5)
            stopped = datetime.now(timezone.utc)
            proc.send_signal(signal.SIGTERM)
            _, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 143, err)
            self.assertIn("interrupted by SIGTERM", err)
            found, coverage, _ = drops.read_drops([str(Path(tmp, "out", "node-a.log"))])
            start, end = coverage["node-a"]
            self.assertEqual([d.location for d in found], ["bpf_lxc.c:1626"])
            # The coverage reaches the last heartbeat before the signal, never past it.
            self.assertTrue(found[0].at < end <= stopped, (found[0].at, end, stopped))
            self.assertFalse(Path(tmp, "out", ".raw").exists())

    def test_a_killed_capture_is_finalized_from_its_raw_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.start(tmp)
            time.sleep(2.5)
            finalize = ["bash", str(HERE / "capture_cilium_drops.sh"), "--finalize", str(Path(tmp, "out"))]
            # SIGKILL of the script alone: no trap runs, and its stream still writes, so finalizing must wait.
            proc.kill()
            proc.communicate(timeout=30)
            self.assertFalse(Path(tmp, "out", "node-a.log").exists())
            run = subprocess.run(finalize, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertIn("is still written", run.stderr)
            os.killpg(proc.pid, signal.SIGKILL)
            time.sleep(0.5)
            run = subprocess.run(finalize, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertIn("killed before it finished", run.stderr)
            found, coverage, _ = drops.read_drops([str(Path(tmp, "out", "node-a.log"))])
            self.assertEqual([d.location for d in found], ["bpf_lxc.c:1626"])
            self.assertTrue(found[0].at < coverage["node-a"][1], coverage)

    def test_a_lost_stream_covers_until_its_last_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.start(tmp, STUB_STREAM_SECONDS="3")
            _, err = proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("the stream ended before the monitor stopped", err)
            found, coverage, _ = drops.read_drops([str(Path(tmp, "out", "node-a.log"))])
            # The drop arrives at 1.3 s; heartbeats prove the stream alive for about 1.5 s more.
            self.assertGreater(coverage["node-a"][1] - found[0].at, timedelta(seconds=0.8), coverage)

    def test_a_line_split_across_a_heartbeat_stays_one_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            stubs = Path(tmp, "bin")
            stubs.mkdir()
            for name, body in (("kubectl", STUB_KUBECTL), ("cilium-dbg", STUB_MONITOR)):
                Path(stubs, name).write_text(body)
                Path(stubs, name).chmod(0o755)
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}", STUB_MODE="split")
            run = subprocess.run(["bash", str(HERE / "capture_cilium_drops.sh"), str(Path(tmp, "out")), "5",
                                  "kind-x/node-a"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            log = Path(tmp, "out", "node-a.log").read_text()
            found, _, _ = drops.read_drops([str(Path(tmp, "out", "node-a.log"))])
            self.assertEqual([(d.location, d.src_ip, d.src_port, d.dst_ip, d.dst_port) for d in found],
                             [("bpf_lxc.c:1626", "10.10.1.205", "46029", "10.10.0.193", "53")], log)
            self.assertNotIn("CMTC_ALIVE", log)

    def test_a_used_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "out").mkdir()
            Path(tmp, "out", "node-a.log").write_text("# coverage x y\n")
            run = subprocess.run(["bash", str(HERE / "capture_cilium_drops.sh"), str(Path(tmp, "out")), "2",
                                  "kind-x/node-a"], capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 2)
            self.assertIn("already holds a capture", run.stderr)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class DnsCheckScriptTests(unittest.TestCase):
    def check(self, kubectl):
        with tempfile.TemporaryDirectory() as tmp:
            stubs = Path(tmp, "bin")
            stubs.mkdir()
            Path(stubs, "kubectl").write_text(kubectl)
            Path(stubs, "kubectl").chmod(0o755)
            env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
            run = subprocess.run(["bash", str(HERE / "dns_check.sh"), str(Path(tmp, "dns.txt")), "kubernetes.default",
                                  "kind-x/fx/client"], env=env, capture_output=True, text=True, timeout=30)
            return run, Path(tmp, "dns.txt").read_text().splitlines()[-1]

    def test_the_answer_or_the_error_is_recorded(self):
        run, line = self.check('#!/bin/sh\nprintf "CMTC_NAMESERVER=10.11.0.10\\n;; connection timed out; '
                               'no servers could be reached\\n\\nCMTC_RC=1\\n"\n')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("kind-x fx/client nameserver=10.11.0.10 rc=1 ;; connection timed out; no servers could be "
                      "reached", line)

    def test_a_failed_exec_is_not_an_answer(self):
        run, line = self.check('#!/bin/sh\necho "error: container not found" >&2\nexit 1\n')
        self.assertEqual(run.returncode, 1)
        self.assertIn("nameserver=? rc=exec error: container not found", line)


if __name__ == "__main__":
    unittest.main()
