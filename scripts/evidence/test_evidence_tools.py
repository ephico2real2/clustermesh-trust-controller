#!/usr/bin/env python3
"""Tests for ztunnel_log_view.py and join_probes_to_ztunnel.py, on synthetic ztunnel lines."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
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


class JoinTests(unittest.TestCase):
    def run_join(self, nodes, probes):
        with Logs(nodes) as logs, tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pods.txt").write_text(PODS)
            Path(tmp, "probes.json").write_text(json.dumps(probes))
            out = Path(tmp, "join.json")
            with contextlib.redirect_stdout(io.StringIO()):
                code = join.main([str(Path(tmp, "probes.json")), "--pods", str(Path(tmp, "pods.txt")),
                                  "--trust-domain", f"cmtc-a={A}", "--trust-domain", f"cmtc-b={B}",
                                  "--logs", *logs.paths, "--out", str(out), "--color", "never"])
            return code, json.loads(out.read_text())

    @staticmethod
    def probe(at="2026-10-25T23:01:00.050000+00:00", url="http://10.20.0.7:8080/?q=1", client="client",
              namespace="fx", expect="allow", rc="0"):
        return {"at": at, "context": "kind-cmtc-a", "namespace": namespace, "client": client, "url": url,
                "expect": expect, "scope": "crosscluster", "curlRC": rc}

    def good_logs(self, **overrides):
        return {"a-worker": [COVER, access("23:01:00.010", "outbound", 5555, **overrides)],
                "b-cp": [COVER, access("23:01:00.012", "inbound", 4444, **overrides)]}

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


if __name__ == "__main__":
    unittest.main()
