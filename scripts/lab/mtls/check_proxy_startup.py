#!/usr/bin/env python3
"""Probe local proxy startup semantics without mounting workload credentials."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


def probe(engine, image, arguments, environment, log_path, resolver_file):
    name = "cmtc-cli-contract-" + uuid.uuid4().hex[:12]
    command = engine + ["run", "--rm", "--pull=never", "--name", name,
        "--platform", "linux/arm64", "--network", "none", "--cap-drop", "ALL",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=16m",
        "--volume", str(resolver_file) + ":/etc/resolv.conf:ro",
        "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1",
        "--entrypoint", "/usr/local/bin/ztunnel"]
    for key, value in {"RUST_LOG": "info", "IPV6_ENABLED": "false",
                       "FAKE_CA": "false", "INPOD_UDS": "/tmp/ztunnel.sock",
                       "XDS_ADDRESS": "http://127.0.0.1:15012",
                       "CA_ADDRESS": "http://127.0.0.1:15012",
                       "XDS_ROOT_CA": "SYSTEM", "CA_ROOT_CA": "SYSTEM",
                       **environment}.items():
        command.extend(["--env", key + "=" + value])
    command.extend([image, *arguments])
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    expired = False
    output = ""
    try:
        try:
            output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            expired = True
            subprocess.run(engine + ["kill", name], check=False, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            output, _ = process.communicate(timeout=10)
        return {"exitCode": process.returncode, "timedOut": expired}, output
    finally:
        if process.poll() is None:
            process.kill()
            remaining, _ = process.communicate()
            output += remaining or ""
        log_path.write_text(output)
        # The UUID is created by this probe; never match/prune other containers.
        subprocess.run(engine + ["rm", "--force", "--ignore", name],
                       check=False, timeout=10, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", default="cmtc-ubuntu-build")
    parser.add_argument("--old-image", required=True)
    parser.add_argument("--new-image", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--shared-fixture-directory", type=Path, default=Path('/private/tmp'),
                        help="Directory shared with the selected local Podman VM")
    args = parser.parse_args()
    if (args.out / 'results.json').exists():
        parser.error('Use a fresh evidence directory')
    args.out.mkdir(parents=True, exist_ok=True)
    engine = ["podman", "--connection", args.connection]
    report = {"status": "running", "qualification": "cli-configuration-only",
              "deploymentReady": False, "cases": []}
    fixture = tempfile.TemporaryDirectory(prefix='cmtc-startup-fixture-', dir=args.shared_fixture_directory)
    resolver_file = Path(fixture.name) / 'resolv.conf'
    resolver_file.write_text('nameserver 127.0.0.1\noptions attempts:1 timeout:1\n')
    try:
        # Version must exit cleanly and identify the actual new source.
        version, output = probe(engine, args.new_image, ["version"], {}, args.out / "new-version.log", resolver_file)
        if version["timedOut"] or version["exitCode"] != 0 or args.expected_revision not in output:
            raise RuntimeError("new image version does not prove the expected source revision")
        report["newVersion"] = version
        old, output = probe(engine, args.old_image, ["proxy-mtls"], {}, args.out / "old-strict.log", resolver_file)
        if old["timedOut"] or old["exitCode"] != 1 or "unknown command: proxy-mtls" not in output:
            raise RuntimeError("old image did not explicitly reject the strict command")
        report["oldStrict"] = old
        cases = [
            ("default", [], {}, False),
            ("proxy-default", ["proxy"], {}, False),
            ("proxy-env-true", ["proxy"], {"REQUIRE_INBOUND_MTLS": "true"}, True),
            ("strict", ["proxy-mtls"], {}, True),
            ("strict-env-false", ["proxy-mtls"], {"REQUIRE_INBOUND_MTLS": "false"}, True),
        ]
        for name, arguments, environment, expected in cases:
            result, output = probe(engine, args.new_image, arguments, environment,
                                   args.out / (name + ".log"), resolver_file)
            values = re.findall(r"^[ \t]*requireInboundMtls:[ \t]*(true|false)[ \t]*$",
                                output, re.MULTILINE)
            if (values != [str(expected).lower()] or "unknown command:" in output
                    or "panicked at" in output):
                raise RuntimeError(f"{name}: no unique expected effective authentication config")
            # A later missing local dependency is not a successful proxy deployment;
            # this probe is intentionally limited to CLI/config semantics.
            result.update(name=name, requireInboundMtls=expected, status="passed")
            report["cases"].append(result)
            print(f"PASS {name}: effective requireInboundMtls={expected}", flush=True)
        for command_name in ["proxy", "proxy-mtls"]:
            name = command_name + "-invalid-env"
            result, output = probe(engine, args.new_image, [command_name],
                {"REQUIRE_INBOUND_MTLS": "not-a-bool"}, args.out / (name + ".log"), resolver_file)
            if (result["timedOut"] or result["exitCode"] != 1
                    or "REQUIRE_INBOUND_MTLS" not in output
                    or "running with config:" in output):
                raise RuntimeError(f"{name}: invalid environment did not fail before proxy startup")
            result.update(name=name, status="passed")
            report["cases"].append(result)
        report["status"] = "passed"
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        report.update(status="failed", error=str(error))
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    finally:
        fixture.cleanup()
        (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
