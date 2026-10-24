#!/usr/bin/env python3
"""Run named Rust library suites and reject empty or unexpected selections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def case_spec(value):
    try:
        name, count_text = value.rsplit("=", 1)
        count = int(count_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("case must be FILTER=EXPECTED_COUNT") from error
    if not name or count < 1:
        raise argparse.ArgumentTypeError("filter and a positive expected count are required")
    return name, count


def run_logged(command, path, cwd, timeout):
    # Keep raw output even on errors. Do not use shell or echo credentials.
    try:
        result = subprocess.run(
            command, cwd=cwd, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        path.write_text(output + "\nERROR: local test command timed out\n")
        raise RuntimeError(f"command timed out; see {path}") from error
    path.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}; see {path}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--case", action="append", type=case_spec)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if (args.out / "results.json").exists():
        parser.error("Use a fresh evidence directory")
    args.out.mkdir(parents=True, exist_ok=True)
    cases = args.case or [
        ("container_runtime::tests::", 4),
        ("identity::spireclient::spire_tests::", 11),
    ]
    report = {"repo": str(repo), "cases": [], "status": "running"}
    report_path = args.out / "results.json"
    try:
        for label, command in [
            ("rustc", ["rustc", "--version", "--verbose"]),
            ("cargo", ["cargo", "--version"]),
            ("source", ["git", "rev-parse", "HEAD"]),
            ("worktree", ["git", "status", "--porcelain"]),
        ]:
            report[label] = run_logged(command, args.out / (label + ".log"), repo, 30).strip()
        for name, expected in cases:
            slug = hashlib.sha256(name.encode()).hexdigest()[:12]
            entry = {"filter": name, "expected": expected, "status": "running", "logPrefix": slug}
            report["cases"].append(entry)
            command = ["cargo", "test", "--locked", "--lib", name]
            listed = run_logged(
                command + ["--", "--list", "--format", "terse"],
                args.out / (slug + "-list.log"), repo, args.timeout,
            )
            names = re.findall(r"^(.+): test$", listed, re.MULTILINE)
            entry["discovered"] = names
            if len(names) != expected or len(set(names)) != expected:
                raise RuntimeError(f"{name}: expected {expected} distinct tests, found {len(names)}")
            if not all(test_name.startswith(name) for test_name in names):
                raise RuntimeError(f"{name}: selection escaped the requested module prefix")
            output = run_logged(
                command + ["--", "--test-threads=1"],
                args.out / (slug + "-run.log"), repo, args.timeout,
            )
            summaries = re.findall(
                r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
                output, re.MULTILINE,
            )
            if summaries != [(str(expected), "0", "0")]:
                raise RuntimeError(f"{name}: unexpected result summaries {summaries!r}")
            entry["status"] = "passed"
            print(f"PASS {name}: {expected} discovered and {expected} passed", flush=True)
        report["status"] = "passed"
    except (RuntimeError, OSError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
