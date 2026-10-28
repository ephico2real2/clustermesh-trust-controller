#!/usr/bin/env python3
"""Checks metrics/contract.json against the sources and the hub it describes.

  sources     For every entry whose source records a token and a line, read the file at the recorded ref and check
              that the token is on that line. --repin REPO=REF reads the entries recorded at REPO's pin
              (captured.pins) at REF instead; --repin REPO@OLDREF=REF does so for the entries recorded at OLDREF.
              With --write it records REF, the new line and, for the first form, the new pin. A token that is
              missing, or not unique where the entry declares no occurrence, is reported and never written.
  collection  For every entry, whether its sample names are in the hub now, and under which job, against the
              entry's collection. "scraped" must be in the hub under the component's job; "not-scraped",
              "dropped-at-ingestion", "not-deployed" and "not-configured" must not be. A name that is not
              zero-initialized may be absent because nothing happened yet; it is reported, not failed.

A checkout is REPO=PATH, a git repository read with `git show REF:FILE`, or REPO@REF=DIR, a plain directory that
holds that ref (an unpacked release, the Go module cache). Exit 1 on a mismatch.

Usage:
  contract_check.py sources --checkout cmtc=. --checkout cilium=../cilium [--repin cilium=823d30c51b]
                            [--repin 'cmtc@<old ref>=<branch commit>'] [--write]
  contract_check.py collection --hub http://127.0.0.1:9090 [--save names.json | --names names.json]
"""
import argparse
import json
import pathlib
import subprocess
import sys
import urllib.parse
import urllib.request

V2 = pathlib.Path(__file__).resolve().parent.parent
CONTRACT = V2 / "metrics" / "contract.json"
# captured.pins key of each source repo whose pin moves with --repin.
PIN_KEYS = {"cmtc": "cmtc", "cilium": "cilium-agent", "ztunnel": "ztunnel", "spire": "spire"}


def sample_names(entry):
    if entry["type"] == "histogram":
        return {entry["name"] + suffix for suffix in ("_bucket", "_sum", "_count")}
    return {entry["name"]}


class Sources:
    def __init__(self, checkouts):
        self.git, self.dirs = {}, {}
        for item in checkouts:
            key, _, path = item.partition("=")
            if not path:
                sys.exit(f"--checkout {item}: want REPO=PATH or REPO@REF=DIR")
            if "@" in key:
                self.dirs[tuple(key.split("@", 1))] = pathlib.Path(path)
            else:
                self.git[key] = pathlib.Path(path)

    def covers(self, repo, ref):
        return repo in self.git or (repo, ref) in self.dirs

    def read(self, repo, ref, path):
        if (repo, ref) in self.dirs:
            return (self.dirs[(repo, ref)] / path).read_text()
        done = subprocess.run(["git", "-C", str(self.git[repo]), "show", f"{ref}:{path}"], capture_output=True, text=True)
        if done.returncode != 0:
            raise LookupError(done.stderr.strip())
        return done.stdout

    def resolve(self, repo, ref):
        """The full commit of ref, for the pin."""
        return subprocess.run(["git", "-C", str(self.git[repo]), "rev-parse", "--verify", f"{ref}^{{commit}}"],
                              check=True, capture_output=True, text=True).stdout.strip()


def find(text, token, occurrence):
    hits = [i + 1 for i, line in enumerate(text.splitlines()) if token in line]
    if occurrence is None:
        return (hits[0], None) if len(hits) == 1 else (None, f"on lines {hits}, want exactly one")
    if len(hits) < occurrence:
        return None, f"{len(hits)} times, want occurrence {occurrence}"
    return hits[occurrence - 1], None


def check_sources(args):
    contract = json.loads(CONTRACT.read_text())
    sources = Sources(args.checkout)
    pins = contract["captured"]["pins"]
    repin = {}  # (repo, recorded ref) -> new ref
    for item in args.repin:
        key, _, ref = item.partition("=")
        repo, _, old = key.partition("@")
        if repo not in sources.git or not ref:
            sys.exit(f"--repin {item}: want REPO=REF or REPO@OLDREF=REF, with --checkout {repo}=<git repository>")
        repin[(repo, old or None)] = ref
    failures = checked = moved = 0
    skipped = set()
    for entry in contract["metrics"]:
        source = entry["source"]
        if "token" not in source:
            continue
        repo = source["repo"]
        pinned = repo in PIN_KEYS and pins.get(PIN_KEYS[repo], "").startswith(source["ref"])
        ref = repin.get((repo, source["ref"])) or (repin.get((repo, None)) if pinned else None) or source["ref"]
        if ref == source["ref"] and not sources.covers(repo, source["ref"]):
            skipped.add(f"{repo}@{source['ref']}")
            continue
        try:
            line, problem = find(sources.read(repo, ref, source["file"]), source["token"], source.get("occurrence"))
        except (LookupError, OSError) as err:
            line, problem = None, f"cannot read {source['file']}: {err}"
        checked += 1
        if problem:
            failures += 1
            print(f"FAIL {entry['name']} ({entry['component']}): {repo}@{ref} {source['file']}: token "
                  f"{source['token']!r} {problem}")
            continue
        if ref != source["ref"] or line != source["line"]:
            moving = ref != source["ref"]
            print(f"{'MOVE' if moving else 'FAIL'} {entry['name']}: {repo} {source['ref']}:{source['line']} "
                  f"-> {ref}:{line}")
            if moving:
                moved += 1
                source["ref"], source["line"] = ref, line
            else:
                failures += 1
    for (repo, old), ref in repin.items():
        if old is None and repo in PIN_KEYS:
            pins[PIN_KEYS[repo]] = sources.resolve(repo, ref)
    print(f"{checked} source lines checked, {moved} moved, {failures} failed; no checkout for: "
          f"{', '.join(sorted(skipped)) or 'none'}")
    if args.write and not failures:
        CONTRACT.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {CONTRACT.relative_to(V2)}")
    elif args.write:
        print("not written: fix the failures first")
    return 1 if failures else 0


def hub_names(url):
    query = urllib.parse.urlencode({"query": 'count by (job, __name__) ({__name__=~".+"})'})
    with urllib.request.urlopen(f"{url.rstrip('/')}/api/v1/query?{query}", timeout=30) as response:
        body = json.load(response)
    if body.get("status") != "success":
        sys.exit(f"hub query failed: {body}")
    jobs = {}
    for series in body["data"]["result"]:
        jobs.setdefault(series["metric"].get("job", ""), set()).add(series["metric"]["__name__"])
    return jobs


def check_collection(args):
    contract = json.loads(CONTRACT.read_text())
    if args.names:
        jobs = {job: set(names) for job, names in json.loads(pathlib.Path(args.names).read_text()).items()}
    else:
        jobs = hub_names(args.hub)
        if args.save:
            pathlib.Path(args.save).write_text(json.dumps({j: sorted(n) for j, n in sorted(jobs.items())}, indent=1) + "\n")
    failures = 0
    for entry in contract["metrics"]:
        names = sample_names(entry)
        found = sorted(job for job, held in jobs.items() if names & held)
        job = contract["components"][entry["component"]]["job"]
        # Prometheus writes up and ALERTS under the job of each target, or under none.
        own = bool(found) if entry["component"] == "prometheus" else job in found
        declared = entry["collection"]
        if declared == "scraped" and not own:
            verdict = "FAIL" if entry["zero_initialized"] or found else "ABSENT"
        elif declared != "scraped" and own:
            # A generic name (process_*, controller_runtime_*) under another job is another component's series.
            verdict = "FAIL"
        else:
            continue
        failures += verdict == "FAIL"
        print(f"{verdict} {entry['name']} ({entry['component']}, job {job}): declared {declared}, "
              f"in the hub under {found or 'no job'}")
    print(f"{len(contract['metrics'])} entries, {failures} failed; jobs in the hub: {', '.join(sorted(jobs))}")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sources")
    s.add_argument("--checkout", action="append", default=[])
    s.add_argument("--repin", action="append", default=[], help="REPO=REF")
    s.add_argument("--write", action="store_true")
    c = sub.add_parser("collection")
    group = c.add_mutually_exclusive_group(required=True)
    group.add_argument("--hub")
    group.add_argument("--names", help="a file written by --save")
    c.add_argument("--save")
    args = parser.parse_args()
    return check_sources(args) if args.command == "sources" else check_collection(args)


if __name__ == "__main__":
    sys.exit(main())
