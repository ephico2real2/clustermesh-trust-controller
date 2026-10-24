#!/usr/bin/env python3
"""Print all Docker IPv4 addresses for nodes in one retained CMTC kind cluster."""

import ipaddress
import json
import subprocess
import sys


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"cmtc-a", "cmtc-b"}:
        raise SystemExit("usage: kind-node-ips.py cmtc-a|cmtc-b")

    cluster = sys.argv[1]
    nodes = run("kind", "get", "nodes", "--name", cluster).splitlines()
    if not nodes:
        raise SystemExit(f"kind cluster {cluster} has no nodes")

    addresses: list[str] = []
    for node in nodes:
        if not node.startswith(f"{cluster}-"):
            raise SystemExit(f"unexpected node {node!r} in cluster {cluster}")
        networks = json.loads(
            run("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", node)
        )
        network = networks.get("kind")
        if network is None:
            raise SystemExit(f"node {node} is not attached to Docker's kind network")
        address = network.get("IPAddress", "")
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise SystemExit(f"node {node} has no valid Docker IPv4 address: {address!r}") from exc
        if address not in addresses:
            addresses.append(address)

    print(json.dumps(addresses, separators=(",", ":")))


if __name__ == "__main__":
    main()
