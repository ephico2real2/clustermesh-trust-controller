#!/usr/bin/env python3
"""Validate the native node-name projection against the live kind APIs.

For each cluster: read the agent's native node table (cilium-dbg db/show nodes),
apply the resolver rule (local-cluster rows only, every address, reject missing
or ambiguous), and compare the result for every CiliumEndpoint with the API Pod
spec.nodeName (matched by Pod UID) and the API Node name. No IP fallback.
"""
import json, subprocess, sys
K = "/private/tmp/cmtc-a-b-20261024.kubeconfig"
UIDS = {"kind-cmtc-a": ("cmtc-a", "bb7182c7-de95-4e70-816a-a1400d755794"),
        "kind-cmtc-b": ("cmtc-b", "f2687af6-bd96-45a3-98a2-d1397a3ee244")}

def kc(ctx, *args):
    return subprocess.run(["kubectl", "--kubeconfig", K, "--context", ctx, *args],
                          check=True, capture_output=True, text=True).stdout

result = {"clusters": {}, "pass": True}
for ctx, (cluster, uid) in UIDS.items():
    assert kc(ctx, "get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}") == uid, ctx
    agent = kc(ctx, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "-o", "jsonpath={.items[0].metadata.name}")
    table = kc(ctx, "-n", "kube-system", "exec", agent, "-c", "cilium-agent", "--", "cilium-dbg", "shell", "--", "db/show", "nodes")
    by_addr, ambiguous, foreign = {}, set(), 0
    for line in table.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        full, _source, addrs = parts
        c, name = full.split("/", 1)
        if c != cluster:
            foreign += 1
            continue
        for a in addrs.split(","):
            ip = a.strip().split(":", 1)[1]
            if ip in by_addr and by_addr[ip] != name:
                ambiguous.add(ip)
            by_addr[ip] = name
    api_nodes = {n["metadata"]["name"]: n["metadata"]["uid"] for n in json.loads(kc(ctx, "get", "nodes", "-o", "json"))["items"]}
    pods = {p["metadata"]["uid"]: p for p in json.loads(kc(ctx, "get", "pods", "-A", "-o", "json"))["items"]}
    ceps = json.loads(kc(ctx, "get", "ciliumendpoints", "-A", "-o", "json"))["items"]
    rows, failures = [], []
    for cep in ceps:
        owners = [o["uid"] for o in cep["metadata"].get("ownerReferences", []) if o.get("kind") == "Pod"]
        node_ip = cep.get("status", {}).get("networking", {}).get("node", "")
        name = None if node_ip in ambiguous else by_addr.get(node_ip)
        pod = pods.get(owners[0]) if len(owners) == 1 else None
        want = pod["spec"].get("nodeName") if pod else None
        ok = bool(name) and name == want and name in api_nodes and name != node_ip
        row = {"cep": cep["metadata"]["namespace"] + "/" + cep["metadata"]["name"], "podUID": owners[0] if owners else None,
               "nodeIP": node_ip, "resolved": name, "podSpecNodeName": want, "apiNodeUID": api_nodes.get(name), "ok": ok}
        rows.append(row)
        if not ok:
            failures.append(row)
    result["clusters"][cluster] = {"context": ctx, "kubeSystemUID": uid, "agent": agent,
        "localNodes": sorted(set(by_addr.values())), "foreignRowsIgnored": foreign, "apiNodes": api_nodes,
        "endpoints": len(rows), "failures": failures, "rows": rows}
    result["pass"] &= not failures and len(rows) > 0
json.dump(result, sys.stdout, indent=2)
print()
sys.exit(0 if result["pass"] else 1)
