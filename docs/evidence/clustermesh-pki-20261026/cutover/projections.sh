#!/usr/bin/env bash
# Print, for every Cilium agent, ztunnel and clustermesh-apiserver Pod, the SHA-256 prefix of each root in each
# projected CA file, read from the kubelet volume directory on its node (the images have no cat).
set -euo pipefail
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig LC_ALL=C
fp() { python3 -c '
import sys,re,subprocess
ps=re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",sys.stdin.read(),re.S)
print(" ".join(subprocess.run(["openssl","x509","-noout","-fingerprint","-sha256"],input=p.encode(),capture_output=True).stdout.decode().split("=")[1].replace(":","")[:8] for p in ps))'; }
for c in cmtc-a cmtc-b; do for sel in k8s-app=cilium app=ztunnel-cilium k8s-app=clustermesh-apiserver; do
  kubectl --context kind-$c -n kube-system get pods -l $sel -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.uid} {.spec.nodeName}{"\n"}{end}'
done; done | while read -r pod uid node; do
  for f in $(docker --context colima-cmtc-cilium exec "$node" sh -c "find /var/lib/kubelet/pods/$uid/volumes \( -name ca.crt -o -name bootstrap-ca.crt -o -name common-etcd-client-ca.crt \) | sort"); do
    echo "$pod ${f#/var/lib/kubelet/pods/$uid/volumes/} $(docker --context colima-cmtc-cilium exec "$node" cat "$f" | fp)"
  done
done
