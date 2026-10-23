#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .tmp/bin .tmp/downloads
arch=amd64; [ "$(uname -m)" = aarch64 ] && arch=arm64
fetch(){ curl -fsSL --retry 5 --retry-all-errors "$2" -o "$1"; }
verify(){ local want;want=$(curl -fsSL --retry 5 "$2" | awk 'NR==1 {print $1}');[ -n "$want" ];printf '%s  %s\n' "$want" "$1" | sha256sum --check; }
kind_url="https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-$arch"
fetch .tmp/bin/kind "$kind_url";verify .tmp/bin/kind "$kind_url.sha256sum";chmod +x .tmp/bin/kind
kubectl_url="https://dl.k8s.io/release/v1.36.4/bin/linux/$arch/kubectl"
fetch .tmp/bin/kubectl "$kubectl_url";verify .tmp/bin/kubectl "$kubectl_url.sha256";chmod +x .tmp/bin/kubectl
cilium_url="https://github.com/cilium/cilium-cli/releases/download/v0.20.0/cilium-linux-$arch.tar.gz"
fetch .tmp/downloads/cilium.tgz "$cilium_url";verify .tmp/downloads/cilium.tgz "$cilium_url.sha256sum"
tar -C .tmp/bin -xzf .tmp/downloads/cilium.tgz cilium
helm_url="https://get.helm.sh/helm-v3.21.4-linux-$arch.tar.gz"
fetch .tmp/downloads/helm.tgz "$helm_url";verify .tmp/downloads/helm.tgz "$helm_url.sha256sum"
tar -C .tmp/downloads -xzf .tmp/downloads/helm.tgz "linux-$arch/helm"
cp ".tmp/downloads/linux-$arch/helm" .tmp/bin/helm
echo "$PWD/.tmp/bin" >> "$GITHUB_PATH"
