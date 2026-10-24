#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
lock=${CILIUM_IMAGE_LOCK:-config/cilium-images.lock.json}
mkdir -p .tmp artifacts
sha=$(python3 scripts/cilium/prepare.py "$lock" .tmp/cilium-image-values.json)
chart_source=${CILIUM_SOURCE_DIR:-$PWD/.tmp/cilium-source-$sha}
if [ ! -d "$chart_source/.git" ] && [ ! -f "$chart_source/.git" ]; then
  if [ -n "${CILIUM_SOURCE_DIR:-}" ]; then echo 'CILIUM_SOURCE_DIR must be a Git checkout' >&2; exit 1; fi
  git init -q "$chart_source"
  git -C "$chart_source" remote add origin https://github.com/ephico2real2/cilium.git
  git -C "$chart_source" sparse-checkout set install/kubernetes/cilium
  git -C "$chart_source" fetch --no-tags --depth=1 --filter=blob:none origin "$sha"
  git -C "$chart_source" checkout --detach FETCH_HEAD
fi
[ "$(git -C "$chart_source" rev-parse HEAD)" = "$sha" ] || { echo 'Chart checkout and image source differ' >&2; exit 1; }
[ -z "$(git -C "$chart_source" status --porcelain --untracked-files=all -- install/kubernetes/cilium)" ] || { echo 'Chart has local modifications' >&2; exit 1; }
test -f "$chart_source/install/kubernetes/cilium/Chart.yaml"
printf '%s\n' "$chart_source/install/kubernetes/cilium" > .tmp/cilium-chart-path
cp "$lock" artifacts/cilium-images.lock.json
cp .tmp/cilium-image-values.json artifacts/cilium-image-values.json
printf '%s\n' "$sha" > artifacts/cilium-source-commit.txt
