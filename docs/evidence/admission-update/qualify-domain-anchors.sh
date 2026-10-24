#!/usr/bin/env bash
set -euo pipefail
out=/private/tmp/cmtc-rebuild-20261024
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --privileged --cpus 2 --memory 6g --security-opt label=disable -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS=2 -v /private/tmp/cmtc-ztunnel-upstream:/private/tmp/cmtc-ztunnel-upstream -v /private/tmp/cmtc-ztunnel-enforcement/.git:/private/tmp/cmtc-ztunnel-enforcement/.git:ro -v /private/tmp/cmtc-ztunnel-enforcement/out/rust:/private/tmp/cmtc-ztunnel-upstream/out/rust -v /private/tmp/cmtc-ztunnel-cargo-cache:/cargo -w /private/tmp/cmtc-ztunnel-upstream def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f sh -ec '
 test "$(id -u)" = 0
 command -v ip
 command -v iptables
 ip netns add cmtc-ztunnel-preflight
 ip netns del cmtc-ztunnel-preflight
 iptables -t mangle -S
 git config --global --add safe.directory "$PWD"
 rustc --version
 cargo test --locked --lib --tests --bins -- --include-ignored --test-threads=1
 cargo fmt --all -- --check
 cargo clippy --locked --benches --tests --bins -- -D warnings
' > "$out/domain-anchors-qualified.log" 2>&1
printf '0\n' > "$out/domain-anchors-qualified.exit"
