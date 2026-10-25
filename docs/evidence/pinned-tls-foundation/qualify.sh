#!/usr/bin/env bash
set -euo pipefail
out=/private/tmp/cmtc-pinned-tls-20261024
src=/private/tmp/cmtc-ztunnel-upstream
trap 'status=$?; printf "%s\n" "$status" > "$out/qualify.exit"' EXIT
git -C "$src" diff --binary > "$out/tested-source.patch"
shasum -a 256 "$out/tested-source.patch" > "$out/tested-source.patch.sha256"
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 \
 --privileged --cpus 2 --memory 6g --security-opt label=disable \
 -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS=2 \
 -v "$src:$src" \
 -v /private/tmp/cmtc-ztunnel-enforcement/.git:/private/tmp/cmtc-ztunnel-enforcement/.git:ro \
 -v /private/tmp/cmtc-ztunnel-enforcement/out/rust:"$src/out/rust" \
 -v /private/tmp/cmtc-ztunnel-cargo-cache:/cargo -w "$src" \
 def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f sh -ec '
 git config --global --add safe.directory "$PWD"
 test "$(id -u)" = 0
 rustc --version
 command -v ip
 command -v iptables
 ip netns add cmtc-pinned-tls-suite
 ip netns del cmtc-pinned-tls-suite
 iptables -t mangle -S
 cargo fmt --all -- --check
 cargo test --locked --lib --tests --bins -- --include-ignored --test-threads=1
 TLS12_ENABLED=true cargo test --locked --lib tls::certificate::test::pinned_configs_recheck_live_crls_with_signed_empty_and_optional_blank_recovery -- --exact --include-ignored --nocapture --test-threads=1
 cargo clippy --locked --benches --tests --bins -- -D warnings
' > "$out/full.log" 2>&1
