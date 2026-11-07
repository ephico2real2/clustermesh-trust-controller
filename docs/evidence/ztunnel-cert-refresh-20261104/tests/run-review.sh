# The checks of the review commit (start_fetch_key decides on the value it marks seen), on the lab's Colima VM:
#   tar -C <ztunnel checkout> -cf - src/identity/manager.rs |
#     docker --context colima-cmtc-cilium run -i --rm -v zt-clockfix-src:/src rust:1.90.0 tar -C /src -xf -
#   docker --context colima-cmtc-cilium run --rm --memory 6g --memory-swap 6g --cpus 3 -e CARGO_BUILD_JOBS=2 \
#     -e CARGO_TARGET_DIR=/target -v zt-clockfix-src:/src -v zt-clockfix-cargo:/usr/local/cargo/registry \
#     -v zt-clockfix-target:/target -v <this directory>:/run -w /src rust:1.90.0 bash /run/run-review.sh
set -u
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq protobuf-compiler libprotobuf-dev cmake >/dev/null 2>&1
git config --global --add safe.directory /src
rustup component add clippy rustfmt >/dev/null 2>&1
git diff --stat
echo "== fmt"; cargo fmt --all -- --check; echo "FMT_EXIT=$?"
echo "== clippy"; cargo clippy --lib --tests --benches --bins -- -D warnings 2>&1 | grep -E '^(warning|error)|Finished' | head -40; echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
echo "== identity and time tests"; cargo test --lib -- identity:: time:: 2>&1 | grep -E '^test result|FAILED|panicked' | head -20; echo "IDENTITY_EXIT=${PIPESTATUS[0]}"
echo "== lib tests without inpod"; cargo test --lib -- --skip inpod:: 2>&1 | grep -E '^test result|FAILED|panicked' | head -40; echo "LIB_EXIT=${PIPESTATUS[0]}"
cp src/identity/manager.rs /tmp/manager.rs.orig
# Mutation 1: no rescheduling after a clock jump -> test_refresh_follows_wall_clock_jump must fail.
python3 - <<'P'
p='src/identity/manager.rs'; s=open(p).read()
o='let _ = pending.set_priority(key, PendingPriority(Priority::Background, refresh_at));'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'let _ = refresh_at;'))
P
echo "== mutation 1 (no reschedule)"; cargo test --lib -- identity::manager::tests::test_refresh_follows_wall_clock_jump 2>&1 | grep -E '^test |test result'
cp /tmp/manager.rs.orig src/identity/manager.rs
# Mutation 2: an expired cached certificate is returned, as at 68c0282 -> test_expired_certificate_is_not_returned must fail.
python3 - <<'P'
p='src/identity/manager.rs'; s=open(p).read()
o='                if is_expired {'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'                if false && is_expired {'))
P
echo "== mutation 2 (no expiry check)"; cargo test --lib -- identity::manager::tests::test_expired_certificate_is_not_returned 2>&1 | grep -E '^test |test result'
cp /tmp/manager.rs.orig src/identity/manager.rs
git diff --stat; echo DONE
