set -u
apt-get update -qq >/dev/null && apt-get install -y -qq protobuf-compiler libprotobuf-dev cmake >/dev/null
git config --global --add safe.directory /src
rustup component add clippy >/dev/null 2>&1
echo "== clippy"; cargo clippy --lib --tests --benches --bins -- -D warnings 2>&1 | grep -E '^(warning|error)|Finished' | head -40; echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
echo "== lib tests"; cargo test --lib 2>&1 | grep -E '^test result|FAILED|failed|panicked' | head -60; echo "LIB_EXIT=${PIPESTATUS[0]}"
# Mutation 1: no rescheduling after a clock jump -> test_refresh_follows_wall_clock_jump must fail.
cp src/identity/manager.rs /tmp/manager.rs.orig
python3 - <<'P'
p='src/identity/manager.rs'; s=open(p).read()
o='let _ = pending.set_priority(key, PendingPriority(Priority::Background, refresh_at));'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'let _ = refresh_at;'))
P
echo "== mutation 1 (no reschedule)"; cargo test --lib -- identity::manager::tests::test_refresh_follows_wall_clock_jump 2>&1 | grep -E '^test |test result'
cp /tmp/manager.rs.orig src/identity/manager.rs
# Mutation 2: expired cached certificates returned as before -> test_expired_certificate_is_not_returned must fail.
python3 - <<'P'
p='src/identity/manager.rs'; s=open(p).read()
o='} else if expired(&rx, self.worker.clock.now()) {'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'} else if false && expired(&rx, self.worker.clock.now()) {'))
P
echo "== mutation 2 (no expiry check)"; cargo test --lib -- identity::manager::tests::test_expired_certificate_is_not_returned 2>&1 | grep -E '^test |test result'
cp /tmp/manager.rs.orig src/identity/manager.rs
git diff --stat; echo DONE
