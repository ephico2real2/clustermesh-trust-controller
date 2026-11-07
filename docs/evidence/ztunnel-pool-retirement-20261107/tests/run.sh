# The checks of the pooled transport retirement, on the lab's Colima VM.
set -u
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq protobuf-compiler libprotobuf-dev cmake >/dev/null 2>&1
rustup component add clippy rustfmt >/dev/null 2>&1
echo "== fmt"; cargo fmt --all -- --check; echo "FMT_EXIT=$?"
echo "== new tests"; cargo test --lib -- certificate_deadline pooled_transport_takes 2>&1 | grep -E '^test |^test result|^error|panicked' | head -30; echo "NEW_EXIT=${PIPESTATUS[0]}"
echo "== clippy"; cargo clippy --lib --tests --benches --bins -- -D warnings 2>&1 | grep -E '^(warning|error)|Finished' | head -40; echo "CLIPPY_EXIT=${PIPESTATUS[0]}"
echo "== lib tests without inpod"; cargo test --lib -- --skip inpod:: 2>&1 | grep -E '^test result|FAILED|failed$|panicked' | head -40; echo "LIB_EXIT=${PIPESTATUS[0]}"
cp src/proxy/h2/client.rs /tmp/client.rs.orig
# Mutation 1: the deadline is not read at checkout -> the retirement test must fail.
python3 - <<'P'
p='src/proxy/h2/client.rs'; s=open(p).read()
o='if self.certificate_deadline.is_some_and(|deadline| {'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'if false && self.certificate_deadline.is_some_and(|deadline| {'))
P
echo "== mutation 1 (no retirement)"; cargo test --lib -- pooled_transport_takes 2>&1 | grep -E '^test |^test result'
cp /tmp/client.rs.orig src/proxy/h2/client.rs
# Mutation 2: retirement also without a lease -> the legacy test must fail.
python3 - <<'P'
p='src/proxy/h2/client.rs'; s=open(p).read()
o='        if let Some(lease) = &self.profile_lease {\n            let Ok(now) = lease.current_time() else {\n                return false;\n            };\n'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'        if self.certificate_deadline.is_some() { return false; }\n'+o))
P
echo "== mutation 2 (retire without a lease)"; cargo test --lib -- certificate_deadline_does_not_retire 2>&1 | grep -E '^test |^test result'
cp /tmp/client.rs.orig src/proxy/h2/client.rs
cp src/tls/profile_provider.rs /tmp/pp.rs.orig
# Mutation 3: the peer deadline is ignored -> the deadline test must fail.
python3 - <<'P'
p='src/tls/profile_provider.rs'; s=open(p).read()
o='self.local_deadline.min(peer.deadline())'
assert s.count(o)==1; open(p,'w').write(s.replace(o,'{ let _ = peer; self.local_deadline }'))
P
echo "== mutation 3 (no peer deadline)"; cargo test --lib -- certificate_deadline_is_the_first 2>&1 | grep -E '^test |^test result'
cp /tmp/pp.rs.orig src/tls/profile_provider.rs
echo DONE
