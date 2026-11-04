set -u
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq protobuf-compiler libprotobuf-dev cmake >/dev/null 2>&1
git config --global --add safe.directory /src
echo "== HEAD $(git rev-parse --short HEAD): lib without inpod"
cargo test --lib -- --skip inpod:: > /tmp/rest.log 2>&1; echo "REST_EXIT=$?"; grep -E '^test result|^test .*FAILED' /tmp/rest.log
echo "== HEAD $(git rev-parse --short HEAD): inpod only"
cargo test --lib -- inpod:: > /tmp/inpod-new.log 2>&1; echo "INPOD_NEW_EXIT=$?"; grep -E '^test result' /tmp/inpod-new.log; grep -E '^test .*FAILED' /tmp/inpod-new.log | sort > /tmp/fail-new.txt; wc -l < /tmp/fail-new.txt
grep -m3 -E "panicked at" -A3 /tmp/inpod-new.log
git stash -q 2>/dev/null; git checkout -q 68c0282
echo "== HEAD $(git rev-parse --short HEAD): inpod only (baseline)"
cargo test --lib -- inpod:: > /tmp/inpod-old.log 2>&1; echo "INPOD_OLD_EXIT=$?"; grep -E '^test result' /tmp/inpod-old.log; grep -E '^test .*FAILED' /tmp/inpod-old.log | sort > /tmp/fail-old.txt; wc -l < /tmp/fail-old.txt
echo "== diff of failing sets (old vs new)"; diff /tmp/fail-old.txt /tmp/fail-new.txt && echo SAME_FAILURES
git checkout -q d5f24b5; git rev-parse --short HEAD
