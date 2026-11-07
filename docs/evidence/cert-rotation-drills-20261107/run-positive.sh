#!/bin/bash
# Positive rotation drills on the deployed build; stops at the first drill whose verdicts fail.
set -u
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
W=$1; LOG=$2; OUT=docs/evidence/cert-rotation-drills-20261107
cd "$W" || exit 2
run() { # drill cluster extra-args...
  local d=$1 c=$2; shift 2
  echo "$(date -u +%FT%TZ) start $d $c" >> "$LOG"
  python3 scripts/evidence/rotation_drill.py drill "$d" --cluster "$c" --out "$OUT/$d-$c" --execute "$@" > "$OUT.$d-$c.out" 2>&1
  local rc=$?
  echo "$(date -u +%FT%TZ) end $d $c exit=$rc" >> "$LOG"
  [ $rc -eq 0 ] || { echo "STOP at $d $c" >> "$LOG"; exit 1; }
}
mkdir -p "$OUT"
run R6 cmtc-a --seconds 150 --lead 5
run R6 cmtc-b --seconds 150 --lead 5
run R1 cmtc-a --seconds 150 --lead 20
run R2 cmtc-a --seconds 150 --lead 20
run R4 cmtc-a --seconds 200 --lead 20
run R5 cmtc-b --seconds 300 --lead 20
run R5 cmtc-a --seconds 300 --lead 20
echo "$(date -u +%FT%TZ) ALL PASSED" >> "$LOG"
