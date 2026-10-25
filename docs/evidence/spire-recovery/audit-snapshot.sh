set -eu
set -o pipefail
cd /data
b=.cmtc-preupgrade-28f6b8d84a
if [ ! -f keys.json ] || [ -L keys.json ] || [ ! -s keys.json ]; then exit 31; fi
if [ ! -d "$b" ] || [ -L "$b" ] || [ ! -f "$b/state.tar" ] || [ -L "$b/state.tar" ] || [ ! -f "$b/COMPLETE" ]; then exit 32; fi
[ "$(stat -c %a "$b")" = 700 ]
[ "$(stat -c %a "$b/state.tar")" = 600 ]
entries=$(tar -tf "$b/state.tar")
count=0;keys=0;db=0
for name in $entries; do
 case "$name" in keys.json) keys=$((keys+1));; datastore.sqlite3) db=$((db+1));; datastore.sqlite3-wal|datastore.sqlite3-shm|datastore.sqlite3-journal) :;; *) exit 33;; esac
 count=$((count+1))
 if [ ! -f "$b/verify/$name" ] || [ -L "$b/verify/$name" ]; then exit 34; fi
 tar -xOf "$b/state.tar" "$name" | cmp -s - "$b/verify/$name"
done
[ "$keys" = 1 ] && [ "$db" = 1 ] && [ "$count" -ge 2 ] && [ "$count" -le 5 ]
tar -tvf "$b/state.tar" | awk '{if(substr($0,1,1)!="-")exit 1}'
printf '{"snapshotAuditPassed":true,"allArchiveEntriesRegular":true,"privateArchiveMode":"0600","privateKeyExported":false}\n'
