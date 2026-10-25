set -eu
umask 077
cd /data
if [ ! -f keys.json ] || [ -L keys.json ] || [ ! -s keys.json ]; then exit 31; fi
if [ ! -f datastore.sqlite3 ] || [ -L datastore.sqlite3 ] || [ ! -s datastore.sqlite3 ]; then exit 32; fi
backup=.cmtc-preupgrade-28f6b8d84a
if [ -e "$backup" ] || [ -L "$backup" ]; then exit 33; fi
mkdir -m 700 "$backup"
set -- keys.json datastore.sqlite3
for name in datastore.sqlite3-wal datastore.sqlite3-shm datastore.sqlite3-journal; do
 if [ -e "$name" ] || [ -L "$name" ]; then
  if [ ! -f "$name" ] || [ -L "$name" ]; then exit 34; fi
  set -- "$@" "$name"
 fi
done
tar -cf "$backup/state.tar" "$@"
chmod 600 "$backup/state.tar"
mkdir -m 700 "$backup/verify"
tar -xf "$backup/state.tar" -C "$backup/verify"
for name in "$@"; do cmp -s "$name" "$backup/verify/$name"; done
# Keep both the archive and the checked copy on this existing PVC.
# Never emit or move a private key outside it.
printf 'complete\n' > "$backup/COMPLETE"
sync
printf '{"snapshotComplete":true,"archive":".cmtc-preupgrade-28f6b8d84a/state.tar","keysExported":false}\n'
