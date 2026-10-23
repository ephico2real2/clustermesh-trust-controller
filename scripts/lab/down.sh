#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ -f .tmp/created-clusters ]; then
  while IFS= read -r cluster; do
    case "$cluster" in cmtc-a|cmtc-b) kind delete cluster --name "$cluster";; *) echo "unexpected lab cluster $cluster" >&2;exit 1;; esac
  done < .tmp/created-clusters
  rm .tmp/created-clusters
fi
if [ -f .tmp/pki-directory ]; then
  python3 - <<'PY'
from pathlib import Path
import shutil
root=(Path.cwd()/'.tmp').resolve()
p=Path('.tmp/pki-directory').read_text().strip()
path=Path(p).resolve()
if path.parent!=root or not path.name.startswith('pki.'):raise SystemExit('refusing unexpected PKI directory')
shutil.rmtree(path,ignore_errors=True)
Path('.tmp/pki-directory').unlink()
PY
fi
