#!/usr/bin/env bash
# Copies the rule files and dashboards into the chart: Helm reads files inside the chart directory only.
# observability/v2/rules/ and observability/v2/dashboards/ stay the files that are edited; deploy/chart/files/ is a
# copy, and tests/test_deploy.py fails when the two differ.
#
# Usage: deploy/sync-files.sh           copy
#        deploy/sync-files.sh --check   compare only; exit 1 and name each file that differs
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

check=false
if [[ "${1:-}" == "--check" ]]; then
  check=true
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

# source directory, chart directory, file pattern
pairs=(
  "rules rules *.rules.yaml"
  "rules/proposed rules/proposed *.rules.yaml"
  "dashboards/grafana dashboards/grafana *.json"
  "dashboards/perses dashboards/perses *.json"
)

status=0
for pair in "${pairs[@]}"; do
  read -r source target pattern <<<"${pair}"
  destination="deploy/chart/files/${target}"
  ${check} || mkdir -p "${destination}"
  for file in "${source}"/${pattern}; do
    [[ -e "${file}" ]] || continue
    copy="${destination}/$(basename "${file}")"
    if ${check}; then
      if ! cmp -s "${file}" "${copy}"; then
        echo "differs: ${file} ${copy}"
        status=1
      fi
    else
      cp "${file}" "${copy}"
    fi
  done
  # A copy whose source was removed must go too.
  for copy in "${destination}"/${pattern}; do
    [[ -e "${copy}" ]] || continue
    if [[ ! -e "${source}/$(basename "${copy}")" ]]; then
      if ${check}; then
        echo "no source: ${copy}"
        status=1
      else
        rm -- "${copy}"
      fi
    fi
  done
done
exit "${status}"
