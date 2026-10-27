#!/usr/bin/env bash
# Run renew_approval.py once a day on the administrator's host (LOCAL_ISSUER_PROFILE.md, Approval renewal):
# a launchd agent on macOS, a systemd user timer on Linux. A daily run with renew_approval.py's 7-day margin
# renews each approval about 22 days into its 29 and retries daily if a run fails.
#
# Usage: renewal-schedule.sh install --state-dir DIR --kubeconfig FILE --python PYTHON [--hour H]
#        renewal-schedule.sh uninstall | status
set -euo pipefail
export LC_ALL=C
NAME=cmtc-issuer-approval-renewal
LABEL=io.cmtc.issuer-approval-renewal
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$HERE/renew_approval.py
# kubectl, colima and docker, which the advance runs, are found on these paths on both systems.
JOB_PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin

usage() { sed -n '2,8p' "$0" >&2; exit 2; }
cmd=${1:-}; [ $# -gt 0 ] && shift
state_dir="" kubeconfig="" python="" hour=6
while [ $# -gt 0 ]; do
  case $1 in
    --state-dir) state_dir=$2; shift 2;;
    --kubeconfig) kubeconfig=$2; shift 2;;
    --python) python=$2; shift 2;;
    --hour) hour=$2; shift 2;;
    *) usage;;
  esac
done

case $(uname -s) in
  Darwin) kind=launchd unit=$HOME/Library/LaunchAgents/$LABEL.plist log=$HOME/Library/Logs/$NAME.log;;
  Linux) kind=systemd unit=$HOME/.config/systemd/user/$NAME;;
  *) echo "unsupported system $(uname -s)" >&2; exit 2;;
esac

install() {
  [ -n "$state_dir" ] && [ -n "$kubeconfig" ] && [ -n "$python" ] || usage
  case $hour in [0-9]|1[0-9]|2[0-3]) ;; *) echo "--hour must be 0-23" >&2; exit 2;; esac
  [ -f "$state_dir/ledger.json" ] || { echo "no ledger in $state_dir" >&2; exit 1; }
  "$python" -c 'import cryptography' || { echo "$python has no cryptography package" >&2; exit 1; }
  # A run now proves the job's command works before it is scheduled; it renews only when due.
  "$python" "$SCRIPT" --state-dir "$state_dir" --kubeconfig "$kubeconfig" --python "$python" --check
  if [ $kind = launchd ]; then
    mkdir -p "$(dirname "$unit")" "$(dirname "$log")"
    cat > "$unit" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$python</string><string>$SCRIPT</string>
    <string>--state-dir</string><string>$state_dir</string>
    <string>--kubeconfig</string><string>$kubeconfig</string>
    <string>--python</string><string>$python</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>$JOB_PATH</string></dict>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>15</integer></dict>
  <key>StandardOutPath</key><string>$log</string>
  <key>StandardErrorPath</key><string>$log</string>
</dict>
</plist>
EOF
    plutil -lint "$unit"
    launchctl bootout "gui/$(id -u)/$LABEL" 2> /dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$unit"
    echo "installed $unit; log $log"
  else
    mkdir -p "$(dirname "$unit")"
    cat > "$unit.service" <<EOF
[Unit]
Description=Renew the CMTC SPIRE intermediate issuer approval before it expires

[Service]
Type=oneshot
Environment=PATH=$JOB_PATH
ExecStart="$python" "$SCRIPT" --state-dir "$state_dir" --kubeconfig "$kubeconfig" --python "$python"
EOF
    cat > "$unit.timer" <<EOF
[Unit]
Description=Daily CMTC issuer approval renewal

[Timer]
OnCalendar=*-*-* $(printf %02d "$hour"):15:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "$NAME.timer"
    echo "installed $unit.service and $unit.timer; log: journalctl --user -u $NAME"
  fi
}

uninstall() {
  if [ $kind = launchd ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2> /dev/null || true
    rm -f "$unit"
  else
    systemctl --user disable --now "$NAME.timer" 2> /dev/null || true
    rm -f "$unit.service" "$unit.timer"
    systemctl --user daemon-reload
  fi
  echo "uninstalled"
}

status() {
  if [ $kind = launchd ]; then
    launchctl print "gui/$(id -u)/$LABEL" | grep -E 'state|last exit|path =|Hour|Minute' || { echo "not installed"; exit 1; }
    [ -f "$log" ] && tail -5 "$log"
  else
    systemctl --user list-timers "$NAME.timer" --no-pager
    journalctl --user -u "$NAME" -n 5 --no-pager || true
  fi
}

case $cmd in
  install) install;;
  uninstall) uninstall;;
  status) status;;
  *) usage;;
esac
