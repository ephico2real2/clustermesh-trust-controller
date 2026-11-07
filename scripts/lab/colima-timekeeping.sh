#!/usr/bin/env bash
# Give a Colima (Lima) guest a single wall-clock owner.
#
# Lima's host agent steps the guest clock to the host's time whenever they
# differ by more than 100 ms (every 10 s, not configurable in Lima 2.2). A guest
# NTP client disciplining the same clock against another reference makes the
# two fight: the guest drifts ahead and Lima steps it back about every 20 s.
# Workload TLS treats a backward wall-clock step as rollback, so a step can close admission.
# Leaving the host-referenced Lima agent as the only owner removes the fight.
#
# Usage: colima-timekeeping.sh [--check|--apply] [--profile NAME] [--window MINUTES]
#   --check  (default) report the guest's timekeeping; exit 1 if it is unsafe.
#   --apply  disable guest NTP clients and clear their kernel discipline, then check
#            (counting only Lima steps after the apply, since earlier ones predate the fix).
set -euo pipefail

mode=check
window=10
profile=${COLIMA_PROFILE:-}
while [ $# -gt 0 ]; do
  case "$1" in
    --check) mode=check ;;
    --apply) mode=apply ;;
    --profile) profile=$2; shift ;;
    --window) window=$2; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# Inside a Lima guest (the lab scripts also run there over `colima ssh`) the
# clock is local, but Lima's step log stays on the host. On the host, the kind
# runtime is the Docker endpoint in use: DOCKER_HOST, else the active context;
# a Colima endpoint is ~/.colima/<profile>/docker.sock.
lima_dir=""
if systemctl is-active --quiet lima-guestagent 2>/dev/null; then
  profile=${profile:-$(hostname)}
  guest() { "$@"; }
else
  if [ -z "$profile" ]; then
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)}
    case "$endpoint" in
      unix://"$HOME"/.colima/*/docker.sock)
        profile=${endpoint#unix://"$HOME"/.colima/}
        profile=${profile%/docker.sock} ;;
      *) echo "Docker endpoint '$endpoint' is not a Colima VM; nothing to do."; exit 0 ;;
    esac
  fi
  lima_dir="$HOME/.colima/_lima/colima-$profile"
  [ "$profile" = default ] && lima_dir="$HOME/.colima/_lima/colima"
  guest() { colima -p "$profile" ssh -- "$@"; }
fi

# adjtimex(2) through ctypes: modes=0 only reads; "reset" zeroes the frequency
# correction and pending PLL offset that a stopped NTP client leaves behind.
timex_py=$(cat <<'PY'
import ctypes, ctypes.util, sys
class timeval(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]
class timex(ctypes.Structure):
    _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long), ("maxerror", ctypes.c_long),
                ("esterror", ctypes.c_long), ("status", ctypes.c_int), ("constant", ctypes.c_long), ("precision", ctypes.c_long),
                ("tolerance", ctypes.c_long), ("time", timeval), ("tick", ctypes.c_long), ("ppsfreq", ctypes.c_long),
                ("jitter", ctypes.c_long), ("shift", ctypes.c_int), ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long),
                ("calcnt", ctypes.c_long), ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
                ("pad", ctypes.c_int * 11)]
ADJ_OFFSET, ADJ_FREQUENCY, ADJ_STATUS, STA_PLL, STA_UNSYNC = 0x0001, 0x0002, 0x0010, 0x0001, 0x0040
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
t = timex()
if sys.argv[1] == "reset":
    t.modes, t.offset, t.freq, t.status = ADJ_OFFSET | ADJ_FREQUENCY | ADJ_STATUS, 0, 0, STA_UNSYNC
    if libc.adjtimex(ctypes.byref(t)) < 0:
        raise OSError(ctypes.get_errno(), "adjtimex reset")
    t = timex()
libc.adjtimex(ctypes.byref(t))
print(f"freq_ppm={t.freq / 65536.0:.3f} pll={'on' if t.status & STA_PLL else 'off'}")
PY
)

ntp_units="systemd-timesyncd chrony chronyd ntp ntpd"

since=0
if [ "$mode" = apply ]; then
  since=$(date -u +%s)
  echo "Disabling guest NTP clients in Colima profile $profile"
  # set-ntp fails once the client is masked (CanNTP=no), so a rerun only acts while NTP is on.
  [ "$(guest timedatectl show -p NTP --value)" = no ] || guest sudo timedatectl set-ntp false
  for unit in $ntp_units; do
    if guest systemctl cat "$unit" >/dev/null 2>&1; then
      guest sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
      guest sudo systemctl mask --quiet "$unit"
    fi
  done
  printf '%s\n' "$timex_py" | guest sudo python3 - reset
fi

unsafe=0
active=""
for unit in $ntp_units; do
  [ "$(guest systemctl is-active "$unit" 2>/dev/null || true)" = active ] && active="$active $unit"
done
discipline=$(printf '%s\n' "$timex_py" | guest python3 - read)
echo "profile=$profile active_guest_ntp=[${active# }] kernel: $discipline"
[ -n "$active" ] && { echo "UNSAFE: guest NTP client competes with Lima's host time sync"; unsafe=1; }
case "$discipline" in *"pll=on"*) echo "UNSAFE: kernel PLL discipline is active"; unsafe=1 ;; esac

# Lima's own log records each step; positive drift means the guest was ahead
# and was stepped backwards.
if [ -z "$lima_dir" ]; then
  echo "Lima's step log is on the macOS host; run --check there for the step history."
  [ "$unsafe" -eq 0 ] && echo "Timekeeping OK in the guest: no competing clock owner." || exit 1
  exit 0
fi
python3 - "$lima_dir/ha.stderr.log" "$window" "$since" <<'PY' || unsafe=1
import datetime, json, sys
log, minutes, applied = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
since = max(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes),
            datetime.datetime.fromtimestamp(applied, datetime.timezone.utc))
steps = []
with open(log) as f:
    for line in f:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("msg", "")
        if "guest clock adjusted" in message:
            at = datetime.datetime.fromisoformat(entry["time"]).astimezone(datetime.timezone.utc)
            if at >= since:
                steps.append((at, int(message.split("was ")[1].split("ms")[0])))
backward = [s for s in steps if s[1] > 0]
print(f"lima_steps_last_{minutes}m={len(steps)} backward={len(backward)}")
for at, drift in steps[-5:]:
    print(f"  {at:%Y-%m-%dT%H:%M:%SZ} drift={drift}ms")
sys.exit(1 if len(backward) > 1 else 0)
PY
[ "$unsafe" -eq 0 ] && echo "Timekeeping OK: Lima's host-referenced sync is the only owner." || exit 1
