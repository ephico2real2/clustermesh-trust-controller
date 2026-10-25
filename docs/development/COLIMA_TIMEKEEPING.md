# Colima guest clock: one owner for the lab VM

The two kind clusters (`cmtc-a`, `cmtc-b`) run in one Colima VM, so every kind
node shares that VM's wall clock. Until 2026-10-25 the clock was stepped
**backwards** about every 20 s. ztunnel treats a backward wall-clock step as a
possible rollback attack on its issuer profile and CRL floors, so each step
ended the node's xDS session and cancelled its workload TLS I/O.

[`scripts/lab/colima-timekeeping.sh`](../../scripts/lab/colima-timekeeping.sh)
fixes it, and [`scripts/lab/up.sh`](../../scripts/lab/up.sh) runs it before it
creates any cluster. Tracked in issue #24; the ztunnel-side tolerance is #25.

Environment where this was measured: macOS host, Colima 0.10.3, Lima 2.2.0,
profile `cmtc-cilium` (`vmType: vz`, 8 CPUs, 16 GiB), guest clocksource
`arch_sys_counter`.

## Cause: two clock owners

| Owner | What it does |
|---|---|
| Lima host agent | Every 10 s (`timeSyncInterval` in `pkg/hostagent/timesync.go`, fixed in Lima 2.2) it sends the host time to the guest agent. The guest agent (`pkg/guestagent/api/server/server.go`) computes `drift = guestNow - hostTime` and, when `abs(drift) > 100 ms`, calls `settimeofday(hostTime)`. The host timestamp is taken before the RPC, so each step lands slightly behind the host. |
| `systemd-timesyncd` in the guest | Disciplines the same clock against `ntp.ubuntu.com` through the VM's NAT. |

Guest state just before the fix (`docs/evidence/colima-timekeeping-20261025/before.txt`,
2026-10-25T18:51:58Z):

- `timedatectl timesync-status`: offset +108.540 ms, delay 130.772 ms,
  frequency **+500.000 ppm** (the kernel limit).
- `adjtimex`: `freq_ppm=500.000`, `status=0x2001` (PLL on), a pending phase
  offset of 32.6 ms still being slewed in.

The NTP client sees the guest as behind its server over a long, asymmetric
path and speeds the clock up at the maximum rate. Lima sees the same clock as
ahead of the host and steps it back. Neither converges.

## Evidence

From Lima's own log, `~/.colima/_lima/colima-cmtc-cilium/ha.stderr.log`
(`"guest clock adjusted"` entries, extracted to `lima-steps.tsv` in the evidence
folder; positive drift = guest ahead = stepped back):

- 856 steps from 2026-10-24T23:41:00Z to 2026-10-25T18:52:10Z. **All 856 were
  backward**, 100 to 142 ms.
- 31 steps in the 10 minutes before the fix, 100 to 130 ms each, median
  interval 20.0 s: the guest gained more than 100 ms every 20 s.

From the four ztunnel Pods' logs, counted at 19:14:42Z
(`docs/evidence/colima-timekeeping-20261025/ztunnel-clock-rejections-1914.txt`): 50 lines
matching `wall clock moved backwards|became unavailable` between the Pods'
start (17:40Z) and the fix, 0 after it.

## Fix: Lima is the only owner

Lima's sync is referenced to the host, which is the clock the operator, the
host tools and the other cluster's evidence use. The guest NTP client is
removed and its kernel discipline cleared:

```sh
bash scripts/lab/colima-timekeeping.sh --apply    # what up.sh runs
```

`--apply` does, in the guest:

1. `timedatectl set-ntp false` (only while NTP is still on: after the unit is
   masked, `timedatectl` reports `CanNTP=no` and `set-ntp` fails).
2. `systemctl disable --now` and `mask` for each of `systemd-timesyncd`,
   `chrony`, `chronyd`, `ntp` and `ntpd` that exists, so a reboot does not bring
   one back.
3. `adjtimex` reset: frequency 0, phase offset 0, status `STA_UNSYNC`. A stopped
   NTP client leaves its frequency correction in the kernel; without this reset
   the clock keeps gaining at +500 ppm.

It then runs the same checks as `--check`.

The script finds its target the way kind does:

- **On the macOS host** it uses `DOCKER_HOST`, else the active Docker context.
  An endpoint of `unix://$HOME/.colima/<profile>/docker.sock` selects that
  Colima profile, and the guest is reached with `colima -p <profile> ssh`. Any
  other endpoint (Docker Desktop, a Linux host) is reported and skipped with
  exit 0.
- **Inside a Lima guest** (`lima-guestagent` is active), it acts on the local
  clock. Lima's step log lives on the host, so the step-history check is only
  available from the host.

`--apply` is idempotent. A second run changes nothing and exits 0; this was
tested both from the host and inside the guest.

## Check

```sh
bash scripts/lab/colima-timekeeping.sh --check --window 60
```

Exit 0 requires:
- no active guest NTP client;
- kernel PLL off;
- at most one backward Lima step in the window.

One step can follow an apply: the step that removes the offset the NTP client
had built up. Right after `--apply`, only steps after the apply are counted.

To measure the offset from the host:

```sh
python3 scripts/lab/clock-offset-sample.py cmtc-a-worker 30 2 colima-cmtc-cilium
```

Each sample brackets the guest's `date +%s.%N` with two host reads. It prints
`guest - host midpoint` and the round trip. The error is up to half the round
trip, about 22 ms here.

## Verification

The fix was applied at 2026-10-25T18:52:00Z.

| Measure | Result | Source |
|---|---|---|
| Lima steps after the apply | One at 18:52:10Z (+104 ms), the expected residual step; none after it | `lima-steps.tsv` |
| Offset, 18:52:14Z to 18:55:12Z | 88 samples, 13.6 to 35.3 ms, median 18.55 ms, slope 0.029 ms/s | `offset-samples-after.tsv` |
| Offset, 19:11:29Z to 19:12:28Z | 30 samples, -4.8 to 4.7 ms, median -1.35 ms, slope -0.0033 ms/s | `offset-samples-1911.tsv` |
| Guest state | No NTP unit active, `freq_ppm=0.000`, `pll=off` | `--check` |
| ztunnel clock rejections after 18:52:15Z | 0 on all four Pods | `ztunnel-clock-rejections-1914.txt` |

All files are in [`docs/evidence/colima-timekeeping-20261025/`](../evidence/colima-timekeeping-20261025/). The two sample sets were
taken 19 minutes apart. Their slopes are well inside measurement noise, and the
guest now tracks the host to within the sampler's error.

The 60-minute acceptance window for #24 is open until `--check --window 60`
passes, from 19:52:10Z.

## Limits

- **Lima still owns the clock.** If the guest drifts more than 100 ms from the
  host, Lima steps it.
  - After host sleep the guest is *behind*, so that step is forward. ztunnel's
    floor accepts forward steps.
  - A backward step after this fix means a new clock source is fighting Lima.
    `--check` reports it.
- **ztunnel tolerance.** The ztunnel fork (`d2f38af`, #25) absorbs a backward
  step of at most 1 s, and at most 1 s spent behind the floor, without ending
  the session. A larger rollback still fails closed. That tolerance is defence
  in depth. It does not replace a single clock owner.
- **Upstream.** Two Lima behaviours are worth reporting:
  - the step target is a host timestamp taken before the RPC;
  - by default the guest image keeps its own NTP client next to Lima's sync.

  This repository's issue comes first; an upstream report is a later decision.
