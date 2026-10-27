# Matrix after generation 6, superseded runner (2026-10-27, 11:07Z)

Run with `docs/evidence/issuer-rebootstrap-20261026/matrix/run_matrix.sh`, whose fixture runner does not record each
probe's client socket. [run.txt](run.txt) names the script blob.

- All 72 allowed curls returned HTTP 200 from the expected cluster ([probes](probes/)).
- [join.txt](join.txt): 48 proven over mTLS (Pod IP probes), 12 dropped by Cilium at `bpf_lxc.c:2381` (unregistered
  callers), 24 "failed". The 24 are the Global Service name probes: without the client socket, the join finds 5 or 6
  ztunnel connections from the client to the Service's backends inside each probe's 3-second window and cannot pick
  one. They are unjoined, not failed traffic.

The qualifying run is [matrix-g6](../matrix-g6/), with `scripts/evidence/run_mtls_matrix.sh`.
