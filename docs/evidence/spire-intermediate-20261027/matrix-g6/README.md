# Matrix after generation 6 and the SPIRE rotation (2026-10-27, 11:12–11:14Z)

Run with `scripts/evidence/run_mtls_matrix.sh` at `e8d6830` ([run.txt](run.txt) names the script blob), after
approval generation 6 and the SPIRE CA rotation onto `<cluster>-spire-intermediate`
([LOCAL_ISSUER_PROFILE.md, Rollout](../../../../LOCAL_ISSUER_PROFILE.md#rollout-2026-10-27)). Node clocks were
45–79 ms behind the host ([window.txt](window.txt)).

[join.txt](join.txt): 132 probes, joined to 96 ztunnel connections.

- 95 of 96 allowed probes are proven over mTLS: each probe's client socket has one ztunnel outbound line, with the
  client's and the server's SPIFFE identities, to the expected Pod. This includes every scope: same node, cross node,
  cross cluster, Global Service, and per-Pod name.
- 36 of 36 unregistered probes are dropped by Cilium at `bpf_lxc.c:2381`.
- 1 is reported "failed": cmtc-a, `client-control-plane` to `server-control-plane…:31337`, at 11:12:27.738Z. The curl
  returned HTTP 200 from the expected Pod. The join found no ztunnel line from the socket curl reported.

## The one unjoined probe

curl reported the same client socket, `10.10.0.2:55836`, for two probes 115 ms apart: `:80`, then `:31337`
([the name probe record](probes/cmtc-a-20261027T111227025139Z-probe-name-allow.json)). ztunnel logged the first at
`55836` and the second at `46727` ([ztunnel log](ztunnel-access/cmtc-a-control-plane.log), 11:12:27.603767Z and
11:12:27.716425Z node time).

The client Pod's outbound capture is a NAT rule (read from the Pod's network namespace at 11:20Z):
`-A CILIUM_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15001`. After the
redirect, both connections have the same tuple at ztunnel's listener, `10.10.0.2:55836 → :15001`, and the first is
still tracked. The kernel then gives the second a new source port. This is consistent with what was measured; the
conntrack entry was not captured.

The probe is joined by destination and time instead: in its window there is exactly one outbound line from
`client-control-plane` to `10.10.0.98:31337`, `src.addr=10.10.0.2:46727`, `src.identity=…/sa/mesh-client`,
`dst.identity=…/sa/rebel-base`. It is listed apart from the 95 because the socket join is the stronger proof.

Earlier, superseded run with the old runner: [matrix-g6-superseded-runner](../matrix-g6-superseded-runner/).
