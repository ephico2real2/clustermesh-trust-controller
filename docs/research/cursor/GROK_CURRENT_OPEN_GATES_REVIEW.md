# Current review of the two open Grok gates

**Reviewed source:** immutable Cilium `37d5fce0f78652cbe6721fedd9e02072daa0765b`. All line numbers below refer to `git show 37d5fce:<path>`, not Opus's dirty R6 files. Historical Grok reports remain unchanged.

**Scope:** read-only source and existing-log review. No source, compiler, Podman, API, permission, signer, image or live resource changes. Code in `../../evidence/grok-recommendation-review/proposals/` is **UNRUN proposal code**, not an accepted patch. Implementation stays with Opus 5.5 XHigh. Follow edit → cmtc-a/cmtc-b → traffic/failure/recovery → exact-image packaging. Preserve the current guard, root keys, Admin DAC=false, signer state and unrelated applications.

## Current verdict

1. **CT_RELATED is not a demonstrated TCP payload bypass.** In the real public conntrack lookup path, the packet protocol and extractor constrain that result to selected ICMP/ICMPv6 error traffic. Do not force a TCP CT_RELATED result in a test and call it a real reproduction.
2. **Permanent quarantine-map write failure remains an open enforcement gate.** Publication serialization, retry and retirement fix ordering/recovery defects. They do not supply a preinstalled kernel expiry or an independent barrier. An already released program can keep forwarding TCP/15008 if withdrawal writes and replacement-program installation keep failing.
3. **The failure limit must be honest.** A preinstalled five-second kernel lease can bound stale forwarding to at most five seconds after the last permitted mint/renewal. It does not guarantee immediate stop when withdrawal writes fail. If immediate stop is a hard requirement under arbitrary kernel-write failure, this lease is insufficient and that requirement remains open.

The last independently supplied live state has Cilium 37d and SPIRE delegated images ready on both clusters but no ztunnel DaemonSet. The 36 HTTP 200 results prove reachability, not workload mTLS.

## 1. CT_RELATED: the actual packet path

The four branches that check HBONE reply source port only for CT_REPLY are:

- `bpf/bpf_lxc.c:942-956`: IPv6 egress.
- `bpf/bpf_lxc.c:1502-1516`: IPv4 egress.
- `bpf/bpf_lxc.c:1852-1863`: IPv6 ingress policy.
- `bpf/bpf_lxc.c:2162-2173`: IPv4 ingress policy.

That condition alone does not show that an arbitrary TCP packet can arrive as CT_RELATED:

- `bpf/bpf_lxc.c:500-550` builds the IPv4 tuple from the packet's actual protocol and invokes public `ct_lookup4`; the corresponding IPv6 path is `:558-613` and invokes public `ct_lookup6` after extension-header parsing.
- `bpf/lib/conntrack.h:1006-1008` resets IPv4 tuple flags before parsing actual L4 headers. IPv6 does the same at `:734-736`. Thus a reused per-CPU tuple cannot carry an old RELATED bit into a TCP packet.
- `ct_extract_ports4` adds `TUPLE_F_RELATED` only under actual IPPROTO_ICMP error types: destination-unreachable, time-exceeded and parameter-problem (`:824-858`). Fragmented ICMP is rejected at `:836-837`. TCP/UDP/SCTP take the separate actual-port extraction branch at `:874-882` and never add RELATED.
- IPv6's corresponding extractor only adds RELATED for packet-too-big, destination-unreachable, time-exceeded and parameter-problem (`:576-607`). Fragmented ICMPv6 is rejected at `:585-586`. TCP follows its separate port extractor (`:624-635`).
- On a reverse map hit, `__ct_lookup4` selects CT_RELATED only if that extractor-set tuple bit is present (`:933-940`); otherwise it selects CT_REPLY. IPv6 mirrors this (`:683-690`).
- Conntrack-created related entries are explicitly keyed with IPPROTO_ICMP (`:1131-1140`) or IPPROTO_ICMPV6 (`:1070-1077`), zero ports and the RELATED bit. They are separate from the TCP tuple. A TCP packet cannot simply hit an ICMP related key.

**Supported conclusion:** selected related ICMP control packets can skip the TCP reply-port check. They are still ICMP packets when delivered. An embedded quoted TCP header inside an ICMP error is not a TCP stream delivered to the application's listening TCP port. This source audit establishes no application-TCP plaintext bypass through CT_RELATED.

**Limits:** this is a protocol-path source result, not a new kernel test or a general proof about every proxy, LB, fragment or metadata path. A helper-only test that fabricates `ret=CT_RELATED` for TCP would bypass the public lookup that supplies the relevant invariant.

### Explicit protocol contract and desired ICMP decision

The useful contract is **workload TCP payload must use authenticated HBONE**, with explicitly governed L3/L4 transport-control traffic. It is not “every L3 control packet is encrypted.” The current `ztunnel_admission.h:27-32` claim that there are no plaintext exceptions is too broad for the related-ICMP path.

Recommendation: retain essential related ICMP errors while defining and qualifying their scope. Do not add a blanket CT_RELATED drop before PMTU acceptance. ICMPv4 fragmentation-needed and ICMPv6 packet-too-big are needed to prevent HBONE MTU black holes. Echo and unrelated arbitrary ICMP must not acquire an implicit exception from this decision.

The current related CT key is primarily an address/protocol relation, not a proof that a quoted inner tuple describes the currently admitted HBONE connection. Do not describe it as cryptographic authorization or as exact quoted-flow validation. If the intended control-plane policy requires checking the quoted TCP/15008 flow, implement that as a separate explicit ICMP control policy. Test wrong quoted addresses/ports, malformed/truncated quotes, stale CT and MTU recovery before relying on it.

A documentation correction can state:

> A released Required endpoint permits workload TCP only through the HBONE transport path. Native conntrack can also permit related ICMP/ICMPv6 transport errors, including PMTU errors. Those control packets do not carry an application TCP stream. Their exact admission policy requires separate PMTU and negative tests. Quarantine still drops all packets at the entry gate.

This does not establish TLS authentication; the existing header correctly leaves that to ztunnel and mandatory capture.

### Complete proposed classification test

`../../evidence/grok-recommendation-review/proposals/ct_related_classification.c.txt` is a complete **UNRUN** BPF test object proposal. It uses actual packet generation, `ct_extract_ports4/6`, real CT maps and public `ct_lookup4/6`. It seeds a reverse lookup entry and deliberately leaves a stale RELATED input bit, then requires:

- IPv4 TCP/8080 → CT_REPLY, actual protocol TCP, RELATED cleared.
- IPv6 TCP/8080 → CT_REPLY, actual protocol TCP, RELATED cleared.
- IPv4 destination-unreachable → CT_RELATED, actual protocol ICMP.
- IPv6 packet-too-big → CT_RELATED, actual protocol ICMPv6.

It never stubs the lookup result. The seed deliberately controls a reverse CT hit; it is a classification fixture, not a TLS or full policy verdict test. Opus must adapt/compile it with the existing kernel-test runner and verify all four selected tests run.

The real entry-path acceptance extension must also exercise `cil_from_container`, `cil_to_container` and `cil_lxc_policy` using the real extractors. Required cases:

| Case | Required result |
|---|---|
| Previously established plaintext TCP reply, source port 8080/31337 | Dropped after HBONE-only activation; actual public lookup reports CT_REPLY |
| HBONE TCP reply, source port 15008 | Allowed only by remaining native policy and capture/authentication requirements |
| Legitimate related IPv4 fragmentation-needed / IPv6 packet-too-big | Control error delivered according to explicit PMTU policy; following HBONE traffic recovers at reduced MTU |
| Unrelated ICMP error, no matching related CT | No automatic related exception |
| Echo / fragmented / truncated error | Enforce explicit policy or reject malformed packet; never classify as application TCP |
| Malformed or wrong quoted inner tuple | No claim of flow validation unless the actual validator rejects it |
| Same packets while quarantined | Dropped by entry quarantine gate before CT classification |

Both IP families and ingress/egress are needed. Use real checksums/quoted packets (the existing Scapy fixture pattern in `bpf/tests/icmp_error_revnat.c` is suitable). Do not report four classifier tests as completion of this matrix.

## 2. Permanent map-write failure: what 37d actually has

`pkg/endpoint/ztunnel_datapath_admission.go:235-241` explicitly documents that an already released program can keep forwarding if all kernel writes fail. That remains accurate.

Current improvements are valuable:

- `:242-255` serializes withdrawal state and map publication, then starts recovery after releasing the publication mutex.
- `:261-289` writes the actual quarantine flag and acknowledges only a successful current interval.
- `:308-326` schedules bounded retry/backoff and a full-datapath regeneration.
- `:387-401` serializes both regeneration publication sites and their frontier recording.
- `:404-411` retires the endpoint's publication before deletion, so that object cannot rewrite its deleted entries.

But `bpf/lib/ztunnel_admission.h:105-136` reads only configured addresses, endpoint ownership and flags. There is no monotonic admission deadline, process liveness gate or independently installed deny barrier there. `struct endpoint_info` still has two unused pad words (`bpf/lib/eps.h:40-51`); its Go mirror has no expiry (`pkg/maps/lxcmap/lxcmap.go:198-210`). No retry interval supplies a kernel-enforced deadline. The eBPF program continues to observe the last successfully written released row until something changes it.

### Recommended preinstalled bounded lease

A small implementation option is to store a 64-bit absolute Linux monotonic expiry in `endpoint_info.pad[2]`. This preserves the existing 48-byte map-value layout; it still changes padding semantics and requires an explicit upgrade/restore qualification. Alternatively use a dedicated keyed map if ABI ownership is unsuitable. Do not add an unqualified compatibility fallback for absent deadlines on a Required endpoint.

**Kernel decision, on every packet and for every configured family:**

1. Keep the existing configured-address, own-lxc-ID and quarantine checks.
2. Collect the minimum valid admission deadline across all configured family rows.
3. If the computed mode is HBONE_ONLY but any required lease is zero, expired or implausibly beyond the maximum duration, return QUARANTINED.
4. Use `ktime_get_ns()` for comparison. Never use wall time or packet-driven timeout extension.

Complete UNRUN decision primitives are in `../../evidence/grok-recommendation-review/proposals/kernel_lease_primitives.h.txt`. In `ztunnel_own_mode`, collect `lease_live` alongside flags at the two existing own-row lookups, with one `now=ktime_get_ns()` snapshot. A missing family sets both `complete=false` and `lease_live=false`. Compute the existing mode, then return QUARANTINED whenever `mode == HBONE_ONLY && !lease_live`. Do not apply this requirement to ORDINARY host/platform endpoints.

**Minting and publication:**

- Add an atomic endpoint expiry. Mint only when the native owner supplies an exact verified release/renewal receipt with current source, trust, policy and incarnation evidence.
- Use CLOCK_MONOTONIC in the **same Linux kernel** as the BPF program; neither macOS time nor a different VM's uptime is valid. Complete Linux-clock/deadline primitives and deterministic Go boundary tests are provided in `../../evidence/grok-recommendation-review/proposals/kernel_lease_deadline.go.txt` and `_test.go`.
- Store expiry under the existing admission publication mutex. Clear it on withdrawal. Serialize renewal with withdrawal, policy drain and retirement.
- The cached frontend may export that already minted expiry; `lxcmap.getBPFValue` copies low 32 bits into Pad[0], high 32 bits into Pad[1]. It must not mint `now+TTL` when a generic map write or regeneration occurs. Otherwise stale regeneration becomes a lease renewal.
- The keeper must obtain fresh current admission evidence before renewing. A timer that blindly republishes a cached successful receipt would defeat the purpose during control-plane loss.
- Preserve the current guard until a real renewal owner and stale-source/policy invalidation exist. A first one-shot lease is safe but will deliberately stop forwarding after expiry; it is not a production availability solution.
- If a write fails, the old row retains its previously minted deadline. With max TTL=5 seconds, forwarding can continue for **up to the remaining five seconds from the last mint**. After expiry, the already installed BPF gate drops packets without another userspace write. A successful immediate quarantine write remains the fast path.

These files are **complete primitives, not a complete production patch**. The current admission/policy/source owner must be integrated by Opus; I have not invented a renewal authority or marked this gate implemented. No code was applied or tested.

### Deterministic negative and recovery qualification

Use the existing BPF test clock override pattern (`bpf/tests/conntrack_test.c:6-9`) instead of sleeps. Update current HBONE-positive fixtures to carry an explicit valid lease; a zero lease on a Required endpoint must fail closed.

1. Install a released program and live lease at fake time T. Show actual TCP/15008 packet forwarding under native allow policy.
2. Fail **all** withdrawal map updates and replacement-program installations after release. Keep the old successful row and program unchanged.
3. At T+TTL−1ns, record that the remaining lease can still permit forwarding. This is expected and must be labeled as the maximum stale window.
4. At T+TTL exactly, pass the same real packet through egress, ingress, local-delivery, existing/reply CT and any relevant fast entry. Require DROP_POLICY. No userspace map write or program reload may occur between these packet checks.
5. Advance time much further. Replay unrelated map writes/regeneration attempts; the deadline must not advance.
6. Resume valid proof and map writes, mint a new exact-incarnation lease, and prove positive traffic recovers. Old incarnation, policy version, source generation and saved old deadlines must not renew it.
7. Remove one family, change lxc ID, set deadline zero/far future, replace/delete endpoint, restart agent and disconnect source. Require quarantine. A previously minted lease survives only until its absolute expiry and cannot be restored as durable proof.
8. Repeat with both IP families and both clusters, then with exact images. Prove live proxy/credential/policy sessions obey the separate withdrawal/drain requirements.

`../../evidence/grok-recommendation-review/proposals/kernel_lease_decision_test.c.txt` provides complete UNRUN BPF boundary assertions for zero, before, equality, after, excessive future, unsigned-underflow inputs and padding encoding. These decision assertions support the matrix but do not replace actual BPF packet execution.

A five-second maximum is a concrete proposal, not a user-approved safety SLA or a measured value. Set the final bound from the stale-authorization requirement and measured owner/renewal latency. If the requirement is zero stale forwarding after an arbitrary failed syscall, keep that gate open; retries or a timer cannot honestly guarantee it.

## Existing evidence independently inspected

I parsed the existing `logs/cil-c3-1/bpf-*.log` records without executing any tests:

- Eight BPF objects, each recorded exit 0.
- 72 leaf PASS records: network_policy 12; skip_tunnel_from_lxc 12; tc_lxc_policy_drop 1; tc_policy_reject_response_test 3; ztunnel_mesh_admission 22; ztunnel_required_admission 7; ztunnel_required_single_stack 9; ztunnel_required_unconfigured 6.
- `stage-b.exit` is 0.

Those are existing C3 results. They do not include the new classification tests or a kernel lease, and they do not prove mTLS. The broader supplied Go record is 2853 passing/681 top-level/52 skipped, race and vet exit0; this review did not rerun or independently recount that broader record.

## Instructions for Opus

Keep a74's publication mutex, acknowledgement and retirement fixes. Do not reintroduce the old Grok watch/ACK snippets. Add real public conntrack-classification regressions and document the ICMP contract first. Preserve PMTU controls while qualifying their precise policy. Treat permanent-write failure as a still-open kernel-boundary story; use a preinstalled bounded lease or independently qualified barrier, with the stale window stated explicitly. Do not report source assertions, retries, ACKs, reachable applications or the new proposal files as Protected status.
