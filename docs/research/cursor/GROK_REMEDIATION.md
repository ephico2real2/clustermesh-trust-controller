# Grok remediation proposal

Retained 2026-10-25. Status: **UNRUN proposal**, delivered in full to Opus5.5 XHigh for adaptation, reproduction and local qualification. Source baseline: Cilium dbd2d32bd935b8b271141667e41546c904e74e8a. This report does not establish a live bypass or a completed fix. Its kernel-write-failure interval remains an explicit acceptance gap. Follow current delivery status for implementation results.

The report below includes complete proposed code and tests. Opus must use the current interfaces, preserve the existing node-binding fix and independently validate races/lifecycle behavior.

---

The node-watch fix in `dbd2d32` stays as it is. I’ll read that binder and the two BPF paths, then write apply-ready patches and tests for the zero-address gap and the failed quarantine-map write.The node-watch fix in the current workspace stays. The two patches below are for the zero-address BPF hole and the failed `cilium_lxc` quarantine write. Nothing here was compiled or run. `git show` is blocked in this session, so the line numbers are from the workspace files that already contain the staged UID binder (`native_node_name.go` lines 164–216, `sendAddressResponse` lines 649–684). Do not replace that binder with the old address-only patch.

## Node-watch race

`dbd2` already does the required sequence. `bindNodeNames` clones the retained Pod-UID map, applies removals and this batch, verifies that whole set, and stores it in `pendingNodeNames` with the watch from that same read. `sendAddressResponse` calls `checkNodeNamesBeforeSend` and calls `commitNodeNames` only after `SendMsg` returns. `TestNativeNodeNameLaterBatchRejectsAnEarlierNodeChange`, `TestNativeNodeNameChangeBeforeSendWithholdsResponse`, `TestNativeNodeNameRemovalRetiresExactPodUID`, and `TestNativeNodeNameFailedSendDoesNotCommit` are the locks. This review did not re-run them.

Two residuals, neither is a replacement patch:

- A node-table write that lands after `checkNodeNamesBeforeSend` and before `SendMsg` returns can still publish one delta. The watch from that verify then fires and `revalidateNodeNames` closes the stream. This is one in-flight response, not a watch replaced by an unrelated batch.
- A `REMOVED` event whose Pod UID is empty does not retire an address (`bind` lines 116–120). A removal that carries a UID does. The following create on a renamed address fails closed through `verify`.

## A. All-zero addresses

`ztunnel_own_mode` (`bpf/lib/ztunnel_admission.h` lines 102–131) starts `complete` at true and clears it only when a compiled address is non-zero and the `cilium_lxc` row is missing or owned by another `lxc_id`. With `endpoint_ipv4.be32 == 0` and `endpoint_ipv6.d1 == d2 == 0`, both lookups are skipped. `ztunnel_mode_decide(true, false, true, 0)` returns `ZTUNNEL_MODE_HBONE_ONLY`. `cil_from_container` (line 1751), `cil_lxc_policy` (line 2472), and `cil_to_container` (line 2597) drop only `ZTUNNEL_MODE_QUARANTINED`, so TCP/15008 is then accepted by `ztunnel_hbone_*_verdict`.

`Endpoint` (`pkg/datapath/config/endpoint.go` lines 16–21) leaves the config zero when `IsValid()` is false, and copies `0.0.0.0` / `::` when `IsValid()` is true because those unspecified addresses are valid. `cfg.ZtunnelRequired` is set from `IsZtunnelMeshOnly()` (lines 59–61) with no address check. `ztunnel_required_01` does not cover this: it assigns `v4_pod_one` and `v6_pod_one`, then deletes the map rows. The lookup runs and misses.

Ordinary programs stay ordinary. `ztunnel_mode_decide` consults `complete` only when `ztunnel_required` is true. One configured family with an owned row stays complete; the other family’s zero address is not a configured family. A non-zero family with a missing or foreign row still clears `complete`.

Reachability of a live exploit is not demonstrated. The agent image on cmtc-a is the older dev overlay, ztunnel is off, and no packet was sent. The code path is real on the next regeneration of a released Required endpoint whose compiled addresses are both zero. Programs already loaded keep the old collector until that regeneration. `ReleaseZtunnelQuarantine` today will also clear the load-time quarantine bit with no address check (`ztunnel_datapath_admission.go` lines 112–115).

### Production patch

`bpf/lib/ztunnel_admission.h`, replace `ztunnel_own_mode` and the input comment that says a missing entry is quarantined:

```c
 *   - load-time ztunnel_required (sticky): the program never runs ORDINARY.
 *     QUARANTINED when no family address is configured, or a configured
 *     family has no cilium_lxc row owned by this program's endpoint ID.
 *     A zero address is not a configured family. One owned family is enough
 *     for a single-stack endpoint;
```

```c
static __always_inline enum ztunnel_mode ztunnel_own_mode(void)
{
	const struct endpoint_info *ep __maybe_unused;
	bool complete = true;
	bool configured = false;
	__u32 flags = 0;

#ifdef ENABLE_IPV4
	if (CONFIG(endpoint_ipv4).be32) {
		configured = true;
		ep = __lookup_ip4_endpoint(CONFIG(endpoint_ipv4).be32);
		if (ep && ep->lxc_id == LXC_ID)
			flags |= ep->flags;
		else
			complete = false;
	}
#endif
#ifdef ENABLE_IPV6
	{
		union v6addr own = CONFIG(endpoint_ipv6);

		if (own.d1 || own.d2) {
			configured = true;
			ep = __lookup_ip6_endpoint(&own);
			if (ep && ep->lxc_id == LXC_ID)
				flags |= ep->flags;
			else
				complete = false;
		}
	}
#endif
	if (!configured)
		complete = false;
	return ztunnel_mode_decide(CONFIG(ztunnel_required), CONFIG(ztunnel_quarantined),
				   complete, flags);
}
```

`pkg/datapath/config/endpoint.go`, replace the two address copies:

```go
	if addr := ep.IPv4Address(); addr.IsValid() && !addr.IsUnspecified() {
		cfg.EndpointIPv4.Addr = addr.As4()
	}
	if addr := ep.IPv6Address(); addr.IsValid() && !addr.IsUnspecified() {
		cfg.EndpointIPv6.Addr = addr.As16()
	}
```

`pkg/endpoint/ztunnel_datapath_admission.go`, add `"net/netip"` and refuse release when both families are zero. Insert this immediately after the `ErrZtunnelNotRequired` check inside `verifyZtunnelReceiptLocked`:

```go
func ztunnelAddressConfigured(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified()
}
```

```go
	if !ztunnelAddressConfigured(e.IPv4) && !ztunnelAddressConfigured(e.IPv6) {
		return fmt.Errorf("%w: Required release has no non-zero endpoint address", ErrZtunnelAdmissionMismatch)
	}
```

`0.0.0.0` and `::` are the same bits as an omitted config, so a Go assertion on the config struct does not fail before this BPF change. The release check does fail before the change: `ReleaseZtunnelQuarantine` currently returns nil for an unspecified address.

Add this test to `pkg/datapath/config/endpoint_ztunnel_test.go`. Change `IPv4Address` and `IPv6Address` to return new fields so the existing cases stay zero:

```go
type testZtunnelConfigEndpoint struct {
	endpointtypes.Config
	options     *option.IntOptions
	required    bool
	quarantined bool
	v4, v6      netip.Addr
}

func (e testZtunnelConfigEndpoint) IPv4Address() netip.Addr { return e.v4 }
func (e testZtunnelConfigEndpoint) IPv6Address() netip.Addr { return e.v6 }
```

```go
func TestEndpointConfigOmitsUnspecifiedAddresses(t *testing.T) {
	lib := option.GetEndpointMutableOptionLibrary()
	ep := testZtunnelConfigEndpoint{
		options: option.NewIntOptions(&lib), required: true,
		v4: netip.IPv4Unspecified(), v6: netip.IPv6Unspecified(),
	}
	cfg := Endpoint(ep, &Config{}).(*BPFLXC)
	require.Equal(t, [4]uint8{}, cfg.EndpointIPv4.Addr)
	require.Equal(t, [16]uint8{}, cfg.EndpointIPv6.Addr)
	require.True(t, cfg.ZtunnelRequired)
	require.False(t, cfg.ZtunnelQuarantined, "release is a separate bit; the BPF collector must quarantine a zero-address Required program")

	ep.v4 = netip.MustParseAddr("10.1.0.10")
	cfg = Endpoint(ep, &Config{}).(*BPFLXC)
	require.Equal(t, ep.v4.As4(), cfg.EndpointIPv4.Addr)
	require.Equal(t, [16]uint8{}, cfg.EndpointIPv6.Addr)
}
```

Add this test to `pkg/endpoint/ztunnel_datapath_admission_test.go` (add `"net/netip"`):

```go
func TestZtunnelReleaseRejectsZeroAddressesThenAcceptsOneFamily(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.IPv4 = netip.IPv4Unspecified()
	ep.IPv6 = netip.IPv6Unspecified()
	err := ep.ReleaseZtunnelQuarantine(receipt)
	require.ErrorIs(t, err, ErrZtunnelAdmissionMismatch)
	require.True(t, ep.IsZtunnelQuarantined())
	require.Nil(t, ep.ztunnelAdmission.Load())

	ep.IPv4 = netip.MustParseAddr("10.1.0.10")
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	require.False(t, ep.IsZtunnelQuarantined())
	require.True(t, ep.IsZtunnelMeshOnly())
}
```

Before the release check, the first `ReleaseZtunnelQuarantine` returns nil. After it, the error is `ErrZtunnelAdmissionMismatch` and the second call returns nil.

Keep `bpf/tests/ztunnel_required_admission.c` cases 01–07. They are the dual-stack non-zero negatives: missing rows, foreign endpoint id 78, IPv6 row absent, and one-family quarantine. Case 04 is the dual-stack recovery (`CTX_ACT_REDIRECT` for TCP/15008). Those `ASSIGN_CONFIG` values cannot change inside one object file.

### BPF program test, both addresses zero

New file `bpf/tests/ztunnel_required_zero_address.c`. Include order matches `ztunnel_required_admission.c`: context and pktgen, `ENABLE_*`, MACs, `lib/bpf_lxc.h` (which includes `bpf_lxc.c` and the tail-call fixture in `bpf/tests/lib/bpf_lxc.h`), then `ASSIGN_CONFIG`, then the map helpers. Both families are enabled so both zero checks exist. `ztunnel_quarantined` is explicitly false. No `cilium_lxc` insert.

```c
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Required program, both families compiled, both endpoint addresses zero,
 * load-time quarantine false, no cilium_lxc rows. ztunnel_own_mode must be
 * QUARANTINED. TCP/15008 must drop at cil_from_container, cil_lxc_policy and
 * cil_to_container. This file cannot also compile a non-zero recovery: that
 * is ztunnel_required_v4_only.c and ztunnel_required_admission.c case 04.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 1

#define POD_IP		v4_pod_one
#define PEER_IP		v4_pod_two
#define PEER_NODE	v4_node_two
#define PEER_IDENTITY	1230
#define OWN_EPID	77

#define APP_PORT	__bpf_htons(8080)
#define HBONE_PORT	__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = 0 })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .d1 = 0, .d2 = 0 })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)
ASSIGN_CONFIG(bool, ztunnel_required, true)
ASSIGN_CONFIG(bool, ztunnel_quarantined, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

static __always_inline void prepare(void)
{
	endpoint_v4_del_entry(POD_IP);
	ipcache_v4_add_entry(PEER_IP, 0, PEER_IDENTITY, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
}

static __always_inline int
build_v4(struct __ctx_buff *ctx, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, bool from_pod)
{
	__u8 *smac = from_pod ? (__u8 *)pod_mac : (__u8 *)peer_mac;
	__u8 *dmac = from_pod ? (__u8 *)peer_mac : (__u8 *)pod_mac;
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	l4 = pktgen__push_ipv4_tcp_packet(&builder, smac, dmac, saddr, daddr, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
build_v6(struct __ctx_buff *ctx, __be16 sport, __be16 dport)
{
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	l4 = pktgen__push_ipv6_tcp_packet(&builder, (__u8 *)pod_mac, (__u8 *)peer_mac,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int status_of(const struct __ctx_buff *ctx, __u32 *status)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return -1;
	*status = *(__u32 *)data;
	return 0;
}

static __always_inline __u64 policy_drops(__u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

CHECK("tc", "ztunnel_zero_00_mode_quarantined")
int ztunnel_zero_00_mode(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();
	prepare();
	assert(ztunnel_own_mode() == ZTUNNEL_MODE_QUARANTINED);
	test_finish();
}

PKTGEN("tc", "ztunnel_zero_01_egress_v4_15008")
int pktgen_zero_01(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43001), HBONE_PORT, true);
}
SETUP("tc", "ztunnel_zero_01_egress_v4_15008")
int setup_zero_01(struct __ctx_buff *ctx)
{
	prepare();
	return pod_send_packet(ctx);
}
CHECK("tc", "ztunnel_zero_01_egress_v4_15008")
int check_zero_01(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}

PKTGEN("tc", "ztunnel_zero_02_egress_v4_8080")
int pktgen_zero_02(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43002), APP_PORT, true);
}
SETUP("tc", "ztunnel_zero_02_egress_v4_8080")
int setup_zero_02(struct __ctx_buff *ctx)
{
	prepare();
	return pod_send_packet(ctx);
}
CHECK("tc", "ztunnel_zero_02_egress_v4_8080")
int check_zero_02(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}

PKTGEN("tc", "ztunnel_zero_03_egress_v6_15008")
int pktgen_zero_03(struct __ctx_buff *ctx)
{
	return build_v6(ctx, __bpf_htons(43003), HBONE_PORT);
}
SETUP("tc", "ztunnel_zero_03_egress_v6_15008")
int setup_zero_03(struct __ctx_buff *ctx)
{
	prepare();
	return pod_send_packet(ctx);
}
CHECK("tc", "ztunnel_zero_03_egress_v6_15008")
int check_zero_03(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}

PKTGEN("tc", "ztunnel_zero_04_ingress_tailcall_15008")
int pktgen_zero_04(struct __ctx_buff *ctx)
{
	return build_v4(ctx, PEER_IP, POD_IP, __bpf_htons(43004), HBONE_PORT, false);
}
SETUP("tc", "ztunnel_zero_04_ingress_tailcall_15008")
int setup_zero_04(struct __ctx_buff *ctx)
{
	prepare();
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
CHECK("tc", "ztunnel_zero_04_ingress_tailcall_15008")
int check_zero_04(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 1);
	test_finish();
}

PKTGEN("tc", "ztunnel_zero_05_ingress_to_container_15008")
int pktgen_zero_05(struct __ctx_buff *ctx)
{
	return build_v4(ctx, PEER_IP, POD_IP, __bpf_htons(43005), HBONE_PORT, false);
}
SETUP("tc", "ztunnel_zero_05_ingress_to_container_15008")
int setup_zero_05(struct __ctx_buff *ctx)
{
	prepare();
	return pod_receive_packet(ctx);
}
CHECK("tc", "ztunnel_zero_05_ingress_to_container_15008")
int check_zero_05(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 1);
	test_finish();
}
```

Before the collector change, check 00 gets `ZTUNNEL_MODE_HBONE_ONLY`. Check 01 is the packet proof: the current collector takes the same egress path as `ztunnel_required_04` and `ztunnel_04`, which redirect TCP/15008 under `TUNNEL_MODE`. Opus must record that pre-fix status. If check 01 is already `CTX_ACT_DROP` for a reason other than `DROP_POLICY`, the mode assertion is still the collector failure and the packet assertion does not prove this hole. After the change, all five packet checks are `CTX_ACT_DROP` with one `DROP_POLICY`, and check 00 is `ZTUNNEL_MODE_QUARANTINED`.

`v6_pod_two` is the existing pktgen symbol next to `v6_pod_one` (`bpf/tests/pktgen.h`). If that object file does not define it, use the same pattern as `v6_pod_one[]`: a `volatile const __u8` array initialized from `v6_pod_two_addr`. Do not invent a 99-byte payload; `default_data` is the harness payload.

### Single-stack recovery and negatives

New file `bpf/tests/ztunnel_required_v4_only.c`. IPv4 only, same shape as `ztunnel_mesh_admission.c`, so `cil_lxc_policy` calls `tail_ipv4_ct_ingress_policy_only` directly instead of the dual-stack `tail_call_internal`. `endpoint_ipv4` is `v4_pod_one`. There is no IPv6 config, so a missing IPv6 row is not partial. Partial-family coverage stays in `ztunnel_required_03`.

```c
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Single-stack Required program. A missing or foreign IPv4 row is
 * QUARANTINED. An owned IPv4 row with no quarantine flag is HBONE_ONLY:
 * TCP/15008 is forwarded and TCP/8080 and TCP/31337 are dropped.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 1

#define POD_IP		v4_pod_one
#define PEER_IP		v4_pod_two
#define PEER_NODE	v4_node_two
#define PEER_IDENTITY	1230
#define OWN_EPID	77
#define FOREIGN_EPID	78

#define APP_PORT	__bpf_htons(8080)
#define HBONE_PORT	__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)
ASSIGN_CONFIG(bool, ztunnel_required, true)
ASSIGN_CONFIG(bool, ztunnel_quarantined, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

enum v4_rows { V4_NONE, V4_FOREIGN, V4_OWN };

static __always_inline void prepare(enum v4_rows rows)
{
	__u16 id = rows == V4_FOREIGN ? FOREIGN_EPID : OWN_EPID;

	endpoint_v4_del_entry(POD_IP);
	if (rows != V4_NONE)
		endpoint_v4_add_entry(POD_IP, 0, id, 0, 0, 0, (__u8 *)pod_mac, NULL);
	ipcache_v4_add_entry(PEER_IP, 0, PEER_IDENTITY, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
}

static __always_inline int
build_v4(struct __ctx_buff *ctx, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, bool from_pod)
{
	__u8 *smac = from_pod ? (__u8 *)pod_mac : (__u8 *)peer_mac;
	__u8 *dmac = from_pod ? (__u8 *)peer_mac : (__u8 *)pod_mac;
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	l4 = pktgen__push_ipv4_tcp_packet(&builder, smac, dmac, saddr, daddr, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int status_of(const struct __ctx_buff *ctx, __u32 *status)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return -1;
	*status = *(__u32 *)data;
	return 0;
}

static __always_inline __u64 policy_drops(__u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

#define ZT_CAT2(a, b) a##b
#define ZT_CAT(a, b) ZT_CAT2(a, b)

#define EXPECT_DROP(name, dir)							\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status == CTX_ACT_DROP);						\
	assert(policy_drops(dir) == 1);						\
	test_finish();								\
}

PKTGEN("tc", "ztunnel_v4_01_missing_15008")
int pktgen_v4_01(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43101), HBONE_PORT, true);
}
SETUP("tc", "ztunnel_v4_01_missing_15008")
int setup_v4_01(struct __ctx_buff *ctx)
{
	prepare(V4_NONE);
	return pod_send_packet(ctx);
}
EXPECT_DROP("ztunnel_v4_01_missing_15008", METRIC_EGRESS)

PKTGEN("tc", "ztunnel_v4_02_foreign_15008")
int pktgen_v4_02(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43102), HBONE_PORT, true);
}
SETUP("tc", "ztunnel_v4_02_foreign_15008")
int setup_v4_02(struct __ctx_buff *ctx)
{
	prepare(V4_FOREIGN);
	return pod_send_packet(ctx);
}
EXPECT_DROP("ztunnel_v4_02_foreign_15008", METRIC_EGRESS)

PKTGEN("tc", "ztunnel_v4_03_owned_15008")
int pktgen_v4_03(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43103), HBONE_PORT, true);
}
SETUP("tc", "ztunnel_v4_03_owned_15008")
int setup_v4_03(struct __ctx_buff *ctx)
{
	prepare(V4_OWN);
	return pod_send_packet(ctx);
}
CHECK("tc", "ztunnel_v4_03_owned_15008")
int check_v4_03(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_REDIRECT);
	assert(policy_drops(METRIC_EGRESS) == 0);
	test_finish();
}

PKTGEN("tc", "ztunnel_v4_04_owned_8080")
int pktgen_v4_04(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43104), APP_PORT, true);
}
SETUP("tc", "ztunnel_v4_04_owned_8080")
int setup_v4_04(struct __ctx_buff *ctx)
{
	prepare(V4_OWN);
	return pod_send_packet(ctx);
}
EXPECT_DROP("ztunnel_v4_04_owned_8080", METRIC_EGRESS)

PKTGEN("tc", "ztunnel_v4_05_owned_31337")
int pktgen_v4_05(struct __ctx_buff *ctx)
{
	return build_v4(ctx, POD_IP, PEER_IP, __bpf_htons(43105), __bpf_htons(31337), true);
}
SETUP("tc", "ztunnel_v4_05_owned_31337")
int setup_v4_05(struct __ctx_buff *ctx)
{
	prepare(V4_OWN);
	return pod_send_packet(ctx);
}
EXPECT_DROP("ztunnel_v4_05_owned_31337", METRIC_EGRESS)

PKTGEN("tc", "ztunnel_v4_06_owned_ingress_15008")
int pktgen_v4_06(struct __ctx_buff *ctx)
{
	return build_v4(ctx, PEER_IP, POD_IP, __bpf_htons(43106), HBONE_PORT, false);
}
SETUP("tc", "ztunnel_v4_06_owned_ingress_15008")
int setup_v4_06(struct __ctx_buff *ctx)
{
	prepare(V4_OWN);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
CHECK("tc", "ztunnel_v4_06_owned_ingress_15008")
int check_v4_06(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status != CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 0);
	test_finish();
}

PKTGEN("tc", "ztunnel_v4_07_missing_ingress_15008")
int pktgen_v4_07(struct __ctx_buff *ctx)
{
	return build_v4(ctx, PEER_IP, POD_IP, __bpf_htons(43107), HBONE_PORT, false);
}
SETUP("tc", "ztunnel_v4_07_missing_ingress_15008")
int setup_v4_07(struct __ctx_buff *ctx)
{
	prepare(V4_NONE);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT_DROP("ztunnel_v4_07_missing_ingress_15008", METRIC_INGRESS)
```

`bpf/tests/Makefile` already builds every `bpf/tests/*.c`. No makefile edit.

Commands, from the Cilium tree, after the patch:

```text
make run_bpf_tests BPF_TEST=ztunnel_required_zero_address
make run_bpf_tests BPF_TEST=ztunnel_required_v4_only
make run_bpf_tests BPF_TEST=ztunnel_required_admission
make run_bpf_tests BPF_TEST=ztunnel_mesh_admission
go test -count=1 -timeout 180s ./pkg/endpoint/ -run 'TestZtunnelReleaseRejectsZeroAddressesThenAcceptsOneFamily|TestZtunnelReleaseRequiresExactNativeReceipt'
go test -count=1 -timeout 120s ./pkg/datapath/config/ -run 'TestEndpointConfig'
```

Run the zero-address BPF test once on the unpatched collector and keep that log. Check 00 must fail there. Then run it again after the patch.

## B. Failed quarantine map write

`WithdrawZtunnelAdmission` (`ztunnel_datapath_admission.go` lines 199–205) stores a nil receipt, then `Swap(true)` returns on a repeat and never reaches `WriteEndpoint`. `rewriteZtunnelDatapathFlags` (lines 210–223) writes the cached frontend once. `epInfoCache.IsZtunnelQuarantined` (cache.go lines 263–265) ORs the cached flag with the live atomic, and `lxcmap.getBPFValue` (lxcmap.go lines 182–187) sets `EndpointFlagZtunnelQuarantined` (16) and, for a Required endpoint, `EndpointFlagZtunnelMeshOnly` (32). On error the function logs and returns. The loaded program still has `ztunnel_quarantined=false` from the release regeneration, and the map still has the released flags. `ztunnel_mode_decide` reads those, not the Go atomic. `TestZtunnelIncarnationChangeQuarantinesUnderLockAndMapFailureStaysClosed` only asserts `IsZtunnelQuarantined()`.

`SetZtunnelMembership` holds `e.mutex` and calls `ObserveZtunnelRequired`, which calls `WithdrawZtunnelAdmission` (ztunnel_membership.go lines 32–61). The withdraw path must not call `lockAlive` or `SetRegenerateStateIfAlive` on that stack. A retry sleep on that stack would also stall the caller. Three immediate `WriteEndpoint` attempts, then a goroutine, is the lock-safe shape. The goroutine runs `SetRegenerateStateIfAlive` after the caller can unlock. If it blocks on `e.mutex`, it is waiting for that unlock, not for a second copy of the same lock.

`Regenerate` is the real enqueue (`policy.go` lines 940–964) into `e.eventQueue`. `EndpointRegenerationEvent.Handle` then calls `e.epBuildQueue.QueueEndpointBuild` (`events.go` lines 66–78). The admission unit endpoint has neither a running queue nor `epBuildQueue`. Calling `Regenerate` there blocks or panics. The production function calls it. The unit test installs `ztunnelQuarantineRegenHook` and returns before that call. The hook is nil outside tests.

There is no second kernel object the loaded program reads. `local_delivery` (`bpf/lib/local_delivery.h` lines 149–150) and `ztunnel_own_mode` both use the `cilium_lxc` flags or the load-time config. `DeleteElement` is the same map. A new persistent map would be a new ABI and would not be read by the program already attached. Immediate packet blocking therefore exists only when a `WriteEndpoint` of the quarantine flag succeeds. If all three writes fail, TCP/15008 continues on the released program until a later regeneration loads `ztunnel_quarantined=true`. That immediate-fail-closed gate stays open. Regeneration is recovery of the load-time bit, not a lease over the current program. Quarantine is not sticky across a later verified release: `ReleaseZtunnelQuarantine` still clears the atomic and the map acknowledgement, and `ZtunnelReleaseRegeneration` still requests `RegenerateWithDatapath`.

Owner check: `recordZtunnelLxcFrontend` publishes a generation. `invalidateZtunnelLxcOwner` bumps it. A write proceeds only when the generation still matches, and the acknowledgement is stored only if it still matches after the write. A mismatch does not write the cached IP keys. One write already inside the kernel can still land; that syscall is not rolled back. The next withdraw does not acknowledge it and queues regeneration.

### Production patch

`pkg/endpoint/endpoint.go`, after `ztunnelLxcFrontend`:

```go
	// ztunnelQuarantineMapAck is true only after cilium_lxc accepted the
	// quarantine flag for this quarantine interval. Release clears it.
	// A failed write leaves it false so a repeated withdraw retries.
	ztunnelQuarantineMapAck atomic.Bool
	// ztunnelLxcOwnerGen changes when a new map image is recorded or the
	// sandbox identity is invalidated. ztunnelLxcOwnerSeen is the generation
	// of the image Withdraw may rewrite.
	ztunnelLxcOwnerGen  atomic.Uint64
	ztunnelLxcOwnerSeen atomic.Uint64
	ztunnelLxcOwner     atomic.Pointer[ztunnelLxcOwner]
	// ztunnelQuarantineRegenFlight is one regeneration goroutine.
	// ztunnelQuarantineRegenDone counts completed goroutines.
	ztunnelQuarantineRegenFlight atomic.Bool
	ztunnelQuarantineRegenDone   atomic.Uint64
```

Same file, add the type next to the other ztunnel types, or in `ztunnel_datapath_admission.go`:

```go
type ztunnelLxcOwner struct {
	podUID      string
	endpointID  uint64
	netNSCookie uint64
}
```

`pkg/endpoint/events.go`, in `Start`, immediately after `e.ID = id`:

```go
	e.invalidateZtunnelLxcOwner()
```

`pkg/endpoint/restore.go`, at the end of `fromSerializedEndpoint`:

```go
	ep.invalidateZtunnelLxcOwner()
```

`pkg/endpoint/ztunnel_datapath_admission.go` replacements. Add imports `"context"` and `"net/netip"`. Keep the existing imports.

```go
const ztunnelQuarantineMapAttempts = 3

var (
	errZtunnelLxcOwnerStale     = errors.New("ztunnel cilium_lxc owner changed before quarantine write")
	errZtunnelLxcWriteExhausted = errors.New("ztunnel cilium_lxc quarantine write failed")
)

// ztunnelQuarantineRegenHook, when non-nil, receives the regeneration metadata
// after SetRegenerateStateIfAlive and skips Endpoint.Regenerate. Production
// leaves it nil. The admission unit endpoint has no running event queue and
// no epBuildQueue, so Handle cannot run there.
var ztunnelQuarantineRegenHook func(*Endpoint, *regeneration.ExternalRegenerationMetadata)
```

In `ReleaseZtunnelQuarantine`, after `e.ztunnelDatapathQuarantined.Store(false)`:

```go
		e.ztunnelQuarantineMapAck.Store(false)
```

Replace `WithdrawZtunnelAdmission`, `rewriteZtunnelDatapathFlags`, and `recordZtunnelLxcFrontend` with:

```go
func (e *Endpoint) invalidateZtunnelLxcOwner() {
	e.ztunnelLxcOwnerGen.Add(1)
}

func (e *Endpoint) recordZtunnelLxcFrontend(f lxcmap.EndpointFrontend) {
	e.ztunnelLxcFrontend.Store(&f)
	owner := &ztunnelLxcOwner{endpointID: f.GetID()}
	if cache, ok := f.(*epInfoCache); ok && cache != nil {
		owner.podUID = cache.k8sPodUID
		owner.endpointID = cache.id
		owner.netNSCookie = cache.netNsCookie
	}
	e.ztunnelLxcOwner.Store(owner)
	e.ztunnelLxcOwnerSeen.Store(e.ztunnelLxcOwnerGen.Add(1))
}

func (e *Endpoint) WithdrawZtunnelAdmission(reason string) {
	e.ztunnelAdmission.Store(nil)
	already := e.ztunnelDatapathQuarantined.Swap(true)
	if already && e.ztunnelQuarantineMapAck.Load() {
		return
	}
	e.rewriteZtunnelDatapathFlags(reason)
}

func (e *Endpoint) rewriteZtunnelDatapathFlags(reason string) {
	logger := e.getLogger()
	var cause error
	for attempt := 1; attempt <= ztunnelQuarantineMapAttempts; attempt++ {
		if !e.ztunnelDatapathQuarantined.Load() || e.ztunnelAdmission.Load() != nil {
			if logger != nil {
				logger.Info("Stopped ztunnel quarantine map write because release won",
					logfields.Event, "ztunnel-datapath-admission",
					logZtunnelStage, "quarantine-withdraw",
					logfields.Reason, reason,
					logfields.Attempt, attempt)
			}
			return
		}
		frontend := e.ztunnelLxcFrontend.Load()
		seen := e.ztunnelLxcOwnerSeen.Load()
		if frontend == nil || *frontend == nil || e.lxcMap == nil {
			return
		}
		if seen == 0 || seen != e.ztunnelLxcOwnerGen.Load() {
			e.armZtunnelQuarantineRegen(reason, errZtunnelLxcOwnerStale)
			return
		}
		err := e.lxcMap.WriteEndpoint(*frontend)
		if err != nil {
			cause = err
			if logger != nil {
				logger.Warn("Failed to write ztunnel quarantine to endpoint map",
					logfields.Event, "ztunnel-datapath-admission",
					logZtunnelStage, "quarantine-withdraw",
					logfields.Reason, reason,
					logfields.Attempt, attempt,
					logfields.Error, err)
			}
			continue
		}
		if !e.ztunnelDatapathQuarantined.Load() || e.ztunnelAdmission.Load() != nil ||
			e.ztunnelLxcOwnerGen.Load() != seen {
			if e.ztunnelDatapathQuarantined.Load() && e.ztunnelAdmission.Load() == nil {
				e.armZtunnelQuarantineRegen(reason, errZtunnelLxcOwnerStale)
			}
			return
		}
		e.ztunnelQuarantineMapAck.Store(true)
		if logger != nil {
			logger.Info("Quarantined ztunnel endpoint",
				logfields.Event, "ztunnel-datapath-admission",
				logZtunnelStage, "quarantine-withdraw",
				logfields.Reason, reason,
				logfields.Attempt, attempt,
				logfields.EndpointID, e.GetID())
		}
		return
	}
	e.ztunnelQuarantineMapAck.Store(false)
	if cause == nil {
		cause = errZtunnelLxcWriteExhausted
	}
	e.armZtunnelQuarantineRegen(reason, cause)
}

func ztunnelQuarantineRegeneration(reason string, parent context.Context, cause error) *regeneration.ExternalRegenerationMetadata {
	message := "ztunnel cilium_lxc quarantine write failed"
	if cause != nil {
		message = message + ": " + cause.Error()
	}
	if parent == nil {
		parent = context.Background()
	}
	return &regeneration.ExternalRegenerationMetadata{
		Reason:            regeneration.ReasonEndpointUpdate,
		Message:           message + " (" + reason + ")",
		RegenerationLevel: regeneration.RegenerateWithDatapath,
		ParentContext:     parent,
	}
}

func (e *Endpoint) armZtunnelQuarantineRegen(reason string, cause error) {
	if !e.ztunnelQuarantineRegenFlight.CompareAndSwap(false, true) {
		return
	}
	go e.runZtunnelQuarantineRegen(reason, cause)
}

func (e *Endpoint) runZtunnelQuarantineRegen(reason string, cause error) {
	defer func() {
		e.ztunnelQuarantineRegenFlight.Store(false)
		e.ztunnelQuarantineRegenDone.Add(1)
	}()
	logger := e.getLogger()
	if e.aliveCtx != nil {
		select {
		case <-e.aliveCtx.Done():
			if logger != nil {
				logger.Info("Skipped ztunnel quarantine regeneration after endpoint cancellation",
					logfields.Event, "ztunnel-datapath-admission",
					logZtunnelStage, "quarantine-withdraw",
					logfields.Reason, reason,
					logfields.Error, e.aliveCtx.Err())
			}
			return
		default:
		}
	}
	if e.ztunnelQuarantineMapAck.Load() || !e.ztunnelDatapathQuarantined.Load() {
		return
	}
	if logger != nil {
		logger.Error("Queueing ztunnel quarantine datapath regeneration",
			logfields.Event, "ztunnel-datapath-admission",
			logZtunnelStage, "quarantine-withdraw",
			logfields.Reason, reason,
			logfields.Error, cause,
			logfields.EndpointID, e.GetID())
	}
	parent := e.aliveCtx
	if parent == nil {
		parent = context.Background()
	}
	meta := ztunnelQuarantineRegeneration(reason, parent, cause)
	regen, err := e.SetRegenerateStateIfAlive(meta)
	if err != nil {
		if logger != nil {
			logger.Warn("Endpoint closed before ztunnel quarantine regeneration",
				logfields.Event, "ztunnel-datapath-admission",
				logZtunnelStage, "quarantine-withdraw",
				logfields.Reason, reason,
				logfields.Error, err)
		}
		return
	}
	if !regen {
		if logger != nil {
			logger.Info("Ztunnel quarantine regeneration joined an existing datapath build",
				logfields.Event, "ztunnel-datapath-admission",
				logZtunnelStage, "quarantine-withdraw",
				logfields.Reason, reason)
		}
		return
	}
	if ztunnelQuarantineRegenHook != nil {
		ztunnelQuarantineRegenHook(e, meta)
		return
	}
	if e.eventQueue == nil {
		if logger != nil {
			logger.Error("Cannot enqueue ztunnel quarantine regeneration without an endpoint event queue",
				logfields.Event, "ztunnel-datapath-admission",
				logZtunnelStage, "quarantine-withdraw",
				logfields.Reason, reason,
				logfields.Error, cause)
		}
		return
	}
	<-e.Regenerate(meta)
}
```

`GetID` reads `e.ID` without the endpoint lock (`endpoint.go` lines 784–786). That matches the existing helper. The owner gate does not read `e.K8sUID`, `e.ID`, or `e.NetNsCookie` during the write; it uses the atomic generation captured in `recordZtunnelLxcFrontend`.

Replace `recordingLxcMap` in `pkg/endpoint/ztunnel_datapath_admission_test.go`. The committed flags are the bits `getBPFValue` would set. This is still a Go double, not a kernel map. `bpf/tests/ztunnel_mesh_admission.c` case `ztunnel_18` is the packet proof that those bits drop an established TCP/15008 flow.

```go
type recordingLxcMap struct {
	lxcmap.Map
	attempts      int
	fail          error
	failRemaining int
	committed     []uint32
}

func (m *recordingLxcMap) WriteEndpoint(f lxcmap.EndpointFrontend) error {
	m.attempts++
	if m.fail != nil {
		return m.fail
	}
	if m.failRemaining > 0 {
		m.failRemaining--
		return errors.New("injected cilium_lxc write failure")
	}
	var flags uint32
	if q, ok := f.(interface{ IsZtunnelQuarantined() bool }); ok && q.IsZtunnelQuarantined() {
		flags |= lxcmap.EndpointFlagZtunnelQuarantined
	}
	if mo, ok := f.(interface{ IsZtunnelMeshOnly() bool }); ok && mo.IsZtunnelMeshOnly() {
		flags |= lxcmap.EndpointFlagZtunnelMeshOnly
	}
	m.committed = append(m.committed, flags)
	return nil
}
```

Update the two existing assertions that read `recorder.writes`:

```go
	require.Equal(t, []uint32{lxcmap.EndpointFlagZtunnelQuarantined | lxcmap.EndpointFlagZtunnelMeshOnly}, recorder.committed)
```

```go
	require.Len(t, recorder.committed, 1)
```

Replace the map-failure half of `TestZtunnelIncarnationChangeQuarantinesUnderLockAndMapFailureStaysClosed` with the tests below, or leave that half only if it sets the hook. A permanent `fail` now reaches the goroutine.

Add imports `"sync/atomic"`, `"time"`, and `"github.com/cilium/cilium/pkg/endpoint/regeneration"`.

```go
func withQuarantineRegenHook(t *testing.T, hook func(*Endpoint, *regeneration.ExternalRegenerationMetadata)) {
	t.Helper()
	previous := ztunnelQuarantineRegenHook
	ztunnelQuarantineRegenHook = hook
	t.Cleanup(func() { ztunnelQuarantineRegenHook = previous })
}

func waitQuarantineRegen(t *testing.T, ep *Endpoint, doneBefore uint64) {
	t.Helper()
	require.Eventually(t, func() bool {
		return ep.ztunnelQuarantineRegenDone.Load() > doneBefore
	}, time.Second, 5*time.Millisecond)
}

func TestZtunnelQuarantineMapWriteRetriesThenStoresKernelFlags(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	recorder := &recordingLxcMap{failRemaining: 2}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.recordZtunnelLxcFrontend(ep.createEpInfoCache("", ""))
	ep.mutex.Unlock()

	var hooked atomic.Bool
	withQuarantineRegenHook(t, func(*Endpoint, *regeneration.ExternalRegenerationMetadata) {
		hooked.Store(true)
	})
	done := ep.ztunnelQuarantineRegenDone.Load()
	ep.WithdrawZtunnelAdmission("transient map failure")

	require.Equal(t, ztunnelQuarantineMapAttempts, recorder.attempts)
	require.Equal(t, []uint32{lxcmap.EndpointFlagZtunnelQuarantined | lxcmap.EndpointFlagZtunnelMeshOnly}, recorder.committed)
	require.True(t, ep.ztunnelQuarantineMapAck.Load())
	require.True(t, ep.IsZtunnelQuarantined())
	require.False(t, hooked.Load())
	require.Equal(t, done, ep.ztunnelQuarantineRegenDone.Load())

	ep.WithdrawZtunnelAdmission("repeat after acknowledged write")
	require.Equal(t, ztunnelQuarantineMapAttempts, recorder.attempts)
	require.Len(t, recorder.committed, 1)
}

func TestZtunnelQuarantineMapWriteExhaustionQueuesDatapathRegen(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.aliveCtx = t.Context()
	recorder := &recordingLxcMap{fail: errors.New("map write failed")}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.recordZtunnelLxcFrontend(ep.createEpInfoCache("", ""))
	ep.mutex.Unlock()

	got := make(chan *regeneration.ExternalRegenerationMetadata, 1)
	withQuarantineRegenHook(t, func(gotEP *Endpoint, meta *regeneration.ExternalRegenerationMetadata) {
		require.Equal(t, ep, gotEP)
		got <- meta
	})
	ep.WithdrawZtunnelAdmission("permanent map failure")
	select {
	case meta := <-got:
		require.Equal(t, regeneration.RegenerateWithDatapath, meta.RegenerationLevel)
		require.Equal(t, regeneration.ReasonEndpointUpdate, meta.Reason)
		require.Contains(t, meta.Message, "map write failed")
	case <-time.After(time.Second):
		t.Fatal("datapath regeneration was not queued")
	}
	require.Equal(t, StateWaitingToRegenerate, ep.GetState())
	require.Equal(t, ztunnelQuarantineMapAttempts, recorder.attempts)
	require.Empty(t, recorder.committed, "a failed WriteEndpoint must not record released flags as quarantined")
	require.False(t, ep.ztunnelQuarantineMapAck.Load())
	require.True(t, ep.IsZtunnelQuarantined())

	done := ep.ztunnelQuarantineRegenDone.Load()
	ep.WithdrawZtunnelAdmission("repeat while map is still released")
	waitQuarantineRegen(t, ep, done)
	require.Equal(t, 2*ztunnelQuarantineMapAttempts, recorder.attempts)
	require.Empty(t, recorder.committed)
}

func TestZtunnelQuarantineMapWriteJoinsExistingRegen(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	recorder := &recordingLxcMap{fail: errors.New("map write failed")}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.recordZtunnelLxcFrontend(ep.createEpInfoCache("", ""))
	ep.mutex.Unlock()
	require.True(t, ep.SetState(StateWaitingToRegenerate, "build already queued"))

	hooked := atomic.Bool{}
	withQuarantineRegenHook(t, func(*Endpoint, *regeneration.ExternalRegenerationMetadata) {
		hooked.Store(true)
	})
	done := ep.ztunnelQuarantineRegenDone.Load()
	ep.WithdrawZtunnelAdmission("join existing build")
	waitQuarantineRegen(t, ep, done)
	require.False(t, hooked.Load())
	ep.mutex.Lock()
	level := ep.skippedRegenerationLevel
	ep.mutex.Unlock()
	require.Equal(t, regeneration.RegenerateWithDatapath, level)
}

func TestZtunnelQuarantineMapWriteSkipsStaleOwner(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ep.aliveCtx = t.Context()
	recorder := &recordingLxcMap{}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.recordZtunnelLxcFrontend(ep.createEpInfoCache("", ""))
	ep.NetNsCookie++
	ep.invalidateZtunnelLxcOwner()
	ep.mutex.Unlock()

	got := make(chan struct{}, 1)
	withQuarantineRegenHook(t, func(_ *Endpoint, meta *regeneration.ExternalRegenerationMetadata) {
		require.Contains(t, meta.Message, errZtunnelLxcOwnerStale.Error())
		got <- struct{}{}
	})
	ep.WithdrawZtunnelAdmission("sandbox replaced")
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("stale cilium_lxc owner did not queue regeneration")
	}
	require.Zero(t, recorder.attempts, "the cached frontend must not be written onto a replaced sandbox")
	require.Empty(t, recorder.committed)
	require.False(t, ep.ztunnelQuarantineMapAck.Load())
	require.True(t, ep.IsZtunnelQuarantined())
}

func TestZtunnelQuarantineRegenStopsWhenEndpointIsCancelled(t *testing.T) {
	ep, receipt := admissionEndpoint(t)
	close(ep.hasBPFProgram)
	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCtx = ctx
	cancel()
	recorder := &recordingLxcMap{fail: errors.New("map write failed")}
	ep.lxcMap = recorder
	require.NoError(t, ep.ReleaseZtunnelQuarantine(receipt))
	ep.mutex.Lock()
	ep.recordZtunnelLxcFrontend(ep.createEpInfoCache("", ""))
	ep.mutex.Unlock()

	hooked := atomic.Bool{}
	withQuarantineRegenHook(t, func(*Endpoint, *regeneration.ExternalRegenerationMetadata) {
		hooked.Store(true)
	})
	done := ep.ztunnelQuarantineRegenDone.Load()
	ep.WithdrawZtunnelAdmission("agent shutdown")
	waitQuarantineRegen(t, ep, done)
	require.False(t, hooked.Load())
	require.Equal(t, StateReady, ep.GetState())
	require.Equal(t, ztunnelQuarantineMapAttempts, recorder.attempts)
	require.Empty(t, recorder.committed)
	require.False(t, ep.ztunnelQuarantineRegenFlight.Load())
}
```

Add `"context"` to the test imports. `StateReady` and `StateWaitingToRegenerate` are the existing endpoint states. `admissionEndpoint` leaves the endpoint in `StateReady`.

Before this patch, the permanent-failure test records no committed flags and does not enter `StateWaitingToRegenerate`. A second `WithdrawZtunnelAdmission` leaves `attempts` at 1 because `Swap(true)` returns. After the patch, the first call attempts 3 writes, queues `RegenerateWithDatapath`, and the second call attempts 3 more.

Command:

```text
go test -count=1 -timeout 180s ./pkg/endpoint/ -run 'TestZtunnelWithdrawalRewritesEndpointMapAndCannotRevive|TestZtunnelIncarnationChangeQuarantinesUnderLockAndMapFailureStaysClosed|TestZtunnelQuarantine|TestZtunnelRelease'
```

The hook must stay nil in the agent. Opus should run this package test with `-race`. The goroutine takes `e.mutex` only through `SetRegenerateStateIfAlive` / `GetState`, after `WithdrawZtunnelAdmission` has returned. It does not call back into `SetZtunnelMembership`.

No datapath integration case is added here. A Go test cannot show that the old program drops packets while `WriteEndpoint` is returning the injected error. Case `ztunnel_18` shows the drop after a successful flag write. The open interval is the failed write.

## C. Acceptance matrix

| Threat | Boundary that changes | Test | Before | After | Residual |
| --- | --- | --- | --- | --- | --- |
| Required program, both compiled addresses zero, quarantine config false, no map row, TCP/15008 egress and ingress | `ztunnel_own_mode` requires one configured family | `ztunnel_zero_00` through `ztunnel_zero_05` | Mode is `HBONE_ONLY`; egress follows the existing 15008 redirect path | `QUARANTINED`, `CTX_ACT_DROP`, one `DROP_POLICY` each direction | Already-loaded bytecode is unchanged until regeneration. Live packet not demonstrated |
| Unspecified address copied into a Required program, then release | `Endpoint` omits unspecified addresses; `verifyZtunnelReceiptLocked` rejects two zero addresses | `TestEndpointConfigOmitsUnspecifiedAddresses`, `TestZtunnelReleaseRejectsZeroAddressesThenAcceptsOneFamily` | Release returns nil | Release returns `ErrZtunnelAdmissionMismatch`; one real IPv4 address then releases | Config zero and stored `0.0.0.0` are the same bits |
| Single-stack IPv4, missing or foreign row | Same collector, one family | `ztunnel_v4_01`, `ztunnel_v4_02`, `ztunnel_v4_07` | Drop, already, for a non-zero compiled address | Drop | None for this shape |
| Single-stack IPv4, owned row | Collector stays complete | `ztunnel_v4_03` through `ztunnel_v4_06` | TCP/15008 redirect or not dropped; 8080 and 31337 drop | Same | TCP/15008 is transport shape, not TLS |
| Dual-stack partial family, foreign id, mixed quarantine | Unchanged file | `ztunnel_required_01` through `07` | As written | As written | Do not delete these cases |
| Ordinary endpoint, `ztunnel_required` false | `complete` is ignored | `ztunnel_mesh_admission.c` decision table and case 01 | Application port forwarded | Same | None from this collector change |
| `WriteEndpoint` fails twice then succeeds | Three immediate writes | `TestZtunnelQuarantineMapWriteRetriesThenStoresKernelFlags` | One failure, no retry, Go atomic true, map unchanged | Attempts equal 3; committed flags `16\|32`; repeat writes nothing | The third write is the first moment packets can drop |
| Every `WriteEndpoint` fails | Regen goroutine after three failures | `TestZtunnelQuarantineMapWriteExhaustionQueuesDatapathRegen` | One attempt, no state change | Six attempts across two withdraws; `RegenerateWithDatapath`; committed flags empty | Immediate drop stays open until a new program is loaded |
| Build already waiting | `skippedRegenerationLevel` | `TestZtunnelQuarantineMapWriteJoinsExistingRegen` | No level bump | Level becomes `RegenerateWithDatapath`; hook not used | The queued build must actually use that level |
| Sandbox cookie changes after the cached frontend | Owner generation | `TestZtunnelQuarantineMapWriteSkipsStaleOwner` | Cached frontend is written | Zero write attempts; regen queued | A syscall already in `Update` is not rolled back |
| `aliveCtx` cancelled | Goroutine returns before `SetRegenerateStateIfAlive` | `TestZtunnelQuarantineRegenStopsWhenEndpointIsCancelled` | Not applicable | State stays `StateReady`; flight cleared | The three failed writes still happened |
| Node rename hidden by another endpoint batch | Already in the UID binder | Existing four node tests | Fixed in this tree | Do not reapply the address-only patch | One response can still be in `SendMsg` |
| Raw TCP/15008, ports 80, 8080, 31337 | BPF shape only | Mesh cases 03, 04, 05, 08, 10, 19 and the new v4 cases | 15008 can pass the shape check; application ports drop | Same | ztunnel is off, so there is no TLS, source-witness, capture, or original-tuple proof |
| Old `bpf_lxc` still attached | No program-version gate in this patch | Agent program list after regen | Old collector and old probe behavior | New collector only on regenerated endpoints | Compatibility guard stays closed |
| Restore | `fromSerializedEndpoint` invalidates the owner generation; admission receipt is still process-local | Existing restore tests plus the stale-owner test | Receipt is not restored | Same, plus a restored object cannot rewrite a previous process’s frontend | Restore is not a release |

TCP/15008 in these BPF tests is a port check. It does not verify TLS, does not authorize the original application tuple, and does not prove native capture or a SPIRE identity. SPIRE agent listener work is outside this patch. Do not change SPIRE server Admin or root keys here.

Cluster qualification, for Opus after the unit and BPF tests, on the owned trees only: build this fork, load it on kind-cmtc-a and kind-cmtc-b, and regenerate every endpoint program. The current cmtc-a image is the `d040` dev overlay, cmtc-b is baseline, and ztunnel is off. Those facts are not a pass. Traffic that is still required before any compatibility-guard change: local and remote, both directions, ports 80, 8080, and 31337 dropped for a released Required endpoint; raw TCP/15008 dropped while quarantine is held and forwarded only as transport shape after release; an active plaintext flow dropped after the mode change; a failed map write followed by regeneration actually loading `ztunnel_quarantined=true`. A unit pass does not open the compatibility guard.

**Verdict for this remediation package:** apply the BPF collector, the release address check, and the bounded map-write retry with regeneration fallback. Leave the node binder as it is. Treat immediate packet drop as unmet whenever every `cilium_lxc` write fails.