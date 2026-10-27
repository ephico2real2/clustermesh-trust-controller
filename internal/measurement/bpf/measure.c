// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// CMTC eBPF measurement plane (ADR-005): two cgroup_skb programs on one Pod's cgroup.
//
// Observe only. Both programs return 1 on their only exit: the cgroup_skb value that keeps the packet
// (kernel/bpf/cgroup.c, __cgroup_bpf_run_filter_skb; net/ipv4/ip_output.c, ip_finish_output). They read the packet
// with bpf_skb_load_bytes, write no packet or context field, and write only the maps of this object.
//
// The loader loads one copy of both programs for each measured Pod, with the Pod's own cmtc_traffic and cmtc_dns
// arrays, and attaches it to the Pod-level cgroup; every copy shares the other maps. The sockets of the Pod's
// containers are in that cgroup or below it. ztunnel's sockets belong to ztunnel's own cgroup, so these programs see
// the application's packets only.
//
// The kernel runs both hooks at the socket layer with the packet starting at its IP header: egress before
// fragmentation and GSO segmentation, ingress after reassembly.
//
// Every counter is a cell of an array, looked up by its cell number, never a field chosen by a variable offset into
// a map value. The loader has CAP_BPF but not CAP_PERFMON, so the verifier applies its Spectre v1 hardening
// (kernel/bpf/verifier.c): it refuses map-value pointer arithmetic whose register differs between the paths that
// reach it (update_alu_sanitation_state), and on the paths that only speculative execution takes it forgets what a
// branch compared (sanitize_speculative_path). An array lookup bounds the cell number at run time instead.
//
// Cell numbers follow the label values of internal/measurement/contract.go, in the row-major order of its
// PodCounters and NodeCounters arrays. scripts/measurement/build-bpf.sh compiles this file into measure_bpfel.o; run
// it after every change.
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_NOEXIST 1
#define BPF_EXIST 2

// Context layouts copied from include/uapi/linux/bpf.h (v6.8); the kernel keeps them stable.
#define __bpf_md_ptr(type, name) \
	union {                      \
		type name;               \
		__u64 : 64;              \
	} __attribute__((aligned(8)))

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__u16 dst_port; /* network byte order; 0 unless the socket is connected */
	__u16 : 16;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__bpf_md_ptr(void *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8 tstamp_type;
	__u32 : 24;
	__u64 hwtstamp;
};

#define PASS 1
#define LOOPBACK_IFINDEX 1 /* include/net/flow.h: lo is ifindex 1 in every network namespace */
#define DNS_PORT 53
#define ZTUNNEL_DNS_PORT 15053 /* ztunnel's in-Pod DNS proxy, when DNS capture is on */

#define MAX_PENDING 4096
#define MAX_NODE_ADDRS 1024
#define N_DIRECTION 2
#define N_PATH 2
#define N_PROTOCOL 6
#define N_TRANSPORT 2
#define N_LOCALITY 3
#define N_RCODE 7
#define N_BOUNDS 13

enum { DIR_EGRESS, DIR_INGRESS };
enum { PATH_LOOPBACK, PATH_POD_NETWORK };
enum { PROTO_TCP, PROTO_UDP, PROTO_DNS, PROTO_ICMP, PROTO_FRAGMENT, PROTO_OTHER };
enum { TRANSPORT_UDP, TRANSPORT_TCP };
enum { LOC_IN_POD, LOC_SAME_NODE, LOC_OFF_NODE };
enum { RC_NOERROR, RC_FORMERR, RC_SERVFAIL, RC_NXDOMAIN, RC_NOTIMP, RC_REFUSED, RC_OTHER };

// The cell counts of the three counter arrays.
#define N_TRAFFIC (N_DIRECTION * N_PATH * N_PROTOCOL)                           /* 24 */
#define N_POD_DNS (N_TRANSPORT * N_LOCALITY * (1 + N_RCODE))                    /* 48 */
#define N_NODE (N_TRANSPORT * N_LOCALITY * (N_BOUNDS + 2) + 2 * N_TRANSPORT)   /* 94 */

struct cmtc_counter {
	__u64 packets;
	__u64 bytes;
};

// An IP address; IPv4 is stored IPv4-mapped (::ffff:a.b.c.d), as Go's netip.Addr.As16 does.
struct cmtc_addr {
	__u8 addr[16];
};

// A query waits for its answer under (socket cookie, DNS ID, transport). An LRU hash bounds the memory and charges
// nothing to the socket, unlike socket storage (net/core/bpf_sk_storage.c charges sk_omem_alloc).
struct cmtc_pending_key {
	__u64 cookie;
	__u16 id;
	__u8 transport;
	__u8 pad[5];
};

// The Pod's packets and bytes, by direction, path and protocol (each Pod's copy has its own).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, N_TRAFFIC);
	__type(key, __u32);
	__type(value, struct cmtc_counter);
} cmtc_traffic SEC(".maps");

// The Pod's DNS queries by transport and locality, then its answers by transport, locality and response code (each
// Pod's copy has its own).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, N_POD_DNS);
	__type(key, __u32);
	__type(value, __u64);
} cmtc_dns SEC(".maps");

// The node's DNS answer latency histogram and sums by transport and locality, then the unmatched answers and the
// replaced queries by transport.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, N_NODE);
	__type(key, __u32);
	__type(value, __u64);
} cmtc_node SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PENDING);
	__type(key, struct cmtc_pending_key);
	__type(value, __u64);
} cmtc_dns_pend SEC(".maps");

// The IP addresses of the Pods on this node (hostNetwork Pods give the node's own addresses). The loader writes it
// from the node agent's list; a DNS peer in it is on the same node.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_NODE_ADDRS);
	__type(key, struct cmtc_addr);
	__type(value, __u32);
} cmtc_node_addrs SEC(".maps");

// The upper bounds of the latency histogram, set by the loader before it loads the programs; read-only data, frozen
// by the kernel.
volatile const __u64 cmtc_bounds_ns[N_BOUNDS] = {};

static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*const bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*const bpf_ktime_get_ns)(void) = (void *)5;
static long (*const bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*const bpf_get_socket_cookie)(void *ctx) = (void *)46;

// What parse learns from one packet.
struct packet {
	struct cmtc_addr peer; /* the destination on egress, the source on ingress */
	__u32 l4;              /* offset of the transport header */
	int l4proto;           /* PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_FRAGMENT or PROTO_OTHER */
};

static __always_inline __u32 be16(const __u8 *p)
{
	return ((__u32)p[0] << 8) | p[1];
}

// parse reads the IP header: the peer address, the transport header offset and the transport protocol. A first or
// later IP fragment is PROTO_FRAGMENT; an IPv6 chain of more than four extension headers is PROTO_OTHER.
static __always_inline void parse(struct __sk_buff *skb, int dir, struct packet *p)
{
	__u8 h[40];

	p->l4proto = PROTO_OTHER;
	if (bpf_skb_load_bytes(skb, 0, h, 1) < 0)
		return;
	if ((h[0] >> 4) == 4) {
		if (bpf_skb_load_bytes(skb, 0, h, 20) < 0)
			return;
		p->peer.addr[10] = 0xff;
		p->peer.addr[11] = 0xff;
		__builtin_memcpy(&p->peer.addr[12], dir == DIR_EGRESS ? &h[16] : &h[12], 4);
		if (be16(&h[6]) & 0x3fff) { /* MF set or a fragment offset */
			p->l4proto = PROTO_FRAGMENT;
			return;
		}
		p->l4 = (h[0] & 0x0f) * 4;
		if (p->l4 < 20)
			return;
		if (h[9] == 6)
			p->l4proto = PROTO_TCP;
		else if (h[9] == 17)
			p->l4proto = PROTO_UDP;
		else if (h[9] == 1)
			p->l4proto = PROTO_ICMP;
		return;
	}
	if ((h[0] >> 4) != 6)
		return;
	if (bpf_skb_load_bytes(skb, 0, h, 40) < 0)
		return;
	__builtin_memcpy(p->peer.addr, dir == DIR_EGRESS ? &h[24] : &h[8], 16);
	__u32 next = h[6];
	__u32 off = 40;
#pragma unroll
	for (int i = 0; i < 4; i++) {
		__u8 ext[2];

		if (next != 0 && next != 43 && next != 60 && next != 51)
			break; /* not hop-by-hop, routing, destination options or AH */
		if (bpf_skb_load_bytes(skb, off, ext, 2) < 0)
			return;
		off += next == 51 ? ((__u32)ext[1] + 2) * 4 : ((__u32)ext[1] + 1) * 8;
		next = ext[0];
	}
	p->l4 = off;
	if (next == 44)
		p->l4proto = PROTO_FRAGMENT;
	else if (next == 6)
		p->l4proto = PROTO_TCP;
	else if (next == 17)
		p->l4proto = PROTO_UDP;
	else if (next == 58)
		p->l4proto = PROTO_ICMP;
}

// peer_port returns the peer's port in host order: the destination port on egress, the source port on ingress. A
// connected socket's peer port wins, because NAT may have changed the packet's port: on egress the in-Pod REDIRECT
// to ztunnel runs before this hook.
static __always_inline __u32 peer_port(struct __sk_buff *skb, int dir, __u32 l4)
{
	__u8 ports[4];
	__u32 port = 0;

	if (bpf_skb_load_bytes(skb, l4, ports, 4) == 0)
		port = dir == DIR_EGRESS ? be16(&ports[2]) : be16(&ports[0]);
	struct bpf_sock *sk = skb->sk;
	if (sk) {
		__u16 connected = sk->dst_port;
		if (connected)
			port = __builtin_bswap16(connected);
	}
	return port;
}

// Cell numbers of the counter arrays.
static __always_inline __u32 traffic_cell(int dir, __u32 path, __u32 proto)
{
	return (dir * N_PATH + path) * N_PROTOCOL + proto;
}

static __always_inline __u32 query_cell(__u32 transport, __u32 loc)
{
	return transport * N_LOCALITY + loc;
}

static __always_inline __u32 answer_cell(__u32 transport, __u32 loc, __u32 rcode)
{
	return N_TRANSPORT * N_LOCALITY + (transport * N_LOCALITY + loc) * N_RCODE + rcode;
}

static __always_inline __u32 latency_count_cell(__u32 transport, __u32 loc, __u32 bucket)
{
	return (transport * N_LOCALITY + loc) * (N_BOUNDS + 1) + bucket;
}

static __always_inline __u32 latency_sum_cell(__u32 transport, __u32 loc)
{
	return N_TRANSPORT * N_LOCALITY * (N_BOUNDS + 1) + transport * N_LOCALITY + loc;
}

static __always_inline __u32 unmatched_cell(__u32 transport)
{
	return N_TRANSPORT * N_LOCALITY * (N_BOUNDS + 2) + transport;
}

static __always_inline __u32 replaced_cell(__u32 transport)
{
	return N_TRANSPORT * N_LOCALITY * (N_BOUNDS + 2) + N_TRANSPORT + transport;
}

// add adds value to one cell of a __u64 counter array. The lookup returns NULL for a cell beyond the array.
static __always_inline void add(void *map, __u32 cell, __u64 value)
{
	__u64 *counter = bpf_map_lookup_elem(map, &cell);

	if (counter)
		__sync_fetch_and_add(counter, value);
}

static __always_inline __u32 locality(struct packet *p, int loopback)
{
	if (loopback)
		return LOC_IN_POD;
	if (bpf_map_lookup_elem(&cmtc_node_addrs, &p->peer))
		return LOC_SAME_NODE;
	return LOC_OFF_NODE;
}

static __always_inline __u32 rcode_class(__u32 rcode)
{
	switch (rcode) {
	case 0:
		return RC_NOERROR;
	case 1:
		return RC_FORMERR;
	case 2:
		return RC_SERVFAIL;
	case 3:
		return RC_NXDOMAIN;
	case 4:
		return RC_NOTIMP;
	case 5:
		return RC_REFUSED;
	default:
		return RC_OTHER;
	}
}

static __always_inline __u32 latency_bucket(__u64 ns)
{
#pragma unroll
	for (int i = 0; i < N_BOUNDS; i++)
		if (ns <= cmtc_bounds_ns[i])
			return i;
	return N_BOUNDS;
}

// dns counts a client DNS query (egress) or answer (ingress) and times the answer. Only a standard query (opcode 0)
// or its answer with exactly one question counts. Over TCP, only a segment whose payload starts a DNS message (a
// 2-byte length, then the header) is read.
static __always_inline void dns(struct __sk_buff *skb, int dir, __u32 transport, struct packet *p, int loopback)
{
	__u8 h[14];
	__u8 *hdr = h;

	if (transport == TRANSPORT_TCP) {
		__u8 doff;

		if (bpf_skb_load_bytes(skb, p->l4 + 12, &doff, 1) < 0)
			return;
		if (bpf_skb_load_bytes(skb, p->l4 + (doff >> 4) * 4, h, 14) < 0)
			return; /* no payload: SYN, ACK or FIN */
		if (be16(h) < 12)
			return;
		hdr = &h[2];
	} else if (bpf_skb_load_bytes(skb, p->l4 + 8, h, 12) < 0) {
		return;
	}
	if (((hdr[2] >> 3) & 0x0f) != 0 || be16(&hdr[4]) != 1)
		return;
	__u32 answer = hdr[2] >> 7;
	if (answer != (dir == DIR_INGRESS))
		return; /* a query this Pod received or an answer it sent: it serves DNS */

	__u32 loc = locality(p, loopback);
	struct cmtc_pending_key key = {};
	key.cookie = bpf_get_socket_cookie(skb);
	key.id = be16(hdr);
	key.transport = transport;

	if (!answer) {
		add(&cmtc_dns, query_cell(transport, loc), 1);
		__u64 now = bpf_ktime_get_ns();
		if (bpf_map_update_elem(&cmtc_dns_pend, &key, &now, BPF_NOEXIST) == 0)
			return;
		// The client reused a waiting ID on this socket, normally a retry: time the answer from the latest query
		// and count the replacement.
		if (bpf_map_update_elem(&cmtc_dns_pend, &key, &now, BPF_EXIST) == 0)
			add(&cmtc_node, replaced_cell(transport), 1);
		return;
	}

	add(&cmtc_dns, answer_cell(transport, loc, rcode_class(hdr[3] & 0x0f)), 1);
	__u64 *sent = bpf_map_lookup_elem(&cmtc_dns_pend, &key);
	if (!sent) {
		add(&cmtc_node, unmatched_cell(transport), 1);
		return;
	}
	__u64 elapsed = bpf_ktime_get_ns() - *sent;
	bpf_map_delete_elem(&cmtc_dns_pend, &key);
	add(&cmtc_node, latency_count_cell(transport, loc, latency_bucket(elapsed)), 1);
	add(&cmtc_node, latency_sum_cell(transport, loc), elapsed);
}

static __always_inline void measure(struct __sk_buff *skb, int dir)
{
	struct packet p = {};
	parse(skb, dir, &p);
	// The device decides the path. A packet to or from a loopback address, or to the Pod's own address, always
	// uses lo, and so does every TCP flow that ztunnel captures in the Pod.
	int loopback = skb->ifindex == LOOPBACK_IFINDEX;
	__u32 proto = p.l4proto;
	if (proto == PROTO_TCP || proto == PROTO_UDP) {
		__u32 port = peer_port(skb, dir, p.l4);
		if (port == DNS_PORT || (port == ZTUNNEL_DNS_PORT && loopback)) {
			dns(skb, dir, proto == PROTO_TCP ? TRANSPORT_TCP : TRANSPORT_UDP, &p, loopback);
			proto = PROTO_DNS;
		}
	}

	// A GSO or GRO packet counts as its segments.
	__u32 segs = skb->gso_segs;
	if (!segs)
		segs = 1;
	__u32 cell = traffic_cell(dir, loopback ? PATH_LOOPBACK : PATH_POD_NETWORK, proto);
	struct cmtc_counter *t = bpf_map_lookup_elem(&cmtc_traffic, &cell);
	if (!t)
		return;
	__sync_fetch_and_add(&t->packets, segs);
	__sync_fetch_and_add(&t->bytes, skb->len);
}

SEC("cgroup_skb/egress")
int cmtc_measure_egress(struct __sk_buff *skb)
{
	measure(skb, DIR_EGRESS);
	return PASS;
}

SEC("cgroup_skb/ingress")
int cmtc_measure_ingress(struct __sk_buff *skb)
{
	measure(skb, DIR_INGRESS);
	return PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
