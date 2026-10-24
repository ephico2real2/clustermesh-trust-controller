// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Observe only. Return TCX_NEXT for every packet and every error.
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct __sk_buff { __u32 len; };
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define TCX_NEXT (-1)
struct counters { __u64 packets; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} observed SEC(".maps");
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
SEC("tcx/ingress")
int cmtc_observe(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct counters *c = bpf_map_lookup_elem(&observed, &key);
    if (c) {
        // Atomic protects same-CPU reentrancy too; no packet data is modified.
        __sync_fetch_and_add(&c->packets, 1);
        __sync_fetch_and_add(&c->bytes, skb->len);
    }
    return TCX_NEXT;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
