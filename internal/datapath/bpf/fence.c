// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Experimental persistent quarantine only. No grant, identity or lease input.
// This must never become an admission/protection claim before the native CNI
// and Cilium restore paths install and verify the actual fence before release.
typedef unsigned int __u32;
typedef unsigned long long __u64;
// Only this stable UAPI context field is read; avoid hand-copying unused ABI.
struct __sk_buff { __u32 len; };
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define TCX_DROP 2
struct counters { __u64 packets; __u64 bytes; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} accounted SEC(".maps");
static void *(*const bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
SEC("tcx/ingress")
int cmtc_fence(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct counters *c = bpf_map_lookup_elem(&accounted, &key);
    if (c) {
        __sync_fetch_and_add(&c->packets, 1);
        __sync_fetch_and_add(&c->bytes, skb->len);
    }
    // Accounting availability and contents cannot change the verdict.
    // TCX_DROP terminates this hook, so the following Cilium program does not run.
    return TCX_DROP;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
