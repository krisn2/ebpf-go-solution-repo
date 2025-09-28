// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>


struct {
__uint(type, BPF_MAP_TYPE_ARRAY);
__uint(max_entries, 1);
__type(key, __u32);
__type(value, __u16);
} allowed_port SEC(".maps");


SEC("cgroup/connect4")
int allow_only_port(struct bpf_sock_addr *ctx) {
__u32 key = 0;
__u16 *p = bpf_map_lookup_elem(&allowed_port, &key);
if (!p) {
// no configured port => allow
return 1;
}


// ctx->user_port is in network byte order already in older kernels
// to be safe: compare in host order
__u16 allowed = *p;
if (ctx->user_port == __builtin_bswap16(allowed)) {
return 1; // allow
}


return 0; // deny
}


char _license[] SEC("license") = "GPL";
