#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port SEC(".maps");

/* 
 * For cgroup/connect4: ctx->user_port is the destination port the task
 * is trying to connect to. Convert to host-order and compare to allowed.
 *
 * For cgroup/bind4: ctx->user_port is the port being bound (host order
 * after bpf_ntohs). Compare to allowed.
 */

SEC("cgroup/connect4")
int cgroup_allow_port_v4(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *allowed = bpf_map_lookup_elem(&allowed_port, &key);
    if (!allowed) {
        bpf_printk("connect4: allowed_port map lookup failed\n");
        return 0;  // DENY if map lookup fails
    }

    // ctx->user_port is in network byte order -> convert to host order
    __u16 dst_port = bpf_ntohs(ctx->user_port);

    bpf_printk("connect4: dst_port=%d allowed=%d\n", dst_port, *allowed);

    if (dst_port == *allowed) {
        return 1;  // ALLOW
    }

    return 0;  // DENY
}

SEC("cgroup/bind4")
int cgroup_allow_port_bind4(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *allowed = bpf_map_lookup_elem(&allowed_port, &key);
    if (!allowed) {
        bpf_printk("bind4: allowed_port map lookup failed\n");
        return 0;  // DENY if map lookup fails
    }

    // ctx->user_port is in network byte order -> convert to host order
    __u16 bind_port = bpf_ntohs(ctx->user_port);

    bpf_printk("bind4: bind_port=%d allowed=%d\n", bind_port, *allowed);

    if (bind_port == *allowed) {
        return 1;  // ALLOW
    }

    return 0;  // DENY
}

char _license[] SEC("license") = "GPL";
