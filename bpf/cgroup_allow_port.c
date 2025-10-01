#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port SEC(".maps");

SEC("cgroup/connect4")
int cgroup_allow_port_v4(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *allowed = bpf_map_lookup_elem(&allowed_port, &key);
    
    if (!allowed) {
        return 0;  // Deny if map lookup fails
    }
    
    // Port is in network byte order, convert to host byte order
    __u16 port = bpf_ntohs(ctx->user_port);
    
    bpf_printk("connect4: port=%d, allowed=%d\n", port, *allowed);
    
    if (port == *allowed) {
        return 1;  // ALLOW
    }
    
    return 0;  // DENY
}

SEC("cgroup/bind4")
int cgroup_allow_port_bind4(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *allowed = bpf_map_lookup_elem(&allowed_port, &key);
    
    if (!allowed) {
        return 0;  // Deny if map lookup fails
    }
    
    // Port is in network byte order, convert to host byte order
    __u16 port = bpf_ntohs(ctx->user_port);
    
    bpf_printk("bind4: port=%d, allowed=%d\n", port, *allowed);
    
    if (port == *allowed) {
        return 1;  // ALLOW
    }
    
    return 0;  // DENY
}

char _license[] SEC("license") = "GPL";