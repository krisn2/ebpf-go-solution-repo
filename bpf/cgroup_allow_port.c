
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to hold the single allowed port
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port SEC(".maps");

// CGroup socket connect hook for IPv4
SEC("cgroup/connect4")
int cgroup_allow_port_v4(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *allowed;

    // We only care about TCP connections
    if (ctx->protocol != IPPROTO_TCP) {
        return 1; // allow
    }

    // Lookup the allowed port from the map
    allowed = bpf_map_lookup_elem(&allowed_port, &key);
    if (!allowed) {
        // If the port is not configured, deny by default for safety
        return 0; // deny
    }

    // Fix: ctx->user_port is in host byte order on modern kernels.
    // The value 'allowed' is also set by userspace in host byte order.
    // We compare host-to-host.
    if (ctx->user_port == *allowed) {
        return 1; // allow connection
    }

    return 0; // deny connection to any other port
}

char LICENSE[] SEC("license") = "GPL";
