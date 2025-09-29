#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Map to hold the single allowed port
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port SEC(".maps");

// Helper function to check the port against the allowed map
static inline int check_allowed_port(struct bpf_sock_addr *ctx) {
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
        bpf_printk("Error: Allowed port not configured, denying.");
        return 0; // deny
    }

    // Check if the relevant port (ctx->user_port for connect, ctx->user_port for bind) matches
    // ctx->user_port is the destination port in connect4, and the local port in bind4.
    // Both are in host byte order.
    if (ctx->user_port == *allowed) {
        return 1; // allow connection/bind
    }

    bpf_printk("Denying access to port %u, only %u is allowed.", ctx->user_port, *allowed);
    return 0; // deny
}


// -----------------------------------------------------------------------------
// 1. Hook for Outgoing (Client) Traffic - cgroup/connect4
// Controls which remote ports the process in the cgroup can connect TO.
// -----------------------------------------------------------------------------
SEC("cgroup/connect4")
int cgroup_allow_port_v4(struct bpf_sock_addr *ctx) {
    // Check the destination port (ctx->user_port)
    return check_allowed_port(ctx);
}

// -----------------------------------------------------------------------------
// 2. Hook for Incoming (Server) Traffic - cgroup/bind4
// Controls which local ports the process in the cgroup can listen ON.
// -----------------------------------------------------------------------------
SEC("cgroup/bind4")
int cgroup_allow_port_bind4(struct bpf_sock_addr *ctx) {
    // Check the local port (ctx->user_port)
    return check_allowed_port(ctx);
}

