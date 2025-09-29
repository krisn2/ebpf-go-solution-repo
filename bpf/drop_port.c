#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define COUNTER_PORT_MATCHES 0
#define COUNTER_DROPPED_PACKETS 1
#define MAX_COUNTERS 10

// Map definitions remain unchanged...

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

static inline void increment_counter(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&debug_counters, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

// Check if the TCP header is safe to access and drop if port matches.
static inline int check_and_drop_port(struct tcphdr *tcph, void *data_end) {
    __u32 key = 0;
    __u16 *blocked;

    // Boundary Check: Ensure the full TCP header is within the packet bounds.
    if ((void *)tcph + sizeof(*tcph) > data_end) {
        return XDP_PASS;
    }

    blocked = bpf_map_lookup_elem(&blocked_port, &key);
    if (!blocked) {
        return XDP_PASS; 
    }

    // Check if source or destination port matches the blocked port.
    if (bpf_ntohs(tcph->source) == *blocked || bpf_ntohs(tcph->dest) == *blocked) {
        increment_counter(COUNTER_PORT_MATCHES);
        increment_counter(COUNTER_DROPPED_PACKETS);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static inline int process_ipv4(void *data, void *data_end) {
    struct iphdr *iph = data;
    struct tcphdr *tcph;
    __u32 ip_header_len;

    // Boundary Check: Ensure the full IP header is within the packet bounds.
    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }
    
    // Get IP header length (in 4-byte words), then convert to bytes
    ip_header_len = iph->ihl * 4;

    // Double-check IP header bounds based on actual length
    if ((void *)iph + ip_header_len > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Calculate TCP header start using the IP header length
    tcph = (void *)iph + ip_header_len;

    return check_and_drop_port(tcph, data_end);
}

// ... (process_ipv6 and xdp_drop_port remain the same as previous)

static inline int process_ipv6(void *data, void *data_end) {
    return XDP_PASS;
}

SEC("xdp")
int xdp_drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check bounds for the Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    __u16 eth_type = bpf_ntohs(eth->h_proto);

    switch (eth_type) {
        case ETH_P_IP:
            return process_ipv4(eth + 1, data_end);
        case ETH_P_IPV6:
            return process_ipv6(eth + 1, data_end);
        default:
            return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";
