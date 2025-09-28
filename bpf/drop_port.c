// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h> 

// Map to store the blocked port
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

// Counter map for debugging
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

// Debug counter indices
#define COUNTER_TOTAL_PACKETS 0
#define COUNTER_IPV4_PACKETS 1
#define COUNTER_IPV6_PACKETS 2
#define COUNTER_TCP_PACKETS 3
#define COUNTER_PORT_MATCHES 4
#define COUNTER_DROPPED_PACKETS 5

// Function declarations first
static __always_inline void increment_counter(__u32 index);
static __always_inline int check_and_drop_port(struct tcphdr *tcp);
static __always_inline int process_ipv4(void *data, void *data_end);
static __always_inline int process_ipv6(void *data, void *data_end);

// Helper function to increment counters
static __always_inline void increment_counter(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&debug_counters, &index);
    if (counter) {
        (*counter)++;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&debug_counters, &index, &init_val, BPF_ANY);
    }
}

// Common function to check port and drop if needed
static __always_inline int check_and_drop_port(struct tcphdr *tcp) {
    // Extract port numbers (convert from network to host byte order)
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    
    // Look up blocked port
    __u32 key = 0;
    __u16 *blocked_port_ptr = bpf_map_lookup_elem(&blocked_port, &key);
    
    if (!blocked_port_ptr) {
        // If no port is configured, pass all traffic
        return XDP_PASS;
    }
    
    __u16 blocked_port_val = *blocked_port_ptr;
    
    // Log the comparison for debugging
    bpf_printk("XDP: src=%d dst=%d blocked=%d", src_port, dst_port, blocked_port_val);
    
    // Check if either source or destination port matches
    if (src_port == blocked_port_val || dst_port == blocked_port_val) {
        increment_counter(COUNTER_PORT_MATCHES);
        increment_counter(COUNTER_DROPPED_PACKETS);
        bpf_printk("XDP: DROPPING packet on port %d", blocked_port_val);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

// Process IPv4 packets
static __always_inline int process_ipv4(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    
    if ((void*)(ip + 1) > data_end) {
        bpf_printk("XDP: IPv4 header out of bounds");
        return XDP_PASS;
    }
    
    // Check for TCP
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    increment_counter(COUNTER_TCP_PACKETS);
    
    // Calculate IP header length
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) {
        bpf_printk("XDP: Invalid IPv4 header length: %d", ip_hdr_len);
        return XDP_PASS;
    }
    
    // Locate TCP header
    struct tcphdr *tcp = (void*)ip + ip_hdr_len;
    if ((void*)(tcp + 1) > data_end) {
        bpf_printk("XDP: TCP header out of bounds (IPv4)");
        return XDP_PASS;
    }
    
    return check_and_drop_port(tcp);
}

// Process IPv6 packets
static __always_inline int process_ipv6(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
    
    if ((void*)(ip6 + 1) > data_end) {
        bpf_printk("XDP: IPv6 header out of bounds");
        return XDP_PASS;
    }
    
    // Check for TCP (IPv6 doesn't have options in main header like IPv4)
    if (ip6->nexthdr != IPPROTO_TCP) {
        bpf_printk("XDP: IPv6 not TCP, nexthdr=%d", ip6->nexthdr);
        return XDP_PASS;
    }
    
    increment_counter(COUNTER_TCP_PACKETS);
    
    // TCP header immediately follows IPv6 header (40 bytes)
    struct tcphdr *tcp = (void*)ip6 + sizeof(struct ipv6hdr);
    if ((void*)(tcp + 1) > data_end) {
        bpf_printk("XDP: TCP header out of bounds (IPv6)");
        return XDP_PASS;
    }
    
    return check_and_drop_port(tcp);
}

SEC("xdp")
int xdp_drop_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Increment total packet counter
    increment_counter(COUNTER_TOTAL_PACKETS);
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) > data_end) {
        bpf_printk("XDP: Packet too small for Ethernet header");
        return XDP_PASS;
    }
    
    struct ethhdr *eth = data;
    
    // Check for IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        increment_counter(COUNTER_IPV4_PACKETS);
        bpf_printk("XDP: Processing IPv4 packet");
        return process_ipv4(data, data_end);
    }
    // Check for IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        increment_counter(COUNTER_IPV6_PACKETS);
        bpf_printk("XDP: Processing IPv6 packet");
        return process_ipv6(data, data_end);
    }
    
    // Neither IPv4 nor IPv6, pass through
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
