/**
 * @file main.bpf.c
 * @brief Data Plane Core - eBPFNetFlowLyzer (Kernel-Space)
 * 
 * This program implements the high-performance packet interception engine using 
 * XDP (eXpress Data Path). It operates at the earliest point in the Linux network 
 * stack (NIC Driver level), enabling wire-speed feature extraction.
 * 
 * Core Functionalities:
 * 1. Dual-Stack Unified Parser: Handles IPv4 and IPv6 through a 128-bit key mapping.
 * 2. Stateful Tracking: Uses BPF Maps (LRU_HASH) for flow accounting.
 * 3. Asynchronous Telemetry: Dispatches flow events to User-Space via RingBuffer.
 * 
 * Research Context:
 * Developed for DDoS detection and mitigation research (Master's Degree).
 * Optimized for high-throughput (PPS) and minimal latency.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/** 
 * @brief Connection Table capacity. 
 * Tuned to handle massive DDoS attack vectors without excessive memory pressure.
 */
#define MAX_ENTRIES 131072 

/**
 * @struct flow_event_t
 * @brief Transfer structure for User-Space synchronization.
 * Contains raw metrics extracted from the L3/L4/L7 headers.
 */
struct flow_event_t {
    __u8 src_ip[16];   /**< 128-bit address (IPv6 or IPv4-mapped) */
    __u8 dst_ip[16];   /**< 128-bit address (IPv6 or IPv4-mapped) */
    __u16 src_port;    
    __u16 dst_port;    
    __u8 protocol;     
    __u8 ip_ver;       
    
    __u16 payload_length; 
    __u16 header_length;  
    __u8 tcp_flags;       /**< Tracked: FIN, SYN, RST, PSH, ACK, URG */
    __u64 timestamp_ns;   /**< Monotonic timestamp for IAT calculation */

    __u8 dns_payload_raw[256]; /**< L7 buffer for DNS metadata extraction */
};

/**
 * @struct flow_key_t
 * @brief The 5-tuple key for stateful flow correlation.
 */
struct flow_key_t {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

/**
 * @struct flow_stats_t
 * @brief Atomic counters for in-kernel flow accounting.
 */
struct flow_stats_t {
    __u64 total_bytes;
    __u64 packet_count;
    __u64 start_time_ns;
    __u64 last_time_ns;
};

/* --- BPF MAP DEFINITIONS --- */

/**
 * @brief High-performance RingBuffer for asynchronous telemetry dispatch.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} flows_ringbuf SEC(".maps");

/**
 * @brief Stateful cache for active flows. 
 * Replaces traditional user-space tracking with O(1) kernel-level lookups.
 * Uses LRU eviction policy to survive massive connection floods.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key_t);
    __type(value, struct flow_stats_t);
} flow_state_cache SEC(".maps");

/* --- DATA PLANE LOGIC --- */

/**
 * @brief XDP Entry Point.
 * 
 * This function is executed for every packet arriving at the NIC.
 * It performs rigorous boundary checks to satisfy the eBPF Verifier
 * while maintaining a lock-free, zero-copy architecture.
 */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 ip_ver = 0;
    __u8 src_ip[16] = {0};
    __u8 dst_ip[16] = {0};
    __u8 l4_proto = 0;
    struct flow_key_t search_key = {0};

    // --- L3 Header Parsing ---
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        ip_ver = 4;
        l4_proto = ip->protocol;
        
        // IPv4-Mapped IPv6: Transcoding for unified 128-bit keying
        // Format: ::ffff:a.b.c.d
        src_ip[10] = 0xff; src_ip[11] = 0xff;
        *(__u32 *)&src_ip[12] = ip->saddr;
        
        dst_ip[10] = 0xff; dst_ip[11] = 0xff;
        *(__u32 *)&dst_ip[12] = ip->daddr;

    } else if (eth->h_proto == bpf_htons(0x86DD)) { // ETH_P_IPV6
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        ip_ver = 6;
        l4_proto = ip6->nexthdr;
        // Memory-safe read of 128-bit IPv6 addresses
        bpf_probe_read_kernel(src_ip, 16, &ip6->saddr);
        bpf_probe_read_kernel(dst_ip, 16, &ip6->daddr);
    } else {
        return XDP_PASS;
    }

    // --- L4 Header Parsing ---
    __u16 l4_payload_len = 0;
    __u16 l4_header_len = 0;
    __u16 tcp_flags_tracked = 0;
    __u16 sport = 0, dport = 0;
    void *l4_header = NULL;

    // Calculate L4 offset based on IP version (considering IPv4 Options)
    if (ip_ver == 4) {
        struct iphdr *ip = (void *)(eth + 1);
        l4_header = (void *)ip + (ip->ihl * 4);
    } else {
        l4_header = (void *)(eth + 1) + sizeof(struct ipv6hdr);
    }

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        
        sport = tcp->source;
        dport = tcp->dest;
        l4_header_len = tcp->doff * 4;
        tcp_flags_tracked = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        
        if (ip_ver == 4) {
            struct iphdr *ip = (void *)(eth + 1);
            l4_payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - l4_header_len;
        } else {
            struct ipv6hdr *ip6 = (void *)(eth + 1);
            l4_payload_len = bpf_ntohs(ip6->payload_len) - l4_header_len;
        }

    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        sport = udp->source;
        dport = udp->dest;
        l4_header_len = sizeof(struct udphdr);
        
        if (ip_ver == 4) {
            struct iphdr *ip = (void *)(eth + 1);
            l4_payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - l4_header_len;
        } else {
            struct ipv6hdr *ip6 = (void *)(eth + 1);
            l4_payload_len = bpf_ntohs(ip6->payload_len);
        }
    } else {
        return XDP_PASS;
    }

    // --- Stateful Flow Correlation ---
    __builtin_memcpy(search_key.src_ip, src_ip, 16);
    __builtin_memcpy(search_key.dst_ip, dst_ip, 16);
    search_key.src_port = sport;
    search_key.dst_port = dport;
    search_key.protocol = l4_proto;

    struct flow_stats_t *stats = bpf_map_lookup_elem(&flow_state_cache, &search_key);
    if (stats) {
        // Atomic updates to ensure data integrity during parallel core execution
        __sync_fetch_and_add(&stats->total_bytes, l4_payload_len);
        __sync_fetch_and_add(&stats->packet_count, 1);
        stats->last_time_ns = bpf_ktime_get_ns();
    } else {
        struct flow_stats_t new_stats = {0};
        new_stats.total_bytes = l4_payload_len;
        new_stats.packet_count = 1;
        new_stats.start_time_ns = bpf_ktime_get_ns();
        new_stats.last_time_ns = new_stats.start_time_ns;
        bpf_map_update_elem(&flow_state_cache, &search_key, &new_stats, BPF_ANY);
    }

    // --- Telemetry Dispatch (RingBuffer) ---
    struct flow_event_t *event;
    event = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*event), 0);
    if (!event)
        return XDP_PASS; 

    __builtin_memcpy(event->src_ip, src_ip, 16);
    __builtin_memcpy(event->dst_ip, dst_ip, 16);
    event->src_port = sport;
    event->dst_port = dport;
    event->protocol = l4_proto;
    event->ip_ver = ip_ver;
    event->tcp_flags = tcp_flags_tracked;
    event->payload_length = l4_payload_len;
    event->header_length = l4_header_len;
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // --- L7 Meta-Extraction Subroutine ---
    // Specifically targets DNS traffic for high-layer feature correlation
    if (l4_proto == IPPROTO_UDP && (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53)) {
        struct udphdr *udp = l4_header;
        void *payload = (void *)(udp + 1);
        __u32 copy_len = l4_payload_len;
        if (copy_len > 255) copy_len = 255; 

        if (payload + copy_len <= data_end) {
            bpf_probe_read_kernel(event->dns_payload_raw, copy_len & 0xFF, payload);
        }
    }
    
    bpf_ringbuf_submit(event, 0); 

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
