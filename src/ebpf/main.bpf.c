/**
 * @file main.bpf.c
 * @brief Data Plane Core - eBPFNetFlowLyzer
 * 
 * Intercepts network traffic at the NIC Driver level via XDP hooks.
 * Implements a Dual-Stack (IPv4/IPv6) stateful flow extraction engine.
 * 
 * @author Leonardo Herkenhoff (Scientific Research Partner)
 * @date 2026-04-18
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
 * @def MAX_ENTRIES
 * @brief Robust Connection Table limit for handling high-volume DDoS peaks.
 */
#define MAX_ENTRIES 131072 // Robust Connection Table limit for handling DDoS peaks

/**
 * @struct flow_event_t
 * @brief Telemetry structure transmitted to the User-Space RingBuffer.
 * 
 * Stores the core features extracted from each packet before statistical aggregation.
 * @note IPs are stored as 128-bit arrays to support IPv4-Mapped IPv6 (::ffff:0:0/96).
 */
struct flow_event_t {
    __u8 src_ip[16];   /**< 128-bit Source Address */
    __u8 dst_ip[16];   /**< 128-bit Destination Address */
    __u16 src_port;    /**< L4 Source Port */
    __u16 dst_port;    /**< L4 Destination Port */
    __u8 protocol;     /**< IP Protocol (TCP/UDP) */
    __u8 ip_ver;       /**< IP Version Helper (4 or 6) */
    
    __u16 payload_length; /**< Length of L4 Payload data */
    __u16 header_length;  /**< Length of L3+L4 headers */
    __u8 tcp_flags;       /**< Bitmap of tracked TCP flags (FIN|SYN|RST|PSH|ACK|URG) */
    __u64 timestamp_ns;   /**< Monotonic timestamp in nanoseconds */

    __u8 dns_payload_raw[256]; /**< Raw DNS payload buffer for L7 extraction */
};

/**
 * @struct flow_key_t
 * @brief 5-tuple lookup key for BPF Maps.
 */
struct flow_key_t {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct flow_stats_t {
    __u64 total_bytes;
    __u64 packet_count;
    __u64 start_time_ns;
    __u64 last_time_ns;
};

// 2. Maps Requested by the "Architecture Blueprint"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Requires heavy throughput. (256 KB)
} flows_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // Replaces the slow Python dictionaries
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key_t);      // 5-tuple key form
    __type(value, struct flow_stats_t);  // Atomic accounting for bytes and packets
} flow_state_cache SEC(".maps");

/**
 * @brief Main XDP Program Entry Point
 * 
 * Parsed Ethernet, IP, and L4 headers with strict boundary checks to satisfy
 * the eBPF Verifier. Implements Dual-Stack address mapping for O(1) flow state tracking.
 * 
 * @param ctx Pointer to the XDP metadata context.
 * @return XDP_PASS to allow the packet to the stack, as we are a passive extractor.
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

    // L3 Parser (Unified Dual-Stack)
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        ip_ver = 4;
        l4_proto = ip->protocol;
        
        // IPv4-Mapped IPv6: ::ffff:a.b.c.d
        src_ip[10] = 0xff; src_ip[11] = 0xff;
        *(__u32 *)&src_ip[12] = ip->saddr;
        
        dst_ip[10] = 0xff; dst_ip[11] = 0xff;
        *(__u32 *)&dst_ip[12] = ip->daddr;

    } else if (eth->h_proto == bpf_htons(0x86DD)) { // ETH_P_IPV6
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        ip_ver = 6;
        l4_proto = ip6->nexthdr;
        bpf_probe_read_kernel(src_ip, 16, &ip6->saddr);
        bpf_probe_read_kernel(dst_ip, 16, &ip6->daddr);
    } else {
        return XDP_PASS;
    }

    __u16 l4_payload_len = 0;
    __u16 l4_header_len = 0;
    __u16 tcp_flags_tracked = 0;
    __u16 sport = 0, dport = 0;
    void *l4_header = NULL;

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

    // Unified Hash Table Lookup
    __builtin_memcpy(search_key.src_ip, src_ip, 16);
    __builtin_memcpy(search_key.dst_ip, dst_ip, 16);
    search_key.src_port = sport;
    search_key.dst_port = dport;
    search_key.protocol = l4_proto;

    struct flow_stats_t *stats = bpf_map_lookup_elem(&flow_state_cache, &search_key);
    if (stats) {
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

    // Reserve RingBuf for safe asynchronous transmission to User-Space
    struct flow_event_t *event;
    event = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*event), 0);
    if (!event)
        return XDP_PASS; // Queue full - Apply Backpressure (Drop temporary stat)

    // Agreggate Event Metadata
    __builtin_memcpy(event->src_ip, src_ip, 16);
    __builtin_memcpy(event->dst_ip, dst_ip, 16);
    event->src_port = sport;
    event->dst_port = dport;
    event->protocol = l4_proto;
    event->ip_ver = ip_ver;
    event->tcp_flags = tcp_flags_tracked;
    event->payload_length = l4_payload_len;
    event->header_length = l4_header_len; // Simplified for Dual-Stack
    event->timestamp_ns = bpf_ktime_get_ns();
    
    // DNS Handling (L7 Payload push)
    if (l4_proto == IPPROTO_UDP && (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53)) {
        struct udphdr *udp = l4_header;
        void *payload = (void *)(udp + 1);
        __u32 copy_len = l4_payload_len;
        if (copy_len > 255) copy_len = 255; 

        if (payload + copy_len <= data_end) {
            bpf_probe_read_kernel(event->dns_payload_raw, copy_len & 0xFF, payload);
        }
    }
    
    bpf_ringbuf_submit(event, 0); // Dispatches event to user-space poller

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
