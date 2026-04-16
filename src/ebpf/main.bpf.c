// main.bpf.c
// Data Plane Core - eBPFNetFlowLyzer
// Intercepts traffic at the NIC Driver level via XDP hooks to prevent DDoS propagation

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

#define MAX_ENTRIES 131072 // Robust Connection Table limit for handling DDoS peaks

// 1. Packet structure transmitted to the RingBuffer (Telemetry Dump)
struct flow_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    
    __u16 payload_length;
    __u16 header_length;
    __u8 tcp_flags;

    // Flexible buffer space for rapid L7 copy restricted to L4 DNS (Port 53)
    __u8 dns_payload_raw[256]; 
};

struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
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

// 3. Program Triggered directly at the Network Card
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // L2 Parser (Ethernet)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // L3 Parser (IP)
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // We only process IPv4 for the Thesis prediction model
    if (ip->version != 4)
        return XDP_PASS;

    __u16 l4_payload_len = 0;
    __u16 tcp_flags_tracked = 0;
    __u16 sport = 0, dport = 0;
    __u8 l4_proto = ip->protocol;

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        sport = tcp->source;
        dport = tcp->dest;
        
        // Instant atomic binary extraction (Replaces slow loops from legacy tools)
        tcp_flags_tracked = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        l4_payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);

    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        sport = udp->source;
        dport = udp->dest;
        l4_payload_len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
    } else {
        return XDP_PASS; // Discard ICMP and other unsupported protocols
    }

    // LRU Hash Table Lookup & Update (Completely zeroes out O(N) Python Checkings)
    struct flow_key_t search_key = {0};
    search_key.src_ip = ip->saddr;
    search_key.dst_ip = ip->daddr;
    search_key.src_port = sport;
    search_key.dst_port = dport;
    search_key.protocol = l4_proto;

    struct flow_stats_t *stats = bpf_map_lookup_elem(&flow_state_cache, &search_key);
    if (stats) {
        // Atomic update for active flows
        __sync_fetch_and_add(&stats->total_bytes, l4_payload_len);
        __sync_fetch_and_add(&stats->packet_count, 1);
        stats->last_time_ns = bpf_ktime_get_ns();
    } else {
        // Initialize state for new flow
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
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = sport;
    event->dst_port = dport;
    event->protocol = l4_proto;
    event->tcp_flags = tcp_flags_tracked;
    event->payload_length = l4_payload_len;
    event->header_length = (ip->ihl * 4) + (l4_proto == IPPROTO_TCP ? ((struct tcphdr *)((void *)ip + (ip->ihl * 4)))->doff * 4 : sizeof(struct udphdr));
    
    // DNS Handling (L7 Payload push)
    // Strict byte allocation to prevent infinite loop errors from the BPF Verifier
    if (l4_proto == IPPROTO_UDP && (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53)) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        void *payload = (void *)(udp + 1);
        __u32 copy_len = l4_payload_len;
        if (copy_len > 255) copy_len = 255; // Hard limit array allocation

        // Prevent stalling the NIC with large reads
        if (payload + copy_len <= data_end) {
            bpf_probe_read_kernel(event->dns_payload_raw, copy_len & 0xFF, payload);
        }
    }
    
    bpf_ringbuf_submit(event, 0); // Dispatches event to user-space poller

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
