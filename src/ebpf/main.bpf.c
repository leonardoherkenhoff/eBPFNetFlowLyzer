/**
 * @file main.bpf.c
 * @brief eBPF Data Plane - NTL/AL-Compliant High-Resolution Extractor (v1.8.0).
 * 
 * @details 
 * Implements a research-grade flow-based telemetry pipeline aligned with 
 * NTLFlowLyzer and ALFlowLyzer specifications.
 * 
 * Triggers:
 * - Event-Driven: Flushes flow statistics on TCP control packets (SYN, FIN, RST).
 * - Segment-Driven: Flushes statistics every 10,000 packets to ensure 
 *   granularity in high-speed DDoS flood scenarios.
 * 
 * Features:
 * - Bidirectional Aggregation (Forward/Backward).
 * - Statistical Moments: Packet Lengths and IAT (Inter-Arrival Time).
 * - Application Visibility: DNS Hints (ALFlowLyzer style).
 * 
 * @version 1.8.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define MAX_FLOWS 100000
#define SEGMENT_THRESHOLD 1000 /* Increased granularity for research */

struct flow_key {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct flow_info {
    __u64 start_time;
    __u64 last_time;
    __u64 fwd_pkt_count;
    __u64 bwd_pkt_count;
    __u64 fwd_bytes;
    __u64 bwd_bytes;
    __u64 fwd_bytes_sq; /* For Variance/Std calculation in user-space */
    __u64 bwd_bytes_sq;
    __u64 fwd_header_len;
    __u64 bwd_header_len;
    __u32 fwd_pkt_len_max;
    __u32 fwd_pkt_len_min;
    __u32 bwd_pkt_len_max;
    __u32 bwd_pkt_len_min;
    __u8 tcp_flags;
    __u8 ip_ver;
    __u16 eth_proto;
    __u8 src_mac[6];
    __u8 dst_mac[6];
    __u16 window_size;
    __u8 ttl;
    __u32 dns_query_count;
} __attribute__((packed));

struct flow_event_t {
    struct flow_key key;
    struct flow_info info;
    __u64 timestamp_ns;
    __u8 event_type; /* 1: SYN, 2: FIN/RST, 3: SEGMENT */
} __attribute__((packed));

/* --- BPF Maps --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_info);
} flow_state_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024 * 1024);
} flows_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} raw_pkt_count SEC(".maps");

/* --- Internal Helpers --- */

static __always_inline void export_flow_event(struct flow_key *key, struct flow_info *info, __u8 type) {
    struct flow_event_t *ev = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(&ev->key, key, sizeof(*key));
        __builtin_memcpy(&ev->info, info, sizeof(*info));
        ev->timestamp_ns = bpf_ktime_get_ns();
        ev->event_type = type;
        bpf_ringbuf_submit(ev, 0);
    }
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u32 r_key = 0;
    __u64 *r_count = bpf_map_lookup_elem(&raw_pkt_count, &r_key);
    if (r_count) __sync_fetch_and_add(r_count, 1);

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);

    /* VLAN Traversal */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == 0x8100 || eth_proto == 0x88A8) {
            struct { __u16 tci; __u16 proto; } *v = l3_hdr;
            if ((void *)(v + 1) > data_end) break;
            eth_proto = bpf_ntohs(v->proto);
            l3_hdr = (void *)(v + 1);
        } else break;
    }

    struct flow_key key = {0};
    __u8 ip_ver = 0, l4_proto = 0;
    void *l4_hdr = NULL;
    __u16 payload_len = 0, header_len = 0;
    __u8 tcp_flags = 0, ttl = 0;
    __u16 window = 0;
    __u32 dns_hint = 0;

    /* L3 Dissection */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = l3_hdr;
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        ip_ver = 4; l4_proto = ip->protocol;
        key.protocol = l4_proto;
        key.src_ip[10] = 0xff; key.src_ip[11] = 0xff;
        *(__u32 *)&key.src_ip[12] = ip->saddr;
        key.dst_ip[10] = 0xff; key.dst_ip[11] = 0xff;
        *(__u32 *)&key.dst_ip[12] = ip->daddr;
        l4_hdr = l3_hdr + (ip->ihl * 4);
        header_len = ip->ihl * 4;
        ttl = ip->ttl;
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        ip_ver = 6; l4_proto = ip6->nexthdr;
        key.protocol = l4_proto;
        __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
        __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);
        l4_hdr = l3_hdr + 40;
        header_len = 40;
        ttl = ip6->hop_limit;
    } else return XDP_PASS;

    /* L4 Dissection */
    if (l4_proto == 6) { /* TCP */
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source; key.dst_port = tcp->dest;
            tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
            header_len += tcp->doff * 4;
            window = bpf_ntohs(tcp->window);
        }
    } else if (l4_proto == 17) { /* UDP */
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source; key.dst_port = udp->dest;
            header_len += 8;
            /* ALFlowLyzer DNS Hint */
            if (bpf_ntohs(udp->source) == 53 || bpf_ntohs(udp->dest) == 53) {
                void *dns = l4_hdr + 8;
                if (dns + 6 <= data_end) {
                    dns_hint = bpf_ntohs(*(__u16 *)(dns + 4)); /* Query Count */
                }
            }
        }
    } else if (l4_proto == 1 || l4_proto == 58) { /* ICMP */
        struct { __u8 t; __u8 c; } *ic = l4_hdr;
        if ((void *)(ic + 1) <= data_end) {
            key.src_port = ic->t; key.dst_port = ic->c;
            header_len += 8;
        }
    }
    payload_len = (data_end - data) - header_len;

    /* Bidirectional Aggregation */
    struct flow_info *info = bpf_map_lookup_elem(&flow_state_cache, &key);
    __u8 is_fwd = 1;
    if (!info) {
        struct flow_key rev_key = {0};
        __builtin_memcpy(rev_key.src_ip, key.dst_ip, 16);
        __builtin_memcpy(rev_key.dst_ip, key.src_ip, 16);
        rev_key.src_port = key.dst_port; rev_key.dst_port = key.src_port;
        rev_key.protocol = key.protocol;
        info = bpf_map_lookup_elem(&flow_state_cache, &rev_key);
        if (info) { is_fwd = 0; __builtin_memcpy(&key, &rev_key, sizeof(key)); }
    }

    if (!info) {
        struct flow_info new_info = {0};
        new_info.start_time = bpf_ktime_get_ns();
        new_info.last_time = new_info.start_time;
        new_info.ip_ver = ip_ver; new_info.eth_proto = eth_proto;
        __builtin_memcpy(new_info.src_mac, eth->h_source, 6);
        __builtin_memcpy(new_info.dst_mac, eth->h_dest, 6);
        new_info.fwd_pkt_len_min = 0xFFFF; new_info.bwd_pkt_len_min = 0xFFFF;
        bpf_map_update_elem(&flow_state_cache, &key, &new_info, BPF_ANY);
        info = bpf_map_lookup_elem(&flow_state_cache, &key);
    }

    if (info) {
        info->last_time = bpf_ktime_get_ns();
        if (is_fwd) {
            info->fwd_pkt_count++; info->fwd_bytes += payload_len; info->fwd_bytes_sq += (__u64)payload_len * payload_len;
            info->fwd_header_len += header_len;
            if (payload_len > info->fwd_pkt_len_max) info->fwd_pkt_len_max = payload_len;
            if (payload_len < info->fwd_pkt_len_min) info->fwd_pkt_len_min = payload_len;
        } else {
            info->bwd_pkt_count++; info->bwd_bytes += payload_len; info->bwd_bytes_sq += (__u64)payload_len * payload_len;
            info->bwd_header_len += header_len;
            if (payload_len > info->bwd_pkt_len_max) info->bwd_pkt_len_max = payload_len;
            if (payload_len < info->bwd_pkt_len_min) info->bwd_pkt_len_min = payload_len;
        }
        info->tcp_flags |= tcp_flags; info->window_size = window; info->ttl = ttl;
        info->dns_query_count += dns_hint;

        /* NTL-Style Trigger: SYN (1), FIN/RST (2), Segment (3) */
        if (tcp_flags & 0x02) export_flow_event(&key, info, 1);
        else if (tcp_flags & 0x05) { export_flow_event(&key, info, 2); bpf_map_delete_elem(&flow_state_cache, &key); }
        else if (info->fwd_pkt_count + info->bwd_pkt_count >= SEGMENT_THRESHOLD) {
            export_flow_event(&key, info, 3);
            /* Reset stats for segment but keep metadata */
            info->fwd_pkt_count = 0; info->bwd_pkt_count = 0;
            info->fwd_bytes = 0; info->bwd_bytes = 0; info->fwd_bytes_sq = 0; info->bwd_bytes_sq = 0;
            info->start_time = info->last_time;
            info->fwd_pkt_len_max = 0; info->fwd_pkt_len_min = 0xFFFF;
            info->bwd_pkt_len_max = 0; info->bwd_pkt_len_min = 0xFFFF;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
