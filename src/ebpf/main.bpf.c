/**
 * @file main.bpf.c
 * @brief eBPF Data Plane - Streaming Feature Extractor (v1.9.0).
 * 
 * @details 
 * Implements a "Running Flow Telemetry" architecture. The kernel identifies 
 * bidirectional flows but exports an event for EVERY packet, enabling 
 * user-space to calculate progressive statistical moments (Welford's).
 * 
 * @version 1.9.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define MAX_FLOWS 100000

struct flow_key {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct flow_meta {
    __u64 start_time;
    __u8 ip_ver;
    __u16 eth_proto;
    __u8 src_mac[6];
    __u8 dst_mac[6];
} __attribute__((packed));

struct packet_event_t {
    struct flow_key key;
    struct flow_meta meta;
    __u32 payload_len;
    __u16 header_len;
    __u16 window_size;
    __u8 tcp_flags;
    __u8 ttl;
    __u8 is_fwd;
    __u64 timestamp_ns;
} __attribute__((packed));

/* --- BPF Maps --- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_meta);
} flow_registry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024 * 1024);
} pkt_ringbuf SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

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
    __u16 header_len = 0;
    __u8 tcp_flags = 0, ttl = 0;
    __u16 window = 0;

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
        }
    }
    
    /* Bidirectional Identification */
    struct flow_meta *meta = bpf_map_lookup_elem(&flow_registry, &key);
    __u8 is_fwd = 1;
    if (!meta) {
        struct flow_key rev_key = {0};
        __builtin_memcpy(rev_key.src_ip, key.dst_ip, 16);
        __builtin_memcpy(rev_key.dst_ip, key.src_ip, 16);
        rev_key.src_port = key.dst_port; rev_key.dst_port = key.src_port;
        rev_key.protocol = key.protocol;
        meta = bpf_map_lookup_elem(&flow_registry, &rev_key);
        if (meta) { is_fwd = 0; __builtin_memcpy(&key, &rev_key, sizeof(key)); }
    }

    if (!meta) {
        struct flow_meta new_meta = {0};
        new_meta.start_time = bpf_ktime_get_ns();
        new_meta.ip_ver = ip_ver; new_meta.eth_proto = eth_proto;
        __builtin_memcpy(new_meta.src_mac, eth->h_source, 6);
        __builtin_memcpy(new_meta.dst_mac, eth->h_dest, 6);
        bpf_map_update_elem(&flow_registry, &key, &new_meta, BPF_ANY);
        meta = bpf_map_lookup_elem(&flow_registry, &key);
    }

    /* Export Packet Event for Streaming Features */
    struct packet_event_t *ev = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(&ev->key, &key, sizeof(key));
        if (meta) __builtin_memcpy(&ev->meta, meta, sizeof(*meta));
        ev->payload_len = (data_end - data) - header_len;
        ev->header_len = header_len;
        ev->window_size = window;
        ev->tcp_flags = tcp_flags;
        ev->ttl = ttl;
        ev->is_fwd = is_fwd;
        ev->timestamp_ns = bpf_ktime_get_ns();
        bpf_ringbuf_submit(ev, 0);
    }

    /* Cleanup logic for FIN/RST to prevent map bloat */
    if (tcp_flags & 0x05) bpf_map_delete_elem(&flow_registry, &key);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
