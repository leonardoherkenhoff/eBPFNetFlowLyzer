/**
 * @file main.bpf.c
 * @brief Data Plane Core - eBPFNetFlowLyzer (Kernel-Space)
 * 
 * High-performance packet interception engine using XDP.
 * Supports IPv4/IPv6 and TCP/UDP/ICMP/ICMPv6 protocols.
 * Enhanced with GRE and VXLAN tunneling decapsulation (v2.0).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#define VXLAN_PORT 4789
#define MAX_ENTRIES 131072 

struct flow_event_t {
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u16 src_port;    
    __u16 dst_port;    
    __u8 protocol;     
    __u8 ip_ver;       
    __u16 payload_length; 
    __u16 header_length;  
    __u8 tcp_flags;       
    __u8 is_tunneled;     
    __u64 timestamp_ns;   
    __u8 dns_payload_raw[256]; 
};

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

struct grehdr {
    __u16 flags;
    __u16 protocol;
} __attribute__((packed));

struct vxlanhdr {
    __u32 flags;
    __u32 vni;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} flows_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key_t);
    __type(value, struct flow_stats_t);
} flow_state_cache SEC(".maps");

static __always_inline int parse_l3(void *data, void *data_end, __u16 eth_proto, 
                                   __u8 *src_ip, __u8 *dst_ip, __u8 *l4_proto, __u8 *ip_ver, void **l4_hdr) {
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data;
        if ((void *)(ip + 1) > data_end) return -1;
        *ip_ver = 4;
        *l4_proto = ip->protocol;
        src_ip[10] = 0xff; src_ip[11] = 0xff;
        *(__u32 *)&src_ip[12] = ip->saddr;
        dst_ip[10] = 0xff; dst_ip[11] = 0xff;
        *(__u32 *)&dst_ip[12] = ip->daddr;
        *l4_hdr = data + (ip->ihl * 4);
        return 0;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end) return -1;
        *ip_ver = 6;
        *l4_proto = ip6->nexthdr;
        bpf_probe_read_kernel(src_ip, 16, &ip6->saddr);
        bpf_probe_read_kernel(dst_ip, 16, &ip6->daddr);
        *l4_hdr = data + sizeof(struct ipv6hdr);
        return 0;
    }
    return -1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u8 ip_ver = 0, l4_proto = 0, is_tunneled = 0;
    __u8 src_ip[16] = {0}, dst_ip[16] = {0};
    void *l3_hdr = (void *)(eth + 1);
    void *l4_hdr = NULL;

    if (parse_l3(l3_hdr, data_end, eth->h_proto, src_ip, dst_ip, &l4_proto, &ip_ver, &l4_hdr) != 0)
        return XDP_PASS;

    // --- Tunnel Decapsulation (GRE) ---
    if (l4_proto == IPPROTO_GRE) {
        struct grehdr *gre = l4_hdr;
        if ((void *)(gre + 1) > data_end) return XDP_PASS;
        is_tunneled = 1;
        l3_hdr = (void *)(gre + 1);
        if (parse_l3(l3_hdr, data_end, gre->protocol, src_ip, dst_ip, &l4_proto, &ip_ver, &l4_hdr) != 0)
            return XDP_PASS;
    }

    __u16 l4_payload_len = 0, l4_header_len = 0, tcp_flags = 0, sport = 0, dport = 0;

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        sport = tcp->source; dport = tcp->dest;
        l4_header_len = tcp->doff * 4;
        tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        l4_payload_len = (ip_ver == 4) ? 
            bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - l4_header_len :
            bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - l4_header_len;
    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        sport = udp->source; dport = udp->dest;
        l4_header_len = sizeof(struct udphdr);

        // --- Tunnel Decapsulation (VXLAN) ---
        if (dport == bpf_htons(VXLAN_PORT)) {
            struct vxlanhdr *vxlan = (void *)(udp + 1);
            if ((void *)(vxlan + 1) > data_end) return XDP_PASS;
            struct ethhdr *inner_eth = (void *)(vxlan + 1);
            if ((void *)(inner_eth + 1) > data_end) return XDP_PASS;
            is_tunneled = 1;
            l3_hdr = (void *)(inner_eth + 1);
            if (parse_l3(l3_hdr, data_end, inner_eth->h_proto, src_ip, dst_ip, &l4_proto, &ip_ver, &l4_hdr) != 0)
                return XDP_PASS;
            // Recursive L4 parsing for VXLAN payload (simplified to match outer logic)
            if (l4_proto == IPPROTO_TCP) {
                struct tcphdr *itcp = l4_hdr; if ((void *)(itcp + 1) > data_end) return XDP_PASS;
                sport = itcp->source; dport = itcp->dest; l4_header_len = itcp->doff * 4;
            } else if (l4_proto == IPPROTO_UDP) {
                struct iudphdr { __u16 s; __u16 d; __u16 l; __u16 c; } *iudp = l4_hdr;
                if ((void *)(iudp + 1) > data_end) return XDP_PASS;
                sport = iudp->s; dport = iudp->d; l4_header_len = 8;
            }
        }
        l4_payload_len = (ip_ver == 4) ? 
            bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - l4_header_len :
            bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len);
    } else if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        struct icmphdr *icmp = l4_hdr;
        if ((void *)(icmp + 1) > data_end) return XDP_PASS;
        sport = icmp->type; dport = icmp->code; l4_header_len = 8;
        l4_payload_len = (ip_ver == 4) ? 
            bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - l4_header_len :
            bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - l4_header_len;
    } else { return XDP_PASS; }

    struct flow_key_t key = {0};
    __builtin_memcpy(key.src_ip, src_ip, 16); __builtin_memcpy(key.dst_ip, dst_ip, 16);
    key.src_port = sport; key.dst_port = dport; key.protocol = l4_proto;

    struct flow_stats_t *stats = bpf_map_lookup_elem(&flow_state_cache, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_bytes, l4_payload_len);
        __sync_fetch_and_add(&stats->packet_count, 1);
        stats->last_time_ns = bpf_ktime_get_ns();
    } else {
        struct flow_stats_t ns = { .total_bytes = l4_payload_len, .packet_count = 1, 
                                   .start_time_ns = bpf_ktime_get_ns() };
        ns.last_time_ns = ns.start_time_ns;
        bpf_map_update_elem(&flow_state_cache, &key, &ns, BPF_ANY);
    }

    struct flow_event_t *ev = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*ev), 0);
    if (!ev) return XDP_PASS;
    __builtin_memcpy(ev->src_ip, src_ip, 16); __builtin_memcpy(ev->dst_ip, dst_ip, 16);
    ev->src_port = sport; ev->dst_port = dport; ev->protocol = l4_proto; ev->ip_ver = ip_ver;
    ev->payload_length = l4_payload_len; ev->header_length = l4_header_len;
    ev->tcp_flags = tcp_flags; ev->is_tunneled = is_tunneled; ev->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
