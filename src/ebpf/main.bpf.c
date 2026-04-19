/**
 * @file main.bpf.c
 * @brief eBPF Data Plane - High-Resolution Stateless Packet Extractor.
 * 
 * @details 
 * Implements a non-aggregated network telemetry pipeline using XDP. Unlike 
 * traditional NetFlow-style extractors that aggregate packets into flows, 
 * this implementation treats every packet as a discrete research sample.
 * 
 * Architecture:
 * 1. L2 Dissection: Full visibility into EtherTypes (ARP, IPv4, IPv6, LLDP, etc.).
 * 2. L3/L4 Parsing: Recursive traversal of IPv6 Extension Headers and deep 
 *    inspection of TCP/UDP/ICMP fields.
 * 3. RingBuffer Submission: High-speed export of atomic packet events to 
 *    user-space without kernel-side state maintenance.
 * 
 * Target: High-entropy DDoS benchmark datasets (SBSeg 2026).
 * 
 * @version 1.5.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58
#define IPPROTO_FRAGMENT 44

/**
 * @struct flow_event_t
 * @brief Universal telemetry structure for per-packet research samples.
 */
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
    __u8 ttl;
    __u16 window_size; 
    __u64 timestamp_ns;
    __u16 eth_proto;      /**< High-visibility EtherType */
    __u8 src_mac[6];     /**< L2 Forensic visibility */
    __u8 dst_mac[6];
    __u8 sni_hostname[64];
    __u8 dns_payload_raw[256];
} __attribute__((packed));

/* --- BPF Maps --- */

/** @brief Diagnostic error tracking. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} error_stats SEC(".maps");

/** @brief Global packet counter. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} raw_pkt_count SEC(".maps");

/** @brief High-speed per-packet telemetry Ring Buffer. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024); 
} flows_ringbuf SEC(".maps");

/* --- Internal Helpers --- */

static __always_inline void count_error(__u32 code) {
    __u64 *val = bpf_map_lookup_elem(&error_stats, &code);
    if (val) __sync_fetch_and_add(val, 1);
    else { __u64 one = 1; bpf_map_update_elem(&error_stats, &code, &one, BPF_ANY); }
}

/**
 * @brief Parses L3 headers (IPv4/IPv6) with extension traversal.
 */
static __always_inline int parse_l3(void *data, void *data_end, __u16 eth_proto, 
                                   __u8 *src_ip, __u8 *dst_ip, __u8 *l4_proto, __u8 *ip_ver, void **l4_hdr) {
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data;
        if ((void *)(ip + 1) > data_end) return -1;
        *ip_ver = 4; *l4_proto = ip->protocol;
        src_ip[10] = 0xff; src_ip[11] = 0xff;
        *(__u32 *)&src_ip[12] = ip->saddr;
        dst_ip[10] = 0xff; dst_ip[11] = 0xff;
        *(__u32 *)&dst_ip[12] = ip->daddr;
        *l4_hdr = data + (ip->ihl * 4);
        return 0;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end) return -1;
        *ip_ver = 6; *l4_proto = ip6->nexthdr;
        __builtin_memcpy(src_ip, &ip6->saddr, 16);
        __builtin_memcpy(dst_ip, &ip6->daddr, 16);
        void *next = data + sizeof(struct ipv6hdr);
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (*l4_proto == 0 || *l4_proto == 60 || *l4_proto == 43 || *l4_proto == 44 || *l4_proto == 51) {
                struct { __u8 next; __u8 len; } *ext = next;
                if ((void *)(ext + 1) > data_end) break;
                __u8 cur_proto = *l4_proto;
                *l4_proto = ext->next;
                if (cur_proto == 44) next += 8;
                else next += (ext->len + 1) << 3;
            } else break;
        }
        *l4_hdr = next;
        return 0;
    }
    return -1; /* Non-IP traffic */
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    /* Global accounting */
    __u32 r_key = 0;
    __u64 *r_count = bpf_map_lookup_elem(&raw_pkt_count, &r_key);
    if (r_count) __sync_fetch_and_add(r_count, 1);

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);

    /* QinQ / VLAN Traversal */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == 0x8100 || eth_proto == 0x88A8) {
            struct { __u16 tci; __u16 proto; } *v = l3_hdr;
            if ((void *)(v + 1) > data_end) break;
            eth_proto = bpf_ntohs(v->proto);
            l3_hdr = (void *)(v + 1);
        } else break;
    }

    /* Initialize event */
    struct flow_event_t *ev = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*ev), 0);
    if (!ev) { count_error(6); return XDP_PASS; }

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->eth_proto = eth_proto;
    ev->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(ev->src_mac, eth->h_source, 6);
    __builtin_memcpy(ev->dst_mac, eth->h_dest, 6);

    __u8 ip_ver = 0, l4_proto = 0;
    __u8 src_ip[16] = {0}, dst_ip[16] = {0};
    void *l4_hdr = NULL;

    /* Dissect IP if applicable */
    if (parse_l3(l3_hdr, data_end, bpf_htons(eth_proto), src_ip, dst_ip, &l4_proto, &ip_ver, &l4_hdr) == 0) {
        __builtin_memcpy(ev->src_ip, src_ip, 16);
        __builtin_memcpy(ev->dst_ip, dst_ip, 16);
        ev->protocol = l4_proto;
        ev->ip_ver = ip_ver;

        /* Deep L4 dissection */
        if (l4_proto == 6) { /* TCP */
            struct tcphdr *tcp = l4_hdr; 
            if ((void *)(tcp + 1) <= data_end) {
                ev->src_port = tcp->source; ev->dst_port = tcp->dest;
                ev->header_length = tcp->doff * 4;
                ev->tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
                ev->window_size = bpf_ntohs(tcp->window);
                if (ip_ver == 4) ev->payload_length = bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - ev->header_length;
                else ev->payload_length = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - ev->header_length;
                ev->ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
            }
        } else if (l4_proto == 17) { /* UDP */
            struct udphdr *udp = l4_hdr;
            if ((void *)(udp + 1) <= data_end) {
                ev->src_port = udp->source; ev->dst_port = udp->dest;
                ev->header_length = 8;
                if (ip_ver == 4) ev->payload_length = bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - 8;
                else ev->payload_length = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - 8;
                ev->ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
            }
        } else if (l4_proto == 1 || l4_proto == 58) { /* ICMP */
            struct { __u8 t; __u8 c; } *ic = l4_hdr;
            if ((void *)(ic + 1) <= data_end) {
                ev->src_port = ic->t; ev->dst_port = ic->c;
                ev->header_length = 8;
                ev->ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
            }
        }
    } else {
        /* Raw Non-IP visibility */
        ev->payload_length = (data_end - l3_hdr);
    }

    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
