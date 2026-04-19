/**
 * @file main.bpf.c
 * @brief Data Plane Core - eBPF/XDP High-Performance Feature Extractor.
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
#define IPPROTO_GRE 47
#define IPPROTO_FRAGMENT 44
#define VXLAN_PORT 4789
#define MAX_ENTRIES 524288 

struct flow_event_t {
    __u8 src_ip[16]; __u8 dst_ip[16];
    __u16 src_port; __u16 dst_port;
    __u8 protocol; __u8 ip_ver;
    __u16 payload_length; __u16 header_length;
    __u8 tcp_flags; __u8 is_tunneled;
    __u8 sni_hostname[64]; __u8 ttl;
    __u16 window_size; __u64 timestamp_ns;
    __u8 dns_payload_raw[256];
} __attribute__((packed));

struct flow_key_t {
    __u8 src_ip[16]; __u8 dst_ip[16];
    __u16 src_port; __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct flow_stats_t {
    __u64 total_bytes __attribute__((aligned(8)));
    __u64 packet_count __attribute__((aligned(8)));
    __u64 start_time_ns __attribute__((aligned(8)));
    __u64 last_time_ns __attribute__((aligned(8)));
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u64);
} proto_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} raw_pkt_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024); 
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
        
        /* Mathematically Correct IPv6 Extension Skip (Verifier-Safe) */
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            if (*l4_proto == 0 || *l4_proto == 60 || *l4_proto == 43 || *l4_proto == 44) {
                struct { __u8 next; __u8 len; } *ext = next;
                if ((void *)(ext + 1) > data_end) break;
                *l4_proto = ext->next;
                // Total len = (ext->len + 1) * 8 octets.
                // We mask len to satisfy the verifier's bound tracking.
                __u16 delta = (ext->len + 1) << 3;
                if (delta > 128) delta = 128; // Hard limit for verifier safety
                next += delta;
            } else break;
        }
        *l4_hdr = next;
        return 0;
    }
    return -1;
}

static __always_inline void parse_sni(void *payload, void *data_end, __u8 *sni_out) {
    if (payload + 6 > data_end) return;
    __u8 *p = payload;
    if (p[0] != 0x16 || p[5] != 0x01) return;
    p += 44; if (p + 1 > data_end) return;
    __u8 sid_len = p[0]; if (sid_len > 32) sid_len = 32;
    p += 1 + sid_len; if (p + 2 > data_end) return;
    __u16 cs_len = bpf_ntohs(*(__u16 *)p); if (cs_len > 128) cs_len = 128;
    p += 2 + cs_len; if (p + 1 > data_end) return;
    __u8 cm_len = p[0]; if (cm_len > 32) cm_len = 32;
    p += 1 + cm_len; if (p + 2 > data_end) return;
    p += 2;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (p + 4 > data_end) break;
        __u16 type = bpf_ntohs(*(__u16 *)p);
        __u16 len = bpf_ntohs(*(__u16 *)(p + 2));
        p += 4;
        if (type == 0) {
            if (p + 5 > data_end) break;
            if (p[2] == 0) {
                __u16 hn_len = bpf_ntohs(*(__u16 *)(p + 3));
                p += 5;
                if (hn_len > 63) hn_len = 63;
                if (p + hn_len <= data_end) bpf_probe_read_kernel(sni_out, hn_len & 0x3F, p);
            }
            break;
        }
        if (len > 128) break;
        p += len;
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

    /* Handle LLC/SNAP */
    if (eth_proto < 1536) {
        if (l3_hdr + 8 > data_end) return XDP_PASS;
        __u8 *llc = l3_hdr;
        if (llc[0] == 0xAA && llc[1] == 0xAA) {
            eth_proto = bpf_ntohs(*(__u16 *)(llc + 6));
            l3_hdr += 8;
        } else return XDP_PASS;
    }

    /* Handle Multi-VLAN Tagging (QinQ) */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == 0x8100 || eth_proto == 0x88A8) {
            struct { __u16 tci; __u16 proto; } *v = l3_hdr;
            if ((void *)(v + 1) > data_end) break;
            eth_proto = bpf_ntohs(v->proto);
            l3_hdr = (void *)(v + 1);
        } else break;
    }

    __u64 *p_count = bpf_map_lookup_elem(&proto_stats, &eth_proto);
    if (p_count) __sync_fetch_and_add(p_count, 1);
    else { __u64 one = 1; bpf_map_update_elem(&proto_stats, &eth_proto, &one, BPF_ANY); }

    __u8 ip_ver = 0, l4_proto = 0, is_tun = 0, ttl = 0;
    __u8 src_ip[16] = {0}, dst_ip[16] = {0}, sni[64] = {0};
    __u16 win = 0; void *l4_hdr = NULL;

    if (parse_l3(l3_hdr, data_end, bpf_htons(eth_proto), src_ip, dst_ip, &l4_proto, &ip_ver, &l4_hdr) != 0)
        return XDP_PASS;

    __u16 pay_len = 0, head_len = 0, flags = 0, sport = 0, dport = 0;
    void *payload = NULL;

    if (l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr; if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        sport = tcp->source; dport = tcp->dest; head_len = tcp->doff * 4;
        flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
        payload = (void *)tcp + head_len;
        if (ip_ver == 4) pay_len = bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - head_len;
        else pay_len = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - head_len;
        ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
        win = bpf_ntohs(tcp->window);
        if (bpf_ntohs(dport) == 443 || bpf_ntohs(sport) == 443) parse_sni(payload, data_end, sni);
    } else if (l4_proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr; if ((void *)(udp + 1) > data_end) return XDP_PASS;
        sport = udp->source; dport = udp->dest; head_len = 8;
        if (ip_ver == 4) pay_len = bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - head_len;
        else pay_len = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - 8;
        ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
    } else if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        struct { __u8 t; __u8 c; __u16 chk; } *ic = l4_hdr;
        if ((void *)(ic + 1) > data_end) return XDP_PASS;
        sport = ic->t; dport = ic->c; 
        if (ic->t == 8 || ic->t == 0 || ic->t == 128 || ic->t == 129) {
             struct { __u8 t; __u8 c; __u16 chk; __u16 id; __u16 seq; } *echo = l4_hdr;
             if ((void *)(echo + 1) <= data_end) sport = bpf_ntohs(echo->id); 
        }
        head_len = 8;
        if (ip_ver == 4) pay_len = bpf_ntohs(((struct iphdr *)l3_hdr)->tot_len) - (((struct iphdr *)l3_hdr)->ihl * 4) - head_len;
        else pay_len = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - head_len;
        ttl = (ip_ver == 4) ? ((struct iphdr *)l3_hdr)->ttl : ((struct ipv6hdr *)l3_hdr)->hop_limit;
    } else if (l4_proto == IPPROTO_FRAGMENT) {
        sport = 0; dport = 0; head_len = 8;
        pay_len = bpf_ntohs(((struct ipv6hdr *)l3_hdr)->payload_len) - 8;
        ttl = ((struct ipv6hdr *)l3_hdr)->hop_limit;
    } else return XDP_PASS;

    struct flow_key_t k = {0};
    __builtin_memcpy(k.src_ip, src_ip, 16); __builtin_memcpy(k.dst_ip, dst_ip, 16);
    k.src_port = sport; k.dst_port = dport; k.protocol = l4_proto;

    struct flow_stats_t *s = bpf_map_lookup_elem(&flow_state_cache, &k);
    if (s) {
        __sync_fetch_and_add(&s->packet_count, 1);
        __sync_fetch_and_add(&s->total_bytes, pay_len);
        s->last_time_ns = bpf_ktime_get_ns();
    } else {
        struct flow_stats_t ns = { .total_bytes = pay_len, .packet_count = 1, .start_time_ns = bpf_ktime_get_ns() };
        ns.last_time_ns = ns.start_time_ns;
        bpf_map_update_elem(&flow_state_cache, &k, &ns, BPF_ANY);
    }

    struct flow_event_t *ev = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*ev), 0);
    if (!ev) {
        __u32 k0 = 0; __u64 *c = bpf_map_lookup_elem(&drop_counter, &k0);
        if (c) __sync_fetch_and_add(c, 1);
        return XDP_PASS;
    }
    __builtin_memcpy(ev->src_ip, src_ip, 16); __builtin_memcpy(ev->dst_ip, dst_ip, 16);
    ev->src_port = sport; ev->dst_port = dport; ev->protocol = l4_proto; ev->ip_ver = ip_ver;
    ev->payload_length = pay_len; ev->header_length = head_len;
    ev->tcp_flags = (__u8)flags; ev->is_tunneled = is_tun; ev->timestamp_ns = bpf_ktime_get_ns();
    ev->ttl = ttl; ev->window_size = win;
    __builtin_memcpy(ev->sni_hostname, sni, 64);
    if (l4_proto == 17 && (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53)) {
        void *dns_p = (void *)l4_hdr + 8;
        if (dns_p + 256 <= data_end) bpf_probe_read_kernel(ev->dns_payload_raw, 256, dns_p);
    }
    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
