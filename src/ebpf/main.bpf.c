/**
 * @file main.bpf.c
 * @brief Lynceus Ultimate Data Plane - Unified Protocol Dissector (v2.2).
 * 
 * @details 
 * Versão final de alta fidelidade integrando:
 * 1. Decapsulamento de Túneis (GRE, VXLAN).
 * 2. Dissecção Granular ICMP (Type/Code + Echo ID).
 * 3. Traversal VLAN QinQ (802.1Q/ad).
 * 4. L7 Hints: DNS Query Counts e Payload Entropy.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_GRE 47
#define VXLAN_PORT 4789
#define PAYLOAD_HINT_SIZE 64

struct flow_key {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_meta {
    uint64_t start_time;
    uint8_t ip_ver; uint16_t eth_proto;
    uint8_t src_mac[6]; uint8_t dst_mac[6];
} __attribute__((packed));

struct packet_event_t {
    struct flow_key key;
    struct flow_meta meta;
    uint32_t payload_len; uint16_t header_len;
    uint16_t window_size; uint8_t tcp_flags;
    uint8_t ttl; uint8_t is_fwd;
    uint64_t timestamp_ns;
    uint8_t icmp_type; uint8_t icmp_code;
    uint16_t dns_answer_count;
    uint8_t payload_hint[PAYLOAD_HINT_SIZE];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_meta);
} flow_registry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, int);
} pkt_ringbuf_map SEC(".maps");

static __always_inline int parse_l3(void *data, void *data_end, uint16_t proto, 
                                   uint8_t *src, uint8_t *dst, uint8_t *ver, uint8_t *l4_p, void **l4_h, uint16_t *h_len, uint8_t *ttl) {
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data; if ((void *)(ip + 1) > data_end) return -1;
        *ver = 4; *l4_p = ip->protocol; *ttl = ip->ttl; *h_len = ip->ihl * 4;
        *l4_h = data + (ip->ihl * 4);
        __builtin_memset(src, 0, 12); __builtin_memset(dst, 0, 12);
        *(__u32 *)&src[12] = ip->saddr; *(__u32 *)&dst[12] = ip->daddr;
        return 0;
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data; if ((void *)(ip6 + 1) > data_end) return -1;
        *ver = 6; *l4_p = ip6->nexthdr; *ttl = ip6->hop_limit; *h_len = 40;
        *l4_h = data + 40;
        __builtin_memcpy(src, &ip6->saddr, 16); __builtin_memcpy(dst, &ip6->daddr, 16);
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

    uint16_t eth_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    /* 1. VLAN QinQ Traversal */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == bpf_htons(0x8100) || eth_proto == bpf_htons(0x88A8)) {
            struct { uint16_t tci; uint16_t proto; } *v = l3_hdr;
            if ((void *)(v + 1) > data_end) break;
            eth_proto = v->proto; l3_hdr = (void *)(v + 1);
        } else break;
    }

    uint8_t ver, l4_p, ttl;
    uint8_t src[16], dst[16];
    uint16_t h_len = 0;
    void *l4_h = NULL;

    if (parse_l3(l3_hdr, data_end, eth_proto, src, dst, &ver, &l4_p, &l4_h, &h_len, &ttl) != 0) return XDP_PASS;

    /* 2. Tunnel Decapsulation (GRE) */
    if (l4_p == IPPROTO_GRE) {
        struct { uint16_t flags; uint16_t proto; } *gre = l4_h;
        if ((void *)(gre + 1) > data_end) return XDP_PASS;
        l3_hdr = (void *)(gre + 1);
        if (parse_l3(l3_hdr, data_end, gre->proto, src, dst, &ver, &l4_p, &l4_h, &h_len, &ttl) != 0) return XDP_PASS;
    }

    uint16_t sport = 0, dport = 0, win = 0, dns_ans = 0;
    uint8_t flags = 0;

    /* 3. L4 Dissection & ICMP Granularity */
    if (l4_p == 6) { /* TCP */
        struct tcphdr *tcp = l4_h; if ((void *)(tcp + 1) <= data_end) {
            sport = tcp->source; dport = tcp->dest;
            flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
            h_len += tcp->doff * 4; win = bpf_ntohs(tcp->window);
        }
    } else if (l4_p == 17) { /* UDP */
        struct udphdr *udp = l4_h; if ((void *)(udp + 1) <= data_end) {
            sport = udp->source; dport = udp->dest; h_len += 8;
            /* VXLAN Decapsulation */
            if (dport == bpf_htons(VXLAN_PORT)) {
                struct { uint32_t f; uint32_t v; } *vx = (void *)(udp + 1);
                if ((void *)(vx + 1) <= data_end) {
                    struct ethhdr *ie = (void *)(vx + 1);
                    if ((void *)(ie + 1) <= data_end) {
                        l3_hdr = (void *)(ie + 1);
                        if (parse_l3(l3_hdr, data_end, ie->h_proto, src, dst, &ver, &l4_p, &l4_h, &h_len, &ttl) == 0) {
                            if (l4_p == 6) { struct tcphdr *it = l4_h; if ((void *)(it + 1) <= data_end) { sport = it->source; dport = it->dest; flags = (it->syn << 1); } }
                            else if (l4_p == 17) { struct udphdr *iu = l4_h; if ((void *)(iu + 1) <= data_end) { sport = iu->source; dport = iu->dest; } }
                        }
                    }
                }
            }
            /* DNS Hint */
            if (sport == bpf_htons(53) || dport == bpf_htons(53)) {
                void *dns = l4_h + 8; if (dns + 8 <= data_end) dns_ans = bpf_ntohs(*(uint16_t *)(dns + 6));
            }
        }
    } else if (l4_p == 1 || l4_p == 58) { /* ICMP/v6 */
        struct icmphdr *icmp = l4_h; if ((void *)(icmp + 1) <= data_end) {
            sport = icmp->type; dport = icmp->code; h_len += 8;
            /* ICMP Echo ID Granularity */
            if (icmp->type == 8 || icmp->type == 0 || icmp->type == 128 || icmp->type == 129) {
                struct { uint8_t t; uint8_t c; uint16_t k; uint16_t id; uint16_t s; } *echo = l4_h;
                if ((void *)(echo + 1) <= data_end) sport = echo->id;
            }
        }
    }

    struct flow_key key = {0}; key.protocol = l4_p; key.src_port = sport; key.dst_port = dport;
    __builtin_memcpy(key.src_ip, src, 16); __builtin_memcpy(key.dst_ip, dst, 16);

    struct flow_meta *meta = bpf_map_lookup_elem(&flow_registry, &key);
    uint8_t is_fwd = 1;
    if (!meta) {
        struct flow_key rk = {0}; rk.protocol = key.protocol; rk.src_port = key.dst_port; rk.dst_port = key.src_port;
        __builtin_memcpy(rk.src_ip, key.dst_ip, 16); __builtin_memcpy(rk.dst_ip, key.src_ip, 16);
        meta = bpf_map_lookup_elem(&flow_registry, &rk);
        if (meta) { is_fwd = 0; __builtin_memcpy(&key, &rk, sizeof(key)); }
    }

    if (!meta) {
        struct flow_meta nm = {0}; nm.start_time = bpf_ktime_get_ns(); nm.ip_ver = ver; nm.eth_proto = eth_proto;
        __builtin_memcpy(nm.src_mac, eth->h_source, 6); __builtin_memcpy(nm.dst_mac, eth->h_dest, 6);
        bpf_map_update_elem(&flow_registry, &key, &nm, BPF_ANY);
        meta = bpf_map_lookup_elem(&flow_registry, &key);
    }

    uint32_t cpu = bpf_get_smp_processor_id();
    int *rb_fd = bpf_map_lookup_elem(&pkt_ringbuf_map, &cpu);
    if (!rb_fd) return XDP_PASS;

    struct packet_event_t *ev = bpf_ringbuf_reserve((void *)(long)*rb_fd, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(&ev->key, &key, sizeof(key)); if (meta) __builtin_memcpy(&ev->meta, meta, sizeof(*meta));
        ev->payload_len = (data_end - data) - h_len - sizeof(struct ethhdr);
        ev->header_len = h_len; ev->window_size = win; ev->tcp_flags = flags;
        ev->ttl = ttl; ev->is_fwd = is_fwd; ev->timestamp_ns = bpf_ktime_get_ns();
        ev->icmp_type = (uint8_t)(sport & 0xFF); ev->icmp_code = (uint8_t)(dport & 0xFF);
        ev->dns_answer_count = dns_ans;
        void *payload = data + h_len + sizeof(struct ethhdr);
        if (payload + PAYLOAD_HINT_SIZE <= data_end) __builtin_memcpy(ev->payload_hint, payload, PAYLOAD_HINT_SIZE);
        bpf_ringbuf_submit(ev, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
