/**
 * @file main.bpf.c
 * @brief Lynceus Data Plane - High-Fidelity Unified Protocol Dissector.
 * 
 * @details 
 * Implements a research-grade packet interception pipeline in kernel-space 
 * using eBPF/XDP. Designed for absolute protocol visibility and high-throughput 
 * telemetry generation. Utilizes iterative VLAN traversal and recursive tunnel 
 * decapsulation to ensure zero-blind-spot monitoring.
 * 
 * @author Leonardo Herkenhoff (Senior Research Partner)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/** @brief Protocol Constants and Limits */
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_GRE 47
#define VXLAN_PORT 4789
#define PAYLOAD_HINT_SIZE 64

/**
 * @brief 5-Tuple Flow Identification Key.
 * @details Uniquely identifies a bidirectional session across the network fabric.
 */
struct flow_key {
    uint8_t src_ip[16]; /**< Source IP address (128-bit mapped) */
    uint8_t dst_ip[16]; /**< Destination IP address (128-bit mapped) */
    uint16_t src_port;  /**< Source L4 port or ICMP Echo ID */
    uint16_t dst_port;  /**< Destination L4 port or ICMP Code */
    uint8_t protocol;   /**< L4 Protocol identifier (IANA) */
} __attribute__((packed));

/**
 * @brief Immutable Flow Metadata.
 * @details Captured during the first packet seen in a new flow session.
 */
struct flow_meta {
    uint64_t start_time;    /**< Inception timestamp in nanoseconds */
    uint8_t ip_ver;         /**< IP Version (4 or 6) */
    uint16_t eth_proto;     /**< Outer EtherType (including QinQ/VLAN) */
    uint8_t src_mac[6];     /**< Source Layer-2 address */
    uint8_t dst_mac[6];     /**< Destination Layer-2 address */
} __attribute__((packed));

/**
 * @brief Telemetry Event Record.
 * @details Binary structure pushed to user-space via core-private RingBuffers.
 */
struct packet_event_t {
    struct flow_key key;    /**< Flow identification 5-tuple */
    struct flow_meta meta;  /**< Historical flow context */
    uint32_t payload_len;   /**< L4 payload length (excluding headers) */
    uint16_t header_len;    /**< Total protocol overhead (L2+L3+L4) */
    uint16_t window_size;   /**< TCP Receive Window value */
    uint8_t tcp_flags;      /**< Accumulated TCP control bits */
    uint8_t ttl;            /**< Time-to-Live or Hop Limit */
    uint8_t is_fwd;         /**< Directionality bit (1=Source->Dest) */
    uint64_t timestamp_ns;  /**< High-precision capture timestamp */
    uint8_t icmp_type;      /**< ICMP message type */
    uint8_t icmp_code;      /**< ICMP message code */
    uint16_t dns_answer_count; /**< RFC 1035 Answer count hint */
    uint8_t payload_hint[PAYLOAD_HINT_SIZE]; /**< Initial 64 bytes of payload for entropy analysis */
} __attribute__((packed));

/** 
 * @brief Global Flow Registry.
 * @details Maintains historical state for active sessions to ensure directionality tracking.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct flow_meta);
} flow_registry SEC(".maps");

/**
 * @brief Core-Private RingBuffer Map-in-Map.
 * @details Array of RingBuffer pointers to ensure absolute core-private isolation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 256); 
    __type(key, uint32_t);
    __type(value, uint32_t); 
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 32 * 1024 * 1024);
    });
} pkt_ringbuf_map SEC(".maps");

/**
 * @brief Recursive L3 Parser for Nested Protocols.
 * @details Decodes standard and encapsulated IP headers with MTU boundary checks.
 * @return 0 on successful dissection, -1 on bounds violation or unknown protocol.
 */
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

/**
 * @brief Main XDP Ingress Program.
 * @details Executes iterative QinQ traversal, recursive tunnel decapsulation (GRE/VXLAN), 
 * and L4 state extraction. Telemetry is flushed to user-space workers via core-pinned RingBuffers.
 */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    uint16_t eth_proto = eth->h_proto;
    void *l3_hdr = (void *)(eth + 1);

    /* Iterative VLAN QinQ Traversal (802.1Q/802.1ad) */
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

    /* Recursive Tunnel Decapsulation (RFC 2784 - GRE) */
    if (l4_p == IPPROTO_GRE) {
        struct { uint16_t flags; uint16_t proto; } *gre = l4_h;
        if ((void *)(gre + 1) > data_end) return XDP_PASS;
        l3_hdr = (void *)(gre + 1);
        if (parse_l3(l3_hdr, data_end, gre->proto, src, dst, &ver, &l4_p, &l4_h, &h_len, &ttl) != 0) return XDP_PASS;
    }

    uint16_t sport = 0, dport = 0, win = 0, dns_ans = 0;
    uint8_t flags = 0;

    /* Protocol Dissection & Flow State Extraction */
    if (l4_p == 6) { /* TCP RFC 793 */
        struct tcphdr *tcp = l4_h; if ((void *)(tcp + 1) <= data_end) {
            sport = tcp->source; dport = tcp->dest;
            flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5) | (tcp->ece << 6) | (tcp->cwr << 7);
            h_len += tcp->doff * 4; win = bpf_ntohs(tcp->window);
        }
    } else if (l4_p == 17 || l4_p == 132) { /* UDP RFC 768 / SCTP RFC 4960 */
        struct udphdr *udp = l4_h; if ((void *)(udp + 1) <= data_end) {
            sport = udp->source; dport = udp->dest; h_len += 8;
            /* Recursive VXLAN Decapsulation (RFC 7348) */
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
            /* DNS Answer Count Extraction (RFC 1035) */
            if (sport == bpf_htons(53) || dport == bpf_htons(53)) {
                void *dns = l4_h + 8; if (dns + 8 <= data_end) dns_ans = bpf_ntohs(*(uint16_t *)(dns + 6));
            }
        }
    } else if (l4_p == 1 || l4_p == 58) { /* ICMP/v6 RFC 792/4443 */
        struct icmphdr *icmp = l4_h; if ((void *)(icmp + 1) <= data_end) {
            sport = icmp->type; dport = icmp->code; h_len += 8;
            /* ICMP Echo ID Extraction for Flow Separation */
            if (icmp->type == 8 || icmp->type == 0 || icmp->type == 128 || icmp->type == 129) {
                struct { uint8_t t; uint8_t c; uint16_t k; uint16_t id; uint16_t s; } *echo = l4_h;
                if ((void *)(echo + 1) <= data_end) sport = echo->id;
            }
        }
    }

    struct flow_key key = {0}; key.protocol = l4_p; key.src_port = sport; key.dst_port = dport;
    __builtin_memcpy(key.src_ip, src, 16); __builtin_memcpy(key.dst_ip, dst, 16);

    /* Bidirectional Flow Registry Lookup */
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

    /* Core-Private Telemetry Dispatch */
    uint32_t cpu = bpf_get_smp_processor_id();
    void *rb = bpf_map_lookup_elem(&pkt_ringbuf_map, &cpu);
    if (!rb) return XDP_PASS;

    struct packet_event_t *ev = bpf_ringbuf_reserve(rb, sizeof(*ev), 0);
    if (ev) {
        __builtin_memcpy(&ev->key, &key, sizeof(key)); if (meta) __builtin_memcpy(&ev->meta, meta, sizeof(*meta));
        ev->payload_len = (data_end - data) - h_len - sizeof(struct ethhdr);
        ev->header_len = h_len; ev->window_size = win; ev->tcp_flags = flags;
        ev->ttl = ttl; ev->is_fwd = is_fwd; ev->timestamp_ns = bpf_ktime_get_ns();
        ev->icmp_type = (uint8_t)(ver == 4 ? (sport & 0xFF) : (sport & 0xFF)); 
        ev->icmp_code = (uint8_t)(dport & 0xFF);
        ev->dns_answer_count = dns_ans;
        void *payload = data + h_len + sizeof(struct ethhdr);
        if (payload + PAYLOAD_HINT_SIZE <= data_end) __builtin_memcpy(ev->payload_hint, payload, PAYLOAD_HINT_SIZE);
        bpf_ringbuf_submit(ev, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
