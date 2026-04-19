/**
 * @file main.bpf.c
 * @brief eBPF Data Plane - Milestone 3: Dynamic Shared-Nothing Extractor (v1.9.8).
 * 
 * @details 
 * Arquitetura massivamente paralela baseada em Dynamic Map-in-Map RingBuffers.
 * Esta implementação resolve o problema de contenção em sistemas multi-core (NUMA)
 * ao particionar o canal de telemetria em buffers privados por CPU.
 * 
 * Formalismo Científico:
 * 1. Particionamento de Estado: Cada core $C_i$ possui um RingBuffer $RB_i$ exclusivo.
 * 2. Roteamento Atômico: Utiliza-se 'bpf_get_smp_processor_id()' para indexar 
 *    o 'pkt_ringbuf_map' (ARRAY_OF_MAPS), garantindo Lockless Ingestion.
 * 3. Fidelidade de Dados: Exportação atômica de eventos 'packet_event_t' para o
 *    ciclo autonômico MAPE-K em user-space.
 * 
 * @version 1.9.8 (Research Milestone 3 - Final)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* Constantes de Rede e Limites de Pesquisa */
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define MAX_FLOWS 200000
#define PAYLOAD_HINT_SIZE 64
#define MAX_CPUS 256

/**
 * @struct flow_key
 * @brief Identificador único de fluxo (5-tuple).
 */
struct flow_key {
    __u8 src_ip[16]; __u8 dst_ip[16];
    __u16 src_port; __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

/**
 * @struct flow_meta
 * @brief Metadados persistentes do fluxo capturados no primeiro pacote.
 */
struct flow_meta {
    __u64 start_time;
    __u8 ip_ver; __u16 eth_proto;
    __u8 src_mac[6]; __u8 dst_mac[6];
} __attribute__((packed));

/**
 * @struct packet_event_t
 * @brief Telemetria exportada para processamento estatístico em user-space.
 */
struct packet_event_t {
    struct flow_key key;
    struct flow_meta meta;
    __u32 payload_len; __u16 header_len;
    __u16 window_size; __u8 tcp_flags;
    __u8 ttl; __u8 is_fwd;
    __u64 timestamp_ns;
    __u8 icmp_type; __u8 icmp_code;
    __u8 payload_hint[PAYLOAD_HINT_SIZE];
} __attribute__((packed));

/**
 * @brief flow_registry: Tabela hash global para rastreamento de estado de fluxo.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_meta);
} flow_registry SEC(".maps");

/**
 * @brief inner_rb: Template para os RingBuffers dinâmicos (um por core).
 */
struct inner_map {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024); /* 32MB per core - Balanço entre RAM e Burst */
} inner_rb SEC(".maps");

/**
 * @brief pkt_ringbuf_map: Array de mapas que gerencia a distribuição per-CPU.
 * Implementa a estratégia Shared-Nothing para escalabilidade linear.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __array(values, struct inner_map);
} pkt_ringbuf_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);

    /* Travessia recursiva de VLAN (802.1Q/ad) */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == 0x8100 || eth_proto == 0x88A8) {
            struct { __u16 tci; __u16 proto; } *v = l3_hdr;
            if ((void *)(v + 1) > data_end) break;
            eth_proto = bpf_ntohs(v->proto); l3_hdr = (void *)(v + 1);
        } else break;
    }

    struct flow_key key = {0};
    __u8 ip_ver = 0, l4_proto = 0, ttl = 0, tcp_flags = 0;
    __u16 header_len = 0, window = 0;
    void *l4_hdr = NULL;

    /* Dissecção de Camada 3 (IPv4/IPv6) */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = l3_hdr; if ((void *)(ip + 1) > data_end) return XDP_PASS;
        ip_ver = 4; l4_proto = ip->protocol;
        *(__u32 *)&key.src_ip[12] = ip->saddr; *(__u32 *)&key.dst_ip[12] = ip->daddr;
        l4_hdr = l3_hdr + (ip->ihl * 4); header_len = ip->ihl * 4; ttl = ip->ttl;
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr; if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        ip_ver = 6; l4_proto = ip6->nexthdr;
        __builtin_memcpy(key.src_ip, &ip6->saddr, 16); __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);
        l4_hdr = l3_hdr + 40; header_len = 40; ttl = ip6->hop_limit;
    } else return XDP_PASS;

    key.protocol = l4_proto;

    /* Dissecção de Camada 4 (TCP/UDP) */
    if (l4_proto == 6) { /* TCP */
        struct tcphdr *tcp = l4_hdr; if ((void *)(tcp + 1) <= data_end) {
            key.src_port = tcp->source; key.dst_port = tcp->dest;
            tcp_flags = (tcp->fin) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
            header_len += tcp->doff * 4; window = bpf_ntohs(tcp->window);
        }
    } else if (l4_proto == 17) { /* UDP */
        struct udphdr *udp = l4_hdr; if ((void *)(udp + 1) <= data_end) {
            key.src_port = udp->source; key.dst_port = udp->dest; header_len += 8;
        }
    }

    /* Normalização de Fluxo Bidirecional */
    struct flow_meta *meta = bpf_map_lookup_elem(&flow_registry, &key);
    __u8 is_fwd = 1;
    if (!meta) {
        struct flow_key rk = {0}; rk.protocol = key.protocol; rk.src_port = key.dst_port; rk.dst_port = key.src_port;
        __builtin_memcpy(rk.src_ip, key.dst_ip, 16); __builtin_memcpy(rk.dst_ip, key.src_ip, 16);
        meta = bpf_map_lookup_elem(&flow_registry, &rk);
        if (meta) { is_fwd = 0; __builtin_memcpy(&key, &rk, sizeof(key)); }
    }

    /* Inicialização de Estado de Fluxo */
    if (!meta) {
        struct flow_meta new_m = {0}; new_m.start_time = bpf_ktime_get_ns();
        new_m.ip_ver = ip_ver; new_m.eth_proto = eth_proto;
        __builtin_memcpy(new_m.src_mac, eth->h_source, 6); __builtin_memcpy(new_m.dst_mac, eth->h_dest, 6);
        bpf_map_update_elem(&flow_registry, &key, &new_m, BPF_ANY);
        meta = bpf_map_lookup_elem(&flow_registry, &key);
    }

    /* Telemetria Descentralizada: Roteamento para RingBuffer privado do Core */
    __u32 cpu_id = bpf_get_smp_processor_id();
    void *rb = bpf_map_lookup_elem(&pkt_ringbuf_map, &cpu_id);
    if (rb) {
        struct packet_event_t *ev = bpf_ringbuf_reserve(rb, sizeof(*ev), 0);
        if (ev) {
            __builtin_memcpy(&ev->key, &key, sizeof(key)); if (meta) __builtin_memcpy(&ev->meta, meta, sizeof(*meta));
            ev->payload_len = (data_end - data) - header_len; ev->header_len = header_len;
            ev->window_size = window; ev->tcp_flags = tcp_flags; ev->ttl = ttl;
            ev->is_fwd = is_fwd; ev->timestamp_ns = bpf_ktime_get_ns();
            
            /* Hint L7: Primeiros 64 bytes para análise de Entropia */
            void *payload = data + header_len + sizeof(struct ethhdr);
            if (payload + PAYLOAD_HINT_SIZE <= data_end) __builtin_memcpy(ev->payload_hint, payload, PAYLOAD_HINT_SIZE);
            bpf_ringbuf_submit(ev, 0);
        }
    }

    /* Cleanup: Liberação de recursos em fluxos encerrados */
    if (tcp_flags & 0x05) bpf_map_delete_elem(&flow_registry, &key);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
