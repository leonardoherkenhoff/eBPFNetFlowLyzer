// main.bpf.c
// Data Plane Core - eBPFNetFlowLyzer
// Atua retendo ataques em NIC Driver level via arquitetura XDP

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 131072 // Tamanho robusto da Tabela de Conexões para DDoS

// 1. Estrutura do Pacote a Transmitir para o RingBuffer (O "Telemetry Dump")
struct flow_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    
    __u16 payload_length;
    __u16 header_length;
    __u8 tcp_flags;

    // Espaço flexível do buffer para cópia rápida do L7 apenas na porta L4 DNS (53)
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

// 2. Os Mapas Requisitados pela "Matriz de Arquitetura"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Exige canal de vazão pesada. (256 KB)
} flows_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // Substituto do Dicionário __ongoing_flows Python
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key_t);      // 5-tuple
    __type(value, struct flow_stats_t);  // Contabilidade atômica de bytes e pacotes
} flow_state_cache SEC(".maps");

// 3. O Programa Engatilhado na Placa
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parser L2 (Ethernet)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parser L3 (IP)
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Apenas passamos IPv4 para a predição da sua Tese
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
        
        // Coleta binária instantânea e mascarada L4 (Substitui loops do NTLFlowLyzer)
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
        return XDP_PASS; // Escarta ICMP e outros 
    }

    // LRU Hash Table Lookup & Update (Zera completamente a verificação lerda de Timeouts Python O(N))
    struct flow_key_t search_key = {0};
    search_key.src_ip = ip->saddr;
    search_key.dst_ip = ip->daddr;
    search_key.src_port = sport;
    search_key.dst_port = dport;
    search_key.protocol = l4_proto;

    struct flow_stats_t *stats = bpf_map_lookup_elem(&flow_state_cache, &search_key);
    if (stats) {
        // Atualiza atômico
        __sync_fetch_and_add(&stats->total_bytes, l4_payload_len);
        __sync_fetch_and_add(&stats->packet_count, 1);
        stats->last_time_ns = bpf_ktime_get_ns();
    } else {
        // Inicializa o state deste fluxo
        struct flow_stats_t new_stats = {0};
        new_stats.total_bytes = l4_payload_len;
        new_stats.packet_count = 1;
        new_stats.start_time_ns = bpf_ktime_get_ns();
        new_stats.last_time_ns = new_stats.start_time_ns;
        bpf_map_update_elem(&flow_state_cache, &search_key, &new_stats, BPF_ANY);
    }

    // Reserva RingBuf para transmissão segura ao User-Space
    struct flow_event_t *event;
    event = bpf_ringbuf_reserve(&flows_ringbuf, sizeof(*event), 0);
    if (!event)
        return XDP_PASS; // Fila cheia - Backpressure (Droppa estatística temporária para proteger rede)

    // Agregação da Tabela O(1) BPF
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = sport;
    event->dst_port = dport;
    event->protocol = l4_proto;
    event->tcp_flags = tcp_flags_tracked;
    event->payload_length = l4_payload_len;
    event->header_length = (ip->ihl * 4) + (l4_proto == IPPROTO_TCP ? ((struct tcphdr *)((void *)ip + (ip->ihl * 4)))->doff * 4 : sizeof(struct udphdr));
    
    // Tratativa DNS (L7 Payload Push) - Para offload no ALFlowLyzer Poller
    // Restrição dura de limite de bytes para BPF não sofrer loop infinito!
    if (l4_proto == IPPROTO_UDP && (bpf_ntohs(sport) == 53 || bpf_ntohs(dport) == 53)) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        void *payload = (void *)(udp + 1);
        __u32 copy_len = l4_payload_len;
        if (copy_len > 255) copy_len = 255; // Limite fixo de alocação de array para dns_payload_raw

        // BPF_PROBE_READ não pode travar a NIC com dados grandes.
        if (payload + copy_len <= data_end) {
            bpf_probe_read_kernel(event->dns_payload_raw, copy_len & 0xFF, payload);
        }
    }
    
    bpf_ringbuf_submit(event, 0); // Dispara pra C user-space

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
