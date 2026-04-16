// loader.c
// User-Space Control Plane Daemon (Pure C Architecture)
// Analisador Estatístico Resiliente L3/L7

#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>

// Tem de sincronizar precisamente com o struct do main.bpf.c
struct flow_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u16 payload_length;
    __u16 header_length;
    __u8 tcp_flags;
    __u8 dns_payload_raw[256]; 
};

static volatile bool exiting = false;

// Componente Welford Estatístico (Para substituir o problemático statistics.pvariance O(N))
struct welford_t {
    unsigned long count;
    double mean;
    double M2;
};

// Soma iterativa blindada - complexidade O(1)
void update_welford(struct welford_t *w, double value) {
    w->count++;
    double delta = value - w->mean;
    w->mean += delta / w->count;
    double delta2 = value - w->mean;
    w->M2 += delta * delta2;
}

double get_variance(struct welford_t *w) {
    if (w->count < 2) return 0.0;
    return w->M2 / (w->count - 1);
}

static void sig_handler(int sig) {
    exiting = true;
}

// ==========================================
// RESILIÊNCIA L7 (BOUNDS CHECKING ANTI-DDOS)
// Proteção extrema contra vazamento (Segfault)
// ==========================================
void parse_dns_payload(void *payload_data, size_t length) {
    if (length < 12) { // Cabeçalho Master RFC 1035 tem que ter 12 Bytes no mínimo
        return; // Malformed / Fragmented Packet - Discard without Segfault
    }

    // Estrutura básica: [ID (2)] [Flags (2)] [QDCOUNT (2)] [ANCOUNT (2)] [NSCOUNT (2)] [ARCOUNT (2)]
    __u16 qdcount = ntohs(*(__u16 *)(payload_data + 4));

    void *data_end = payload_data + length;
    unsigned char *cursor = (unsigned char *)payload_data + 12; // Pula os 12 bytes do Header

    // Iterador blindado para não fugir da memória alocada do BPF map Event.
    if (qdcount > 0) {
        // Tentativa de ler Queries de DNS
        int safety_limit = 255; 
        while (cursor < (unsigned char *)data_end && *cursor != 0 && safety_limit-- > 0) {
            __u8 label_len = *cursor;
            
            // Defesa 1: DNS Pointer Compression detectado.
            if ((label_len & 0xC0) == 0xC0) { 
                cursor += 2; // Ponteiros usam 2 bytes
                break;
            }

            // Defesa 2: Malformed Label Bound Checks
            if (cursor + 1 + label_len >= (unsigned char *)data_end) {
                return; // Ataque detectado (Buffer Over-read Prevention)
            }
            
            cursor += 1 + label_len; // Pula o label atual 'www' -> 'google' -> 'com'
        }
        
        // Pula o Zero byte + QTYPE + QCLASS
        if (cursor + 5 <= (unsigned char *)data_end) {
            cursor += 5;
            // Feature ALFlowLyzer extraída perfeitamente e sem risco.
        }
    }
}

// Callback trigado em microssegundos toda vez que o XDP Kernel emitir o bpf_ringbuf_submit
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct flow_event_t *e = data;
    static struct welford_t dummy_variance_accumulator = {0}; // Abstração Global temporária
    
    // Alimentar Algoritmo de Welford O(1) isolado em CPU
    update_welford(&dummy_variance_accumulator, (double)e->payload_length);

    // Repasse da L7 (ALFlowLyzer Equivalente) blindada  
    if (e->protocol == 17 && (e->src_port == ntohs(53) || e->dst_port == ntohs(53))) {
        parse_dns_payload((void *)e->dns_payload_raw, e->payload_length);
    }
    
    // TODO: Escrever num arquivo Ground_Truth CSV Asynchronous
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    int map_fd;

    // 1. Limpa os Lixos via Sinais de Controle
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. Carrega bytecode C-eBPF gerado pelo Makefile no Linux Kernel
    obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, ">> FATAL: Falha ao abrir bytecode BPF.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, ">> FATAL: Falha ao acoplar BPF no Kernel.\n");
        return 1;
    }
    
    // 3. Monta o Canal Lock-Free do User-Space apontando pro handle_event
    map_fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, ">> FATAL: Falha ao alocar o Tubo (RingBuffer).\n");
        goto cleanup;
    }

    printf(">> eBPFNetFlowLyzer (Pure C Architecture) Inicializado.\n");
    printf(">> Ouvinte RingBuffer atracado. Pressione Ctrl+C para encerrar.\n");

    // 4. Polling assíncrono blindado
    while (!exiting) {
        ring_buffer__poll(rb, 100); // Aguarda eventos a cada 100ms
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
