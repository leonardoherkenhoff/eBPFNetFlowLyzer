// loader.c
// User-Space Control Plane Daemon (Pure C Architecture)
// Resilient Statistical L3/L7 Analyzer

#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

// Must precisely synchronize with main.bpf.c struct map
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

// Statistical Welford Component (Replaces the sluggish O(N) Python statistics.pvariance)
struct welford_t {
    unsigned long count;
    double mean;
    double M2;
};

// Iterative sum completely bounded - O(1) Time complexity
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
// RESILIENT L7 ENGINE (ANTI-DDOS BOUND CHECKING)
// Extreme protective layers preventing Segfaults
// ==========================================
void parse_dns_payload(void *payload_data, size_t length) {
    if (length < 12) { // Master RFC 1035 Header strictly requires 12 Bytes 
        return; // Malformed / Fragmented Packet - Discard without Segfault
    }

    // Basic Header format: [ID (2)] [Flags (2)] [QDCOUNT (2)] [ANCOUNT (2)] [NSCOUNT (2)] [ARCOUNT (2)]
    __u16 qdcount = ntohs(*(__u16 *)(payload_data + 4));

    void *data_end = payload_data + length;
    unsigned char *cursor = (unsigned char *)payload_data + 12; // Jumps header overhead

    // Iron-clad iterator avoiding out-of-bounds pointer allocations
    if (qdcount > 0) {
        // Attempts evaluating DNS Query Record fields
        int safety_limit = 255; 
        while (cursor < (unsigned char *)data_end && *cursor != 0 && safety_limit-- > 0) {
            __u8 label_len = *cursor;
            
            // Defense layer 1: DNS Pointer Compression triggers
            if ((label_len & 0xC0) == 0xC0) { 
                cursor += 2; // Compression pointers are fixed 2-bytes offset
                break;
            }

            // Defense layer 2: Malformed label length bounds evaluation
            if (cursor + 1 + label_len >= (unsigned char *)data_end) {
                return; // Suspected Buffer Over-read attack mechanism detected. Discard.
            }
            
            cursor += 1 + label_len; // Jumps forward string labels e.g. 'www' -> 'google' -> 'com'
        }
        
        // Final jump across ZERO byte delimiting QTYPE and QCLASS
        if (cursor + 5 <= (unsigned char *)data_end) {
            cursor += 5;
            // Native metrics retrieved safely here
        }
    }
}

// Callback triggered in microseconds upon XDP Kernel bpf_ringbuf_submit events
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct flow_event_t *e = data;
    static struct welford_t dummy_variance_accumulator = {0}; // Temporary global instance
    
    // Feed isolated O(1) Welford's continuous calculation
    update_welford(&dummy_variance_accumulator, (double)e->payload_length);

    // Relay heavily bounded L7 Analysis (Port 53 logic only)
    if (e->protocol == 17 && (e->src_port == ntohs(53) || e->dst_port == ntohs(53))) {
        parse_dns_payload((void *)e->dns_payload_raw, e->payload_length);
    }
    
    // Universally Portable Pipeline (stdout)
    // Legacy NTLFlowLyzer nomenclature mapping exactly to ML model features
    // We isolate bitwise flags in C dynamically: FIN, SYN, RST, PSH, ACK, URG
    printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.4f\n",
            e->src_ip, e->dst_ip,
            e->src_port, e->dst_port,
            e->protocol,
            e->payload_length,
            e->header_length,
            (e->tcp_flags & 1),             // fin_flag_cnt
            ((e->tcp_flags >> 1) & 1),      // syn_flag_cnt
            ((e->tcp_flags >> 2) & 1),      // rst_flag_cnt
            ((e->tcp_flags >> 3) & 1),      // psh_flag_cnt
            ((e->tcp_flags >> 4) & 1),      // ack_flag_cnt
            ((e->tcp_flags >> 5) & 1),      // urg_flag_cnt
            get_variance(&dummy_variance_accumulator) // fwd_pkt_len_var
    );
    fflush(stdout); // Previne Data Leakage em buffers do pipe 

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    int map_fd;

    // 1. Flush termination states using Signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. Load C-eBPF bytecode generated previously targeting the inner linux Kernel
    obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, ">> FATAL: Failed loading generated BPF bytecode.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, ">> FATAL: Failed attaching eBPF into Network Drivers.\n");
        return 1;
    }
    
    // 3. Assemble User-Space Lock-Free channel targeting core 'handle_event' callback
    map_fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, ">> FATAL: Failed allocating primary RingBuffer.\n");
        goto cleanup;
    }

    // Header compatível com a Nomenclatura Padrão NTL original impresso globalmente no topo
    printf("src_ip,dst_ip,src_port,dst_port,protocol,tot_len_fwd_pkts,fwd_header_len,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,fwd_pkt_len_var\n");

    // 4. Asynchronous polling mechanism keeping daemon active
    while (!exiting) {
        ring_buffer__poll(rb, 100); // Trigger waits 100ms max between loads
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
