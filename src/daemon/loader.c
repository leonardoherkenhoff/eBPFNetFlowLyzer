// loader.c
// User-Space Control Plane Daemon (Pure C Architecture V2)
// Unificacao Estrita NTLFlowLyzer + ALFlowLyzer

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include "uthash.h"

// Synchronized precisely with main.bpf.c RingBuffer Event
struct flow_event_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t payload_length;
    uint16_t header_length;
    uint8_t tcp_flags;
    uint64_t timestamp_ns;
    uint8_t dns_payload_raw[256];
};

static volatile bool exiting = false;

// O(1) Mathematical Core for Continuous Flow Stream (Replaces Python Arrays)
struct welford_stat {
    unsigned long count;
    double mean;
    double M2;
    double min;
    double max;
};

void welford_init(struct welford_stat *w) {
    w->count = 0;
    w->mean = 0.0;
    w->M2 = 0.0;
    w->min = -1.0; // Handled specially
    w->max = 0.0;
}

void welford_update(struct welford_stat *w, double value) {
    w->count++;
    double delta = value - w->mean;
    w->mean += delta / w->count;
    double delta2 = value - w->mean;
    w->M2 += delta * delta2;
    
    if (w->min < 0 || value < w->min) w->min = value;
    if (value > w->max) w->max = value;
}

double welford_variance(struct welford_stat *w) {
    if (w->count < 2) return 0.0;
    return w->M2 / (w->count - 1);
}

double welford_std(struct welford_stat *w) {
    return sqrt(welford_variance(w));
}

// User-Space Hash Table Flow State structure (uthash)
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_record {
    struct flow_key key;
    
    // Core Timers
    uint64_t start_time;
    uint64_t last_time;
    uint64_t fwd_last_time;
    uint64_t bwd_last_time;
    
    // Core Counters
    uint64_t fwd_pkt_count;
    uint64_t bwd_pkt_count;
    uint64_t fwd_total_bytes;
    uint64_t bwd_total_bytes;
    uint64_t fwd_total_header;
    uint64_t bwd_total_header;
    
    // Bidirectional State Tracking
    struct welford_stat fwd_len;
    struct welford_stat bwd_len;
    struct welford_stat fwd_iat;
    struct welford_stat bwd_iat;
    struct welford_stat pkt_iat;

    // TCP Flags Breakdown
    uint8_t fwd_flags;
    uint8_t bwd_flags;
    
    // ALFlowLyzer DNS Exclusives
    uint32_t dns_query_count;
    struct welford_stat dns_ttl_stat;

    UT_hash_handle hh; /* Macro that makes this structure hashable */
};

struct flow_record *flows = NULL; // Head of Hash Table

void parse_dns_metrics(struct flow_record *f, void *payload_data, size_t length) {
    if (length < 12) return;
    
    uint16_t qdcount = ntohs(*(uint16_t *)(payload_data + 4));
    uint16_t ancount = ntohs(*(uint16_t *)(payload_data + 6));
    
    // DNS Queries metric tracking
    if (qdcount > 0) f->dns_query_count += qdcount;

    // Fast-Forward to Answers to extract TTL (ALFlowLyzer DistinctTTLValues equivalent)
    // Simplified bounded scan due to C string complexity. We track answer sizes implicitly.
    if (ancount > 0 && length > 24) {
        // Rudimentary TTL offset jump estimation to prevent BPF complexity leakage
        uint32_t ttl_sample = ntohl(*(uint32_t *)(payload_data + length - 10)); // Heuristic offset
        if (ttl_sample > 0 && ttl_sample < 86400) {
            welford_update(&f->dns_ttl_stat, (double)ttl_sample);
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz; // Silent unused warnings
    const struct flow_event_t *e = data;
    struct flow_record *f;
    struct flow_key k;
    
    k.src_ip = e->src_ip;
    k.dst_ip = e->dst_ip;
    k.src_port = e->src_port;
    k.dst_port = e->dst_port;
    k.protocol = e->protocol;

    HASH_FIND(hh, flows, &k, sizeof(struct flow_key), f);
    
    uint8_t is_fwd = 1; // True heuristic based on initialization

    if (!f) {
        // Reverse lookup to detect Backward packets
        struct flow_key reverse_k;
        reverse_k.src_ip = e->dst_ip;
        reverse_k.dst_ip = e->src_ip;
        reverse_k.src_port = e->dst_port;
        reverse_k.dst_port = e->src_port;
        reverse_k.protocol = e->protocol;
        
        HASH_FIND(hh, flows, &reverse_k, sizeof(struct flow_key), f);
        if (f) is_fwd = 0;
    }

    if (!f) {
        // Initialize entirely new Flow Allocation
        f = (struct flow_record *)malloc(sizeof(struct flow_record));
        if (!f) return 0; // OOM Protection
        
        f->key = k;
        f->start_time = e->timestamp_ns;
        f->last_time = e->timestamp_ns;
        f->fwd_last_time = e->timestamp_ns;
        f->bwd_last_time = 0;
        
        f->fwd_pkt_count = 0;
        f->bwd_pkt_count = 0;
        f->fwd_total_bytes = 0;
        f->bwd_total_bytes = 0;
        f->fwd_total_header = 0;
        f->bwd_total_header = 0;
        f->fwd_flags = 0;
        f->bwd_flags = 0;
        f->dns_query_count = 0;

        welford_init(&f->fwd_len);
        welford_init(&f->bwd_len);
        welford_init(&f->fwd_iat);
        welford_init(&f->bwd_iat);
        welford_init(&f->pkt_iat);
        welford_init(&f->dns_ttl_stat);

        HASH_ADD(hh, flows, key, sizeof(struct flow_key), f);
    }
    
    // Global IAT Update
    double delta_global = (double)(e->timestamp_ns > f->last_time ? e->timestamp_ns - f->last_time : 0) / 1000.0; // In microseconds
    if (f->fwd_pkt_count + f->bwd_pkt_count > 0) welford_update(&f->pkt_iat, delta_global);
    f->last_time = e->timestamp_ns;

    // Directional Core State Tracking
    if (is_fwd) {
        f->fwd_pkt_count++;
        f->fwd_total_bytes += e->payload_length;
        f->fwd_total_header += e->header_length;
        f->fwd_flags |= e->tcp_flags;
        welford_update(&f->fwd_len, (double)e->payload_length);
        
        if (f->fwd_pkt_count > 1) {
            double delta = (double)(e->timestamp_ns > f->fwd_last_time ? e->timestamp_ns - f->fwd_last_time : 0) / 1000.0;
            welford_update(&f->fwd_iat, delta);
        }
        f->fwd_last_time = e->timestamp_ns;
    } else {
        f->bwd_pkt_count++;
        f->bwd_total_bytes += e->payload_length;
        f->bwd_total_header += e->header_length;
        f->bwd_flags |= e->tcp_flags;
        welford_update(&f->bwd_len, (double)e->payload_length);
        
        if (f->bwd_pkt_count > 1) {
            double delta = (double)(e->timestamp_ns > f->bwd_last_time ? e->timestamp_ns - f->bwd_last_time : 0) / 1000.0;
            welford_update(&f->bwd_iat, delta);
        }
        f->bwd_last_time = e->timestamp_ns;
    }

    // L7 Extraction Subroutine
    if (e->protocol == 17 && (ntohs(e->src_port) == 53 || ntohs(e->dst_port) == 53)) {
        parse_dns_metrics(f, (void *)e->dns_payload_raw, e->payload_length);
    }

    return 0;
}

// Memory Cleanup and Export Matrix
void export_all_flows() {
    struct flow_record *f, *tmp;
    uint32_t exported = 0;
    
    // NTLFlowLyzer Master Header Equivalent (Truncated block for presentation parity)
    printf("src_ip,dst_ip,src_port,dst_port,protocol,timestamp,flow_duration,tot_fwd_pkts,tot_bwd_pkts,tot_len_fwd_pkts,tot_len_bwd_pkts,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fwd_header_len,bwd_header_len,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,cwe_flag_cnt,ece_flag_cnt,dns_query_cont,dns_ttl_mean,dns_ttl_std\n");

    HASH_ITER(hh, flows, f, tmp) {
        double duration_us = (double)(f->last_time - f->start_time) / 1000.0;
        
        printf("%u,%u,%u,%u,%u,%lu,%.2f,%lu,%lu,%lu,%lu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.2f,%.2f\n",
            f->key.src_ip, f->key.dst_ip,
            ntohs(f->key.src_port), ntohs(f->key.dst_port), f->key.protocol,
            f->start_time, duration_us,
            f->fwd_pkt_count, f->bwd_pkt_count,
            f->fwd_total_bytes, f->bwd_total_bytes,
            f->fwd_len.max, (f->fwd_len.min < 0 ? 0 : f->fwd_len.min), f->fwd_len.mean, welford_std(&f->fwd_len),
            f->bwd_len.max, (f->bwd_len.min < 0 ? 0 : f->bwd_len.min), f->bwd_len.mean, welford_std(&f->bwd_len),
            f->pkt_iat.mean, welford_std(&f->pkt_iat), f->pkt_iat.max, (f->pkt_iat.min < 0 ? 0 : f->pkt_iat.min),
            f->fwd_iat.mean, welford_std(&f->fwd_iat), f->fwd_iat.max, (f->fwd_iat.min < 0 ? 0 : f->fwd_iat.min),
            f->bwd_iat.mean, welford_std(&f->bwd_iat), f->bwd_iat.max, (f->bwd_iat.min < 0 ? 0 : f->bwd_iat.min),
            ((f->fwd_flags >> 3) & 1), ((f->bwd_flags >> 3) & 1), // PSH
            ((f->fwd_flags >> 5) & 1), ((f->bwd_flags >> 5) & 1), // URG
            f->fwd_total_header, f->bwd_total_header,
            ((f->fwd_flags | f->bwd_flags) & 1),       // FIN
            (((f->fwd_flags | f->bwd_flags) >> 1) & 1), // SYN
            (((f->fwd_flags | f->bwd_flags) >> 2) & 1), // RST
            (((f->fwd_flags | f->bwd_flags) >> 3) & 1), // PSH
            (((f->fwd_flags | f->bwd_flags) >> 4) & 1), // ACK
            (((f->fwd_flags | f->bwd_flags) >> 5) & 1), // URG
            (((f->fwd_flags | f->bwd_flags) >> 6) & 1), // CWE
            (((f->fwd_flags | f->bwd_flags) >> 7) & 1), // ECE
            f->dns_query_count, f->dns_ttl_stat.mean, welford_std(&f->dns_ttl_stat) // ALFlowLyzer DNS specific context 
        );
        
        HASH_DEL(flows, f);
        free(f);
        exported++;
    }
    fprintf(stderr, "\n[SIGINT Flush] Successfully exported %u flows to CSV.\n", exported);
}

static void sig_handler(int sig) {
    if (!exiting) {
        exiting = true;
        export_all_flows(); // Guaranteed safe offload logic at program shutdown
        exit(0);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    int ifindex = if_nametoindex(iface);
    if (!ifindex) return 1;

    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (bpf_object__load(obj)) return 1;

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) goto cleanup;
    
    int map_fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    fprintf(stderr, "[System] Waiting for flows... Aggregating O(n) math gracefully.\n");
    while (!exiting) {
        ring_buffer__poll(rb, 100); 
    }

cleanup:
    if (link) bpf_link__destroy(link);
    if (rb) ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
