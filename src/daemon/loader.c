/**
 * @file loader.c
 * @brief User-Space Control Plane Daemon for eBPFNetFlowLyzer.
 * 
 * This daemon orchestrates the high-performance network traffic feature extraction.
 * It serves as the asynchronous consumer of the eBPF RingBuffer, performing 
 * stateful bidirectional flow aggregation and O(1) statistical analysis.
 * 
 * Core Technical Contributions:
 * 1. O(1) Memory Space Statistics: Implementation of Welford's Algorithm for 
 *    rolling variance and standard deviation without sample buffering.
 * 2. Unified Dual-Stack keying: 5-tuple IPv4-Mapped IPv6 addressing for seamless 
 *    v4/v6 hybrid flow tracking.
 * 3. RingBuffer Synchronization: Lock-free event consumption from XDP Data Plane.
 * 
 * Research Context:
 * Developed as part of the Master's Degree in Applied Computing research, 
 * focusing on high-speed DDoS detection and mitigation.
 */

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

/**
 * @struct flow_event_t
 * @brief Binary event structure received from XDP Kernel Space.
 * Precise 1:1 mapping with the C-eBPF definition in main.bpf.c.
 */
struct flow_event_t {
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t ip_ver;
    uint16_t payload_length;
    uint16_t header_length;
    uint8_t tcp_flags;
    uint8_t is_tunneled;
    uint8_t sni_hostname[64];
    uint64_t timestamp_ns;
    uint8_t dns_payload_raw[256];
};

static volatile bool exiting = false;

/**
 * @struct welford_stat
 * @brief Iterative statistical accumulator (O(1) memory complexity).
 * 
 * To ensure wire-speed processing, we must avoid storing packet sequences.
 * Welford's algorithm allows the calculation of Mean and Variance in a 
 * single pass with numerically stable results.
 */
struct welford_stat {
    unsigned long count; /**< Sample count (N) */
    double mean;         /**< Rolling expected value (Mean) */
    double M2;           /**< Aggregate of squared differences for Variance */
    double min;          /**< Extreme value tracking (Minimum) */
    double max;          /**< Extreme value tracking (Maximum) */
};

/**
 * @brief Initializes a statistical container.
 */
void welford_init(struct welford_stat *w) {
    w->count = 0;
    w->mean = 0.0;
    w->M2 = 0.0;
    w->min = -1.0; 
    w->max = 0.0;
}

/**
 * @brief Incremental update using Welford's recurrence relation.
 * @param value New observation (e.g., IAT or Packet Length).
 */
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

/**
 * @struct flow_key
 * @brief Unique 5-tuple identifier for bidirectional flow correlation.
 */
struct flow_key {
    uint8_t src_ip[16];
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

/**
 * @struct flow_record
 * @brief Persistent state for an active network flow.
 * Aggregates metrics from individual packets into a cohesive feature vector.
 */
struct flow_record {
    struct flow_key key;
    
    // Temporal Context
    uint64_t start_time;
    uint64_t last_time;
    uint64_t fwd_last_time;
    uint64_t bwd_last_time;
    
    // Throughput Counters
    uint64_t fwd_pkt_count;
    uint64_t bwd_pkt_count;
    uint64_t fwd_total_bytes;
    uint64_t bwd_total_bytes;
    uint64_t fwd_total_header;
    uint64_t bwd_total_header;
    
    // Statistical Features (Welford)
    struct welford_stat fwd_len;
    struct welford_stat bwd_len;
    struct welford_stat fwd_iat;
    struct welford_stat bwd_iat;
    struct welford_stat pkt_iat;

    // TCP State Bitmask
    uint8_t fwd_flags;
    uint8_t bwd_flags;
    uint8_t is_tunneled;
    char    sni_hostname[64];
    
    // DNS Meta-Extraction (Dissertation specific features)
    uint32_t dns_query_count;
    struct welford_stat dns_ttl_stat;

    UT_hash_handle hh; /**< UTHash linkage for O(1) user-space lookup */
};

struct flow_record *flows = NULL; 

/**
 * @brief Simplified DNS metadata parser.
 * Extracts Query counts and TTL samples for L7 feature correlation.
 */
void parse_dns_metrics(struct flow_record *f, void *payload_data, size_t length) {
    if (length < 12) return;
    
    uint16_t qdcount = ntohs(*(uint16_t *)(payload_data + 4));
    uint16_t ancount = ntohs(*(uint16_t *)(payload_data + 6));
    
    if (qdcount > 0) f->dns_query_count += qdcount;

    if (ancount > 0 && length > 24) {
        // Heuristic TTL extraction from the first Answer Resource Record (RR)
        uint32_t ttl_sample = ntohl(*(uint32_t *)(payload_data + length - 10)); 
        if (ttl_sample > 0 && ttl_sample < 86400) {
            welford_update(&f->dns_ttl_stat, (double)ttl_sample);
        }
    }
}

/**
 * @brief RingBuffer Callback. Triggered for every packet event from Kernel Space.
 * Handles flow lookup, direction detection, and statistical updates.
 */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    const struct flow_event_t *e = data;
    struct flow_record *f;
    struct flow_key k;
    
    memcpy(k.src_ip, e->src_ip, 16);
    memcpy(k.dst_ip, e->dst_ip, 16);
    k.src_port = e->src_port;
    k.dst_port = e->dst_port;
    k.protocol = e->protocol;

    // Bidirectional Lookup Strategy:
    // We check if either (A->B) or (B->A) exists in our flow table.
    HASH_FIND(hh, flows, &k, sizeof(struct flow_key), f);
    
    uint8_t is_fwd = 1;

    if (!f) {
        struct flow_key reverse_k;
        memcpy(reverse_k.src_ip, e->dst_ip, 16);
        memcpy(reverse_k.dst_ip, e->src_ip, 16);
        reverse_k.src_port = e->dst_port;
        reverse_k.dst_port = e->src_port;
        reverse_k.protocol = e->protocol;
        
        HASH_FIND(hh, flows, &reverse_k, sizeof(struct flow_key), f);
        if (f) is_fwd = 0;
    }

    if (!f) {
        // Initializing new Flow Context
        f = (struct flow_record *)malloc(sizeof(struct flow_record));
        if (!f) return 0; 
        
        f->key = k;
        f->start_time = e->timestamp_ns;
        f->last_time = e->timestamp_ns;
        f->fwd_last_time = e->timestamp_ns;
        f->bwd_last_time = 0;
        
        f->fwd_pkt_count = 0; f->bwd_pkt_count = 0;
        f->fwd_total_bytes = 0; f->bwd_total_bytes = 0;
        f->fwd_total_header = 0; f->bwd_total_header = 0;
        f->fwd_flags = 0; f->bwd_flags = 0;
        f->is_tunneled = e->is_tunneled;
        memset(f->sni_hostname, 0, 64);
        f->dns_query_count = 0;

        welford_init(&f->fwd_len); welford_init(&f->bwd_len);
        welford_init(&f->fwd_iat); welford_init(&f->bwd_iat);
        welford_init(&f->pkt_iat); welford_init(&f->dns_ttl_stat);

        HASH_ADD(hh, flows, key, sizeof(struct flow_key), f);
    }
    
    // Inter-Arrival Time (IAT) Analysis
    double delta_global = (double)(e->timestamp_ns > f->last_time ? e->timestamp_ns - f->last_time : 0) / 1000.0;
    if (f->fwd_pkt_count + f->bwd_pkt_count > 0) welford_update(&f->pkt_iat, delta_global);
    f->last_time = e->timestamp_ns;

    // Feature Accumulation based on directionality
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
        if (e->sni_hostname[0] != 0) {
            strncpy(f->sni_hostname, (char *)e->sni_hostname, 63);
        }
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

    // DNS Subroutine for L7-aware extraction
    if (e->protocol == 17 && (ntohs(e->src_port) == 53 || ntohs(e->dst_port) == 53)) {
        parse_dns_metrics(f, (void *)e->dns_payload_raw, e->payload_length);
    }

    return 0;
}

/**
 * @brief Serializes the current flow table to CSV format.
 * Triggers at the end of execution to produce the ground truth feature matrix.
 */
void export_all_flows() {
    struct flow_record *f, *tmp;
    uint32_t exported = 0;
    
    // CSV Header (Master's thesis ground-truth compatible)
    printf("src_ip,dst_ip,src_port,dst_port,protocol,is_tunneled,sni_hostname,timestamp,flow_duration,tot_fwd_pkts,tot_bwd_pkts,tot_len_fwd_pkts,tot_len_bwd_pkts,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fwd_header_len,bwd_header_len,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,cwe_flag_cnt,ece_flag_cnt,dns_query_cont,dns_ttl_mean,dns_ttl_std\n");

    HASH_ITER(hh, flows, f, tmp) {
        double duration_us = (double)(f->last_time - f->start_time) / 1000.0;
        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        
        // IPv4-Mapped IPv6 address resolution logic
        if (memcmp(f->key.src_ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) == 0) {
            inet_ntop(AF_INET, &f->key.src_ip[12], src_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &f->key.dst_ip[12], dst_str, INET_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, f->key.src_ip, src_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, f->key.dst_ip, dst_str, INET6_ADDRSTRLEN);
        }

        printf("%s,%s,%u,%u,%u,%u,%s,%lu,%.2f,%lu,%lu,%lu,%lu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.2f,%.2f\n",
            src_str, dst_str,
            ntohs(f->key.src_port), ntohs(f->key.dst_port), f->key.protocol, f->is_tunneled, f->sni_hostname,
            f->start_time, duration_us,
            f->fwd_pkt_count, f->bwd_pkt_count,
            f->fwd_total_bytes, f->bwd_total_bytes,
            f->fwd_len.max, (f->fwd_len.min < 0 ? 0 : f->fwd_len.min), f->fwd_len.mean, welford_std(&f->fwd_len),
            f->bwd_len.max, (f->bwd_len.min < 0 ? 0 : f->bwd_len.min), f->bwd_len.mean, welford_std(&f->bwd_len),
            f->pkt_iat.mean, welford_std(&f->pkt_iat), f->pkt_iat.max, (f->pkt_iat.min < 0 ? 0 : f->pkt_iat.min),
            f->fwd_iat.mean, welford_std(&f->fwd_iat), f->fwd_iat.max, (f->fwd_iat.min < 0 ? 0 : f->fwd_iat.min),
            f->bwd_iat.mean, welford_std(&f->bwd_iat), f->bwd_iat.max, (f->bwd_iat.min < 0 ? 0 : f->bwd_iat.min),
            ((f->fwd_flags >> 3) & 1), ((f->bwd_flags >> 3) & 1), 
            ((f->fwd_flags >> 5) & 1), ((f->bwd_flags >> 5) & 1), 
            f->fwd_total_header, f->bwd_total_header,
            ((f->fwd_flags | f->bwd_flags) & 1),       
            (((f->fwd_flags | f->bwd_flags) >> 1) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 2) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 3) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 4) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 5) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 6) & 1), 
            (((f->fwd_flags | f->bwd_flags) >> 7) & 1), 
            f->dns_query_count, f->dns_ttl_stat.mean, welford_std(&f->dns_ttl_stat) 
        );
        
        HASH_DEL(flows, f);
        free(f);
        exported++;
    }
    fprintf(stderr, "\n[Flush] Successfully exported %u flows to CSV.\n", exported);
}

#define MAX_INTERFACES 16
static struct bpf_link *links[MAX_INTERFACES];
static int link_count = 0;

static void sig_handler(int sig) {
    (void)sig;
    if (!exiting) {
        exiting = true;
        export_all_flows(); 
        
        for (int i = 0; i < link_count; i++) {
            if (links[i]) bpf_link__destroy(links[i]);
        }
        
        exit(0);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <iface1> [iface2] ... [ifaceN]\n", argv[0]);
        return 1;
    }

    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (bpf_object__load(obj)) return 1;

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    
    for (int i = 1; i < argc && link_count < MAX_INTERFACES; i++) {
        const char *iface = argv[i];
        int ifindex = if_nametoindex(iface);
        if (!ifindex) {
            fprintf(stderr, "[Error] Interface %s not found. Skipping.\n", iface);
            continue;
        }

        struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "[Error] Failed to attach to %s.\n", iface);
            continue;
        }
        links[link_count++] = link;
        fprintf(stderr, "[System] Attached to interface: %s (index %d)\n", iface, ifindex);
    }

    if (link_count == 0) {
        fprintf(stderr, "[Fatal] Could not attach to any interface. Exiting.\n");
        goto cleanup;
    }
    
    int map_fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    fprintf(stderr, "[System] Monitoring %d interfaces. Aggregating data plane events...\n", link_count);
    while (!exiting) {
        ring_buffer__poll(rb, 100); 
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
