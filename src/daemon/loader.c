/**
 * @file loader.c
 * @brief User-Space Control Plane Daemon for eBPFNetFlowLyzer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <linux/if_link.h>
#include <time.h>
#include "uthash.h"

struct flow_event_t {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol; uint8_t ip_ver;
    uint16_t payload_length; uint16_t header_length;
    uint8_t tcp_flags; uint8_t is_tunneled;
    uint8_t sni_hostname[64]; uint8_t ttl;
    uint16_t window_size; uint64_t timestamp_ns;
    uint8_t dns_payload_raw[256];
} __attribute__((packed));

struct welford_stat {
    unsigned long count; double mean; double M2; double min; double max;
};

void welford_init(struct welford_stat *w) {
    w->count = 0; w->mean = 0.0; w->M2 = 0.0; w->min = -1.0; w->max = 0.0;
}

void welford_update(struct welford_stat *w, double value) {
    w->count++;
    double delta = value - w->mean; w->mean += delta / w->count;
    double delta2 = value - w->mean; w->M2 += delta * delta2;
    if (w->min < 0 || value < w->min) w->min = value;
    if (value > w->max) w->max = value;
}

double welford_std(struct welford_stat *w) {
    if (w->count < 2) return 0.0;
    return sqrt(w->M2 / (w->count - 1));
}

struct flow_key {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_record {
    struct flow_key key;
    uint64_t start_time; uint64_t last_time;
    uint64_t fwd_last_time; uint64_t bwd_last_time;
    uint64_t fwd_pkt_count; uint64_t bwd_pkt_count;
    uint64_t fwd_total_bytes; uint64_t bwd_total_bytes;
    uint64_t fwd_total_header; uint64_t bwd_total_header;
    struct welford_stat fwd_len; struct welford_stat bwd_len;
    struct welford_stat fwd_iat; struct welford_stat bwd_iat;
    struct welford_stat pkt_iat; 
    uint8_t fwd_flags; uint8_t bwd_flags;
    uint8_t is_tunneled; char sni_hostname[64];
    uint8_t ttl; uint16_t window_size;
    uint32_t dns_query_count; struct welford_stat dns_ttl_stat;
    UT_hash_handle hh;
};

struct flow_record *flows = NULL; 
static volatile bool exiting = false;
static int drop_map_fd = -1;
static int raw_pkt_map_fd = -1;

void sig_handler(int sig) { (void)sig; exiting = true; }

void print_stats() {
    uint32_t key = 0; uint64_t drops = 0, raw = 0;
    if (drop_map_fd >= 0) bpf_map_lookup_elem(drop_map_fd, &key, &drops);
    if (raw_pkt_map_fd >= 0) bpf_map_lookup_elem(raw_pkt_map_fd, &key, &raw);
    fprintf(stderr, "\n📊 [Stats] Total Packets Observed (XDP): %lu | RingBuffer Drops: %lu\n", raw, drops);
}

void export_all_flows() {
    struct flow_record *f, *tmp; uint32_t exported = 0;
    HASH_ITER(hh, flows, f, tmp) {
        double dur = (double)(f->last_time - f->start_time) / 1000.0;
        char s_s[64], d_s[64];
        if (memcmp(f->key.src_ip, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) == 0) {
            inet_ntop(AF_INET, &f->key.src_ip[12], s_s, 64);
            inet_ntop(AF_INET, &f->key.dst_ip[12], d_s, 64);
        } else {
            inet_ntop(AF_INET6, f->key.src_ip, s_s, 64);
            inet_ntop(AF_INET6, f->key.dst_ip, d_s, 64);
        }
        printf("%s,%s,%u,%u,%u,%u,%u,%u,%s,%lu,%.2f,%lu,%lu,%lu,%lu,", 
               s_s, d_s, (unsigned int)ntohs(f->key.src_port), (unsigned int)ntohs(f->key.dst_port), (unsigned int)f->key.protocol, 
               (unsigned int)f->ttl, (unsigned int)f->window_size, (unsigned int)f->is_tunneled, f->sni_hostname, f->start_time, dur,
               f->fwd_pkt_count, f->bwd_pkt_count, f->fwd_total_bytes, f->bwd_total_bytes);
        printf("%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
               f->fwd_len.max, (f->fwd_len.min < 0 ? 0 : f->fwd_len.min), f->fwd_len.mean, welford_std(&f->fwd_len),
               f->bwd_len.max, (f->bwd_len.min < 0 ? 0 : f->bwd_len.min), f->bwd_len.mean, welford_std(&f->bwd_len));
        printf("%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
               f->pkt_iat.mean, welford_std(&f->pkt_iat), f->pkt_iat.max, (f->pkt_iat.min < 0 ? 0 : f->pkt_iat.min),
               f->fwd_iat.mean, welford_std(&f->fwd_iat), f->fwd_iat.max, (f->fwd_iat.min < 0 ? 0 : f->fwd_iat.min),
               f->bwd_iat.mean, welford_std(&f->bwd_iat), f->bwd_iat.max, (f->bwd_iat.min < 0 ? 0 : f->bwd_iat.min));
        printf("%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.2f,%.2f\n",
               (unsigned int)((f->fwd_flags >> 3) & 1), (unsigned int)((f->bwd_flags >> 3) & 1), 
               (unsigned int)((f->fwd_flags >> 5) & 1), (unsigned int)((f->bwd_flags >> 5) & 1),
               f->fwd_total_header, f->bwd_total_header,
               (unsigned int)((f->fwd_flags | f->bwd_flags) & 1), (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 1) & 1), 
               (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 2) & 1), (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 3) & 1), 
               (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 4) & 1), (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 5) & 1), 
               (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 6) & 1), (unsigned int)(((f->fwd_flags | f->bwd_flags) >> 7) & 1), 
               f->dns_query_count, f->dns_ttl_stat.mean, welford_std(&f->dns_ttl_stat));
        HASH_DEL(flows, f); free(f); exported++;
    }
    fflush(stdout);
    fprintf(stderr, "\n[Flush] Successfully exported %u flows to CSV.\n", exported);
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz; const struct flow_event_t *e = data;
    struct flow_record *f; struct flow_key k; memset(&k, 0, sizeof(k));
    memcpy(k.src_ip, e->src_ip, 16); memcpy(k.dst_ip, e->dst_ip, 16);
    k.src_port = e->src_port; k.dst_port = e->dst_port; k.protocol = e->protocol;
    HASH_FIND(hh, flows, &k, sizeof(struct flow_key), f);
    uint8_t is_fwd = 1;
    if (!f) {
        struct flow_key rk; memset(&rk, 0, sizeof(rk));
        memcpy(rk.src_ip, e->dst_ip, 16); memcpy(rk.dst_ip, e->src_ip, 16);
        rk.src_port = e->dst_port; rk.dst_port = e->src_port; rk.protocol = e->protocol;
        HASH_FIND(hh, flows, &rk, sizeof(struct flow_key), f);
        if (f) is_fwd = 0;
    }
    if (!f) {
        f = calloc(1, sizeof(struct flow_record)); if (!f) return 0;
        f->key = k; f->start_time = e->timestamp_ns; f->is_tunneled = e->is_tunneled;
        f->ttl = e->ttl; f->window_size = e->window_size;
        welford_init(&f->fwd_len); welford_init(&f->bwd_len);
        welford_init(&f->fwd_iat); welford_init(&f->bwd_iat);
        welford_init(&f->pkt_iat); welford_init(&f->dns_ttl_stat);
        HASH_ADD(hh, flows, key, sizeof(struct flow_key), f);
    }
    double dg = (double)(e->timestamp_ns > f->last_time ? e->timestamp_ns - f->last_time : 0) / 1000.0;
    if (f->fwd_pkt_count + f->bwd_pkt_count > 0) welford_update(&f->pkt_iat, dg);
    f->last_time = e->timestamp_ns;
    if (is_fwd) {
        f->fwd_pkt_count++; f->fwd_total_bytes += e->payload_length; f->fwd_total_header += e->header_length;
        f->fwd_flags |= e->tcp_flags; welford_update(&f->fwd_len, (double)e->payload_length);
        if (f->fwd_pkt_count > 1) {
            double d = (double)(e->timestamp_ns > f->fwd_last_time ? e->timestamp_ns - f->fwd_last_time : 0) / 1000.0;
            welford_update(&f->fwd_iat, d);
        }
        f->fwd_last_time = e->timestamp_ns;
        if (e->sni_hostname[0] != 0) strncpy(f->sni_hostname, (char *)e->sni_hostname, 63);
    } else {
        f->bwd_pkt_count++; f->bwd_total_bytes += e->payload_length; f->bwd_total_header += e->header_length;
        f->bwd_flags |= e->tcp_flags; welford_update(&f->bwd_len, (double)e->payload_length);
        if (f->bwd_pkt_count > 1) {
            double d = (double)(e->timestamp_ns > f->bwd_last_time ? e->timestamp_ns - f->bwd_last_time : 0) / 1000.0;
            welford_update(&f->bwd_iat, d);
        }
        f->bwd_last_time = e->timestamp_ns;
    }
    if (e->protocol == 17 && (ntohs(e->src_port) == 53 || ntohs(e->dst_port) == 53)) {
        if (e->payload_length >= 12) {
            f->dns_query_count += ntohs(*(uint16_t *)(e->dns_payload_raw + 4));
            if (ntohs(*(uint16_t *)(e->dns_payload_raw + 6)) > 0 && e->payload_length > 24) {
                uint32_t ts = ntohl(*(uint32_t *)(e->dns_payload_raw + e->payload_length - 10));
                if (ts > 0 && ts < 86400) welford_update(&f->dns_ttl_stat, (double)ts);
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    if (argc < 2) return 1;
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    printf("src_ip,dst_ip,src_port,dst_port,protocol,ttl,window_size,is_tunneled,sni_hostname,timestamp,flow_duration,tot_fwd_pkts,tot_bwd_pkts,tot_len_fwd_pkts,tot_len_bwd_pkts,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fwd_header_len,bwd_header_len,fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,cwe_flag_cnt,ece_flag_cnt,dns_query_cont,dns_ttl_mean,dns_ttl_std\n");
    fflush(stdout);
    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "[Fatal] BPF Load Fail. Check dmesg.\n"); return 1; }
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    int attached = 0;
    for (int i = 1; i < argc; i++) {
        int idx = if_nametoindex(argv[i]);
        if (idx) {
            struct bpf_link *link = bpf_program__attach_xdp(p, idx);
            if (link) attached++;
        }
    }
    if (!attached) { fprintf(stderr, "[Fatal] No interface attached.\n"); return 1; }
    int fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    drop_map_fd = bpf_object__find_map_fd_by_name(obj, "drop_counter");
    raw_pkt_map_fd = bpf_object__find_map_fd_by_name(obj, "raw_pkt_count");
    while (!exiting) ring_buffer__poll(rb, 100);
    print_stats(); export_all_flows();
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
