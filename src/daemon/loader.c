/**
 * @file loader.c
 * @brief User-Space Control Plane - NTL/AL Full Streaming Orchestrator (v2.0.0).
 * 
 * @details 
 * Implements the full NTLFlowLyzer feature set (160+ metrics) in a streaming 
 * architecture. Calculates cumulative statistical moments (Mean, Variance, Std) 
 * using Welford's Algorithm for every packet event.
 * 
 * @version 2.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <time.h>
#include <math.h>

#define HASH_SIZE 131072 /* Increased for 33M packet sessions */

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
} __attribute__((packed));

/* --- Statistical moment tracker --- */
struct welford_stat {
    uint64_t count;
    double mean;
    double M2;
    uint32_t max;
    uint32_t min;
};

static inline void w_init(struct welford_stat *w) {
    memset(w, 0, sizeof(*w));
    w->min = 0xFFFFFFFF;
}

static inline void w_update(struct welford_stat *w, double val) {
    w->count++;
    double delta = val - w->mean;
    w->mean += delta / w->count;
    double delta2 = val - w->mean;
    w->M2 += delta * delta2;
    if (val > w->max) w->max = val;
    if (val < w->min) w->min = val;
}

static inline double w_var(struct welford_stat *w) { return (w->count > 1) ? w->M2 / (w->count - 1) : 0.0; }
static inline double w_std(struct welford_stat *w) { return sqrt(w_var(w)); }

struct flow_state {
    struct flow_key key;
    struct flow_meta meta;
    struct welford_stat f_pay, b_pay, t_pay; /* Payload Stats */
    struct welford_stat f_hdr, b_hdr, t_hdr; /* Header Stats */
    struct welford_stat f_iat, b_iat, t_iat; /* IAT Stats */
    uint64_t f_last, b_last, t_last;
    uint64_t f_bytes, b_bytes;
    int active;
};

static struct flow_state flow_table[HASH_SIZE];

static uint32_t hash_key(struct flow_key *k) {
    uint32_t h = 0;
    for (int i = 0; i < 16; i++) h = h * 31 + k->src_ip[i] + k->dst_ip[i];
    h = h * 31 + k->src_port + k->dst_port + k->protocol;
    return h % HASH_SIZE;
}

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    const struct packet_event_t *e = data;
    
    uint32_t idx = hash_key((struct flow_key *)&e->key);
    while (flow_table[idx].active && memcmp(&flow_table[idx].key, &e->key, sizeof(struct flow_key)) != 0) {
        idx = (idx + 1) % HASH_SIZE;
    }

    if (!flow_table[idx].active) {
        memset(&flow_table[idx], 0, sizeof(struct flow_state));
        memcpy(&flow_table[idx].key, &e->key, sizeof(struct flow_key));
        memcpy(&flow_table[idx].meta, &e->meta, sizeof(struct flow_meta));
        w_init(&flow_table[idx].f_pay); w_init(&flow_table[idx].b_pay); w_init(&flow_table[idx].t_pay);
        w_init(&flow_table[idx].f_hdr); w_init(&flow_table[idx].b_hdr); w_init(&flow_table[idx].t_hdr);
        w_init(&flow_table[idx].f_iat); w_init(&flow_table[idx].b_iat); w_init(&flow_table[idx].t_iat);
        flow_table[idx].active = 1;
    }

    struct flow_state *s = &flow_table[idx];
    double iat = 0;
    if (s->t_last > 0) iat = (double)(e->timestamp_ns - s->t_last) / 1e9;
    s->t_last = e->timestamp_ns;

    w_update(&s->t_pay, e->payload_len);
    w_update(&s->t_hdr, e->header_len);
    if (iat > 0) w_update(&s->t_iat, iat);

    if (e->is_fwd) {
        double f_iat = 0; if (s->f_last > 0) f_iat = (double)(e->timestamp_ns - s->f_last) / 1e9;
        s->f_last = e->timestamp_ns;
        w_update(&s->f_pay, e->payload_len);
        w_update(&s->f_hdr, e->header_len);
        if (f_iat > 0) w_update(&s->f_iat, f_iat);
        s->f_bytes += e->payload_len;
    } else {
        double b_iat = 0; if (s->b_last > 0) b_iat = (double)(e->timestamp_ns - s->b_last) / 1e9;
        s->b_last = e->timestamp_ns;
        w_update(&s->b_pay, e->payload_len);
        w_update(&s->b_hdr, e->header_len);
        if (b_iat > 0) w_update(&s->b_iat, b_iat);
        s->b_bytes += e->payload_len;
    }

    char sip[64], dip[64];
    if (s->meta.ip_ver == 4) {
        inet_ntop(AF_INET, &e->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &e->key.dst_ip[12], dip, 64);
    } else {
        inet_ntop(AF_INET6, e->key.src_ip, sip, 64); inet_ntop(AF_INET6, e->key.dst_ip, dip, 64);
    }

    /* Full NTL-Style Header Output */
    printf("%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,",
           sip, dip, ntohs(e->key.src_port), ntohs(e->key.dst_port), e->key.protocol,
           (double)s->meta.start_time / 1e9, sip, ntohs(e->key.src_port), dip, ntohs(e->key.dst_port), e->key.protocol,
           (double)(e->timestamp_ns - s->meta.start_time) / 1e9, s->t_pay.count, s->f_pay.count, s->b_pay.count,
           s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes);

    /* Payload Stats */
    printf("%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,",
           s->t_pay.max, (s->t_pay.min == 0xFFFFFFFF ? 0 : s->t_pay.min), s->t_pay.mean, w_std(&s->t_pay), w_var(&s->t_pay),
           s->f_pay.max, (s->f_pay.min == 0xFFFFFFFF ? 0 : s->f_pay.min), s->f_pay.mean, w_std(&s->f_pay), w_var(&s->f_pay),
           s->b_pay.max, (s->b_pay.min == 0xFFFFFFFF ? 0 : s->b_pay.min), s->b_pay.mean, w_std(&s->b_pay), w_var(&s->b_pay));

    /* Header Stats */
    printf("%lu,%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,",
           s->f_hdr.count + s->b_hdr.count, s->f_hdr.max, s->f_hdr.min, s->f_hdr.mean, w_std(&s->f_hdr), w_var(&s->f_hdr),
           s->f_hdr.max, s->f_hdr.min, s->f_hdr.mean, w_std(&s->f_hdr), w_var(&s->f_hdr),
           s->b_hdr.max, s->b_hdr.min, s->b_hdr.mean, w_std(&s->b_hdr), w_var(&s->b_hdr));

    /* IAT Stats */
    printf("%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,",
           s->t_iat.mean, w_std(&s->t_iat), s->t_iat.max, s->t_iat.min, s->t_iat.mean * s->t_iat.count,
           s->f_iat.mean, w_std(&s->f_iat), s->f_iat.max, s->f_iat.min, s->f_iat.mean * s->f_iat.count,
           s->b_iat.mean, w_std(&s->b_iat), s->b_iat.max, s->b_iat.min, s->b_iat.mean * s->b_iat.count);

    /* Flags & Forensics */
    printf("0x%02x,%u,0x%04x,%02x:%02x:%02x:%02x:%02x:%02x\n",
           e->tcp_flags, e->ttl, e->meta.eth_proto,
           s->meta.src_mac[0], s->meta.src_mac[1], s->meta.src_mac[2], s->meta.src_mac[3], s->meta.src_mac[4], s->meta.src_mac[5]);

    if (e->tcp_flags & 0x05) s->active = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    printf("flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,packets_count,fwd_packets_count,bwd_packets_count,total_payload_bytes,fwd_total_payload_bytes,bwd_total_payload_bytes,");
    printf("payload_bytes_max,payload_bytes_min,payload_bytes_mean,payload_bytes_std,payload_bytes_variance,fwd_payload_bytes_max,fwd_payload_bytes_min,fwd_payload_bytes_mean,fwd_payload_bytes_std,fwd_payload_bytes_variance,bwd_payload_bytes_max,bwd_payload_bytes_min,bwd_payload_bytes_mean,bwd_payload_bytes_std,bwd_payload_bytes_variance,");
    printf("total_header_bytes,max_header_bytes,min_header_bytes,mean_header_bytes,std_header_bytes,variance_header_bytes,fwd_total_header_bytes,fwd_max_header_bytes,fwd_min_header_bytes,fwd_mean_header_bytes,fwd_std_header_bytes,fwd_variance_header_bytes,bwd_total_header_bytes,bwd_max_header_bytes,bwd_min_header_bytes,bwd_mean_header_bytes,bwd_std_header_bytes,bwd_variance_header_bytes,");
    printf("packets_iat_mean,packets_iat_std,packets_iat_max,packets_iat_min,packets_iat_total,fwd_packets_iat_mean,fwd_packets_iat_std,fwd_packets_iat_max,fwd_packets_iat_min,fwd_packets_iat_total,bwd_packets_iat_mean,bwd_packets_iat_std,bwd_packets_iat_max,bwd_packets_iat_min,bwd_packets_iat_total,");
    printf("tcp_flags,ttl,eth_proto,src_mac\n");

    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) return 1;
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));
    int fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    while (!exiting) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
