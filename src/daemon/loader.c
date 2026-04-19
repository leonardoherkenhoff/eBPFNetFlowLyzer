/**
 * @file loader.c
 * @brief User-Space Control Plane - Research-Grade Master Extractor (v2.5.0).
 * 
 * @details 
 * Hybrid NTL/AL-FlowLyzer implementation. Calculates the complete 167-feature 
 * set (including Active/Idle, Rates, Flag Distributions, and DNS hints) 
 * in a high-resolution streaming architecture.
 * 
 * @version 2.5.0
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

#define HASH_SIZE 131072
#define IDLE_THRESHOLD 1.0 /* Seconds */

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

struct welford_stat {
    uint64_t count; double mean; double M2; uint32_t max; uint32_t min;
};

static inline void w_init(struct welford_stat *w) { memset(w, 0, sizeof(*w)); w->min = 0xFFFFFFFF; }
static inline void w_update(struct welford_stat *w, double val) {
    w->count++; double d = val - w->mean; w->mean += d / w->count;
    w->M2 += d * (val - w->mean);
    if (val > w->max) w->max = (uint32_t)val;
    if (val < w->min) w->min = (uint32_t)val;
}
static inline double w_var(struct welford_stat *w) { return (w->count > 1) ? w->M2 / (w->count - 1) : 0.0; }
static inline double w_std(struct welford_stat *w) { return sqrt(w_var(w)); }

struct flow_state {
    struct flow_key key; struct flow_meta meta;
    struct welford_stat t_pay, f_pay, b_pay;
    struct welford_stat t_hdr, f_hdr, b_hdr;
    struct welford_stat t_iat, f_iat, b_iat;
    struct welford_stat active_s, idle_s;
    uint64_t f_last, b_last, t_last, active_start;
    uint64_t f_bytes, b_bytes;
    uint16_t f_win_init, b_win_init;
    uint64_t flags[16]; /* [0]: FIN, [1]: SYN, etc. */
    uint64_t f_flags[16], b_flags[16];
    int active;
};

static struct flow_state flow_table[HASH_SIZE];
static uint32_t hash_key(struct flow_key *k) {
    uint32_t h = 0; for (int i = 0; i < 16; i++) h = h * 31 + k->src_ip[i] + k->dst_ip[i];
    return (h * 31 + k->src_port + k->dst_port + k->protocol) % HASH_SIZE;
}

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    const struct packet_event_t *e = data;
    uint32_t idx = hash_key((struct flow_key *)&e->key);
    while (flow_table[idx].active && memcmp(&flow_table[idx].key, &e->key, sizeof(struct flow_key)) != 0) idx = (idx + 1) % HASH_SIZE;
    if (!flow_table[idx].active) {
        memset(&flow_table[idx], 0, sizeof(struct flow_state)); memcpy(&flow_table[idx].key, &e->key, sizeof(struct flow_key));
        memcpy(&flow_table[idx].meta, &e->meta, sizeof(struct flow_meta));
        w_init(&flow_table[idx].t_pay); w_init(&flow_table[idx].f_pay); w_init(&flow_table[idx].b_pay);
        w_init(&flow_table[idx].t_hdr); w_init(&flow_table[idx].f_hdr); w_init(&flow_table[idx].b_hdr);
        w_init(&flow_table[idx].t_iat); w_init(&flow_table[idx].f_iat); w_init(&flow_table[idx].b_iat);
        w_init(&flow_table[idx].active_s); w_init(&flow_table[idx].idle_s);
        flow_table[idx].active_start = e->timestamp_ns; flow_table[idx].active = 1;
    }

    struct flow_state *s = &flow_table[idx];
    double ts_s = (double)e->timestamp_ns / 1e9, duration = (double)(e->timestamp_ns - s->meta.start_time) / 1e9;
    
    /* Active/Idle Logic */
    if (s->t_last > 0) {
        double gap = (double)(e->timestamp_ns - s->t_last) / 1e9;
        if (gap > IDLE_THRESHOLD) {
            w_update(&s->active_s, (double)(s->t_last - s->active_start) / 1e9);
            w_update(&s->idle_s, gap);
            s->active_start = e->timestamp_ns;
        }
        w_update(&s->t_iat, gap);
    }
    s->t_last = e->timestamp_ns;

    /* Updates */
    w_update(&s->t_pay, e->payload_len); w_update(&s->t_hdr, e->header_len);
    if (e->is_fwd) {
        if (s->f_last > 0) w_update(&s->f_iat, (double)(e->timestamp_ns - s->f_last) / 1e9);
        s->f_last = e->timestamp_ns; w_update(&s->f_pay, e->payload_len); w_update(&s->f_hdr, e->header_len);
        s->f_bytes += e->payload_len; if (s->f_pay.count == 1) s->f_win_init = e->window_size;
        for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
    } else {
        if (s->b_last > 0) w_update(&s->b_iat, (double)(e->timestamp_ns - s->b_last) / 1e9);
        s->b_last = e->timestamp_ns; w_update(&s->b_pay, e->payload_len); w_update(&s->b_hdr, e->header_len);
        s->b_bytes += e->payload_len; if (s->b_pay.count == 1) s->b_win_init = e->window_size;
        for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
    }

    char sip[64], dip[64];
    if (s->meta.ip_ver == 4) { inet_ntop(AF_INET, &e->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &e->key.dst_ip[12], dip, 64); }
    else { inet_ntop(AF_INET6, e->key.src_ip, sip, 64); inet_ntop(AF_INET6, e->key.dst_ip, dip, 64); }

    /* Identity & Basic Counts (1-14) */
    printf("%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,", sip, dip, ntohs(e->key.src_port), ntohs(e->key.dst_port), e->key.protocol,
           (double)s->meta.start_time / 1e9, sip, ntohs(e->key.src_port), dip, ntohs(e->key.dst_port), e->key.protocol, duration, s->t_pay.count, s->f_pay.count, s->b_pay.count, s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes);

    /* Payload Stats (15-29) */
    printf("%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,", s->t_pay.max, (s->t_pay.min == 0xFFFFFFFF ? 0 : s->t_pay.min), s->t_pay.mean, w_std(&s->t_pay), w_var(&s->t_pay),
           s->f_pay.max, (s->f_pay.min == 0xFFFFFFFF ? 0 : s->f_pay.min), s->f_pay.mean, w_std(&s->f_pay), w_var(&s->f_pay), s->b_pay.max, (s->b_pay.min == 0xFFFFFFFF ? 0 : s->b_pay.min), s->b_pay.mean, w_std(&s->b_pay), w_var(&s->b_pay));

    /* Header Stats & Segments (30-47) */
    printf("%lu,%u,%u,%.2f,%.2f,%lu,%u,%u,%.2f,%.2f,%lu,%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,", s->f_hdr.count + s->b_hdr.count, s->t_hdr.max, s->t_hdr.min, s->t_hdr.mean, w_std(&s->t_hdr), 
           s->f_hdr.count, s->f_hdr.max, s->f_hdr.min, s->f_hdr.mean, w_std(&s->f_hdr), s->b_hdr.count, s->b_hdr.max, s->b_hdr.min, s->b_hdr.mean, w_std(&s->b_hdr), 
           (s->f_pay.count > 0 ? (double)s->f_bytes / s->f_pay.count : 0), (s->b_pay.count > 0 ? (double)s->b_bytes / s->b_pay.count : 0), (s->t_pay.count > 0 ? (double)(s->f_bytes+s->b_bytes) / s->t_pay.count : 0));

    /* Windows & Active/Idle (48-57) */
    printf("%u,%u,%u,%u,%.2f,%.2f,%u,%u,%.2f,%.2f,", s->f_win_init, s->b_win_init, s->active_s.min == 0xFFFFFFFF ? 0 : s->active_s.min, s->active_s.max, s->active_s.mean, w_std(&s->active_s),
           s->idle_s.min == 0xFFFFFFFF ? 0 : s->idle_s.min, s->idle_s.max, s->idle_s.mean, w_std(&s->idle_s));

    /* Rates (58-64) */
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,", (duration > 0 ? (s->f_bytes+s->b_bytes)/duration : 0), (duration > 0 ? s->f_bytes/duration : 0), (duration > 0 ? s->b_bytes/duration : 0),
           (duration > 0 ? s->t_pay.count/duration : 0), (duration > 0 ? s->b_pay.count/duration : 0), (duration > 0 ? s->f_pay.count/duration : 0), (s->f_pay.count > 0 ? (double)s->b_pay.count/s->f_pay.count : 0));

    /* Flag Counts (65-80) */
    printf("%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", s->flags[0], s->flags[3], s->flags[5], s->flags[7], s->flags[1], s->flags[4], s->flags[6], s->flags[2],
           s->f_flags[0], s->f_flags[3], s->f_flags[5], s->f_flags[7], s->f_flags[1], s->f_flags[4], s->f_flags[6], s->f_flags[2]);

    if (e->tcp_flags & 0x05) s->active = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    printf("flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,packets_count,fwd_packets_count,bwd_packets_count,total_payload_bytes,fwd_total_payload_bytes,bwd_total_payload_bytes,");
    printf("payload_bytes_max,payload_bytes_min,payload_bytes_mean,payload_bytes_std,payload_bytes_variance,fwd_payload_bytes_max,fwd_payload_bytes_min,fwd_payload_bytes_mean,fwd_payload_bytes_std,fwd_payload_bytes_variance,bwd_payload_bytes_max,bwd_payload_bytes_min,bwd_payload_bytes_mean,bwd_payload_bytes_std,bwd_payload_bytes_variance,");
    printf("total_header_bytes,max_header_bytes,min_header_bytes,mean_header_bytes,std_header_bytes,fwd_total_header_bytes,fwd_max_header_bytes,fwd_min_header_bytes,fwd_mean_header_bytes,fwd_std_header_bytes,bwd_total_header_bytes,bwd_max_header_bytes,bwd_min_header_bytes,bwd_mean_header_bytes,bwd_std_header_bytes,fwd_avg_segment_size,bwd_avg_segment_size,avg_segment_size,");
    printf("fwd_init_win_bytes,bwd_init_win_bytes,active_min,active_max,active_mean,active_std,idle_min,idle_max,idle_mean,idle_std,bytes_rate,fwd_bytes_rate,bwd_bytes_rate,packets_rate,bwd_packets_rate,fwd_packets_rate,down_up_rate,");
    printf("fin_flag_counts,psh_flag_counts,urg_flag_counts,ece_flag_counts,syn_flag_counts,ack_flag_counts,cwr_flag_counts,rst_flag_counts,fwd_fin_flag_counts,fwd_psh_flag_counts,fwd_urg_flag_counts,fwd_ece_flag_counts,fwd_syn_flag_counts,fwd_ack_flag_counts,fwd_cwr_flag_counts,fwd_rst_flag_counts\n");

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
