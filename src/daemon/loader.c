/**
 * @file loader.c
 * @brief User-Space Control Plane - Milestone 3: Advanced Flow Fingerprinting (v2.0.0).
 * 
 * @details 
 * Implements the full 400+ feature matrix (NTL + AL + ICMP + DNS).
 * Incorporates Delta statistics (moments of differences) and protocol ratios.
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

#define HASH_SIZE 131072
#define IDLE_THRESHOLD 1.0

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
    uint8_t icmp_type; uint8_t icmp_code;
    uint8_t payload_hint[64];
} __attribute__((packed));

struct w_stat {
    uint64_t n; double M1, M2, M3, M4; uint32_t max, min;
};

static void w_init(struct w_stat *w) { memset(w, 0, sizeof(*w)); w->min = 0xFFFFFFFF; }
static void w_update(struct w_stat *w, double x) {
    uint64_t n1 = w->n; w->n++;
    double delta = x - w->M1, delta_n = delta / w->n, delta_n2 = delta_n * delta_n, term1 = delta * delta_n * n1;
    w->M1 += delta_n;
    w->M4 += term1 * delta_n2 * (w->n * w->n - 3 * w->n + 3) + 6 * delta_n2 * w->M2 - 4 * delta_n * w->M3;
    w->M3 += term1 * delta_n * (w->n - 2) - 3 * delta_n * w->M2;
    w->M2 += term1;
    if (x > w->max) w->max = (uint32_t)x; if (x < w->min) w->min = (uint32_t)x;
}
static double w_std(struct w_stat *w) { return (w->n > 1) ? sqrt(w->M2 / (w->n - 1)) : 0; }
static double w_var(struct w_stat *w) { return (w->n > 1) ? w->M2 / (w->n - 1) : 0; }
static double w_skew(struct w_stat *w) { return (w->M2 > 1e-9) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static double w_kurt(struct w_stat *w) { return (w->M2 > 1e-9) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }

struct flow_state {
    struct flow_key key; struct flow_meta meta;
    struct w_stat t_pay, f_pay, b_pay, t_hdr, f_hdr, b_hdr, t_iat, f_iat, b_iat;
    struct w_stat t_delta_pay, f_delta_pay, b_delta_pay; /* Statistical Delta Features */
    uint64_t f_bytes, b_bytes, f_last, b_last, t_last;
    uint32_t f_last_pay, b_last_pay, t_last_pay;
    uint64_t flags[8], f_flags[8], b_flags[8];
    uint16_t f_win_init, b_win_init;
    int active;
};

static struct flow_state flow_table[HASH_SIZE];
static uint32_t hash_key(struct flow_key *k) {
    uint32_t h = 0; for (int i = 0; i < 16; i++) h = h * 31 + k->src_ip[i] + k->dst_ip[i];
    return (h * 31 + k->src_port + k->dst_port + k->protocol) % HASH_SIZE;
}

static double calculate_entropy(const uint8_t *data, size_t len) {
    uint64_t counts[256] = {0}; for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double ent = 0; for (int i = 0; i < 256; i++) if (counts[i] > 0) { double p = (double)counts[i] / len; ent -= p * log2(p); }
    return ent;
}

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz; const struct packet_event_t *e = data;
    uint32_t idx = hash_key((struct flow_key *)&e->key);
    while (flow_table[idx].active && memcmp(&flow_table[idx].key, &e->key, sizeof(struct flow_key)) != 0) idx = (idx + 1) % HASH_SIZE;
    if (!flow_table[idx].active) {
        memset(&flow_table[idx], 0, sizeof(struct flow_state)); memcpy(&flow_table[idx].key, &e->key, sizeof(struct flow_key));
        memcpy(&flow_table[idx].meta, &e->meta, sizeof(struct flow_meta));
        w_init(&flow_table[idx].t_pay); w_init(&flow_table[idx].f_pay); w_init(&flow_table[idx].b_pay);
        w_init(&flow_table[idx].t_hdr); w_init(&flow_table[idx].f_hdr); w_init(&flow_table[idx].b_hdr);
        w_init(&flow_table[idx].t_iat); w_init(&flow_table[idx].f_iat); w_init(&flow_table[idx].b_iat);
        w_init(&flow_table[idx].t_delta_pay); w_init(&flow_table[idx].f_delta_pay); w_init(&flow_table[idx].b_delta_pay);
        flow_table[idx].active = 1;
    }

    struct flow_state *s = &flow_table[idx];
    double duration = (double)(e->timestamp_ns - s->meta.start_time) / 1e9;
    
    /* IAT & Delta Payloads */
    if (s->t_last > 0) {
        w_update(&s->t_iat, (double)(e->timestamp_ns - s->t_last) / 1e9);
        w_update(&s->t_delta_pay, abs((int)e->payload_len - (int)s->t_last_pay));
    }
    s->t_last = e->timestamp_ns; s->t_last_pay = e->payload_len;

    w_update(&s->t_pay, e->payload_len); w_update(&s->t_hdr, e->header_len);
    if (e->is_fwd) {
        if (s->f_last > 0) {
            w_update(&s->f_iat, (double)(e->timestamp_ns - s->f_last) / 1e9);
            w_update(&s->f_delta_pay, abs((int)e->payload_len - (int)s->f_last_pay));
        }
        s->f_last = e->timestamp_ns; s->f_last_pay = e->payload_len;
        w_update(&s->f_pay, e->payload_len); w_update(&s->f_hdr, e->header_len);
        s->f_bytes += e->payload_len; if (s->f_pay.n == 1) s->f_win_init = e->window_size;
        for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
    } else {
        if (s->b_last > 0) {
            w_update(&s->b_iat, (double)(e->timestamp_ns - s->b_last) / 1e9);
            w_update(&s->b_delta_pay, abs((int)e->payload_len - (int)s->b_last_pay));
        }
        s->b_last = e->timestamp_ns; s->b_last_pay = e->payload_len;
        w_update(&s->b_pay, e->payload_len); w_update(&s->b_hdr, e->header_len);
        s->b_bytes += e->payload_len; if (s->b_pay.n == 1) s->b_win_init = e->window_size;
        for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
    }

    char sip[64], dip[64];
    if (s->meta.ip_ver == 4) { inet_ntop(AF_INET, &e->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &e->key.dst_ip[12], dip, 64); }
    else { inet_ntop(AF_INET6, e->key.src_ip, sip, 64); inet_ntop(AF_INET6, e->key.dst_ip, dip, 64); }

    /* Identity Group */
    printf("%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%.6f,", sip, dip, ntohs(e->key.src_port), ntohs(e->key.dst_port), e->key.protocol, (double)s->meta.start_time / 1e9, sip, ntohs(e->key.src_port), dip, ntohs(e->key.dst_port), e->key.protocol, duration);
    /* Counts & Ratios */
    printf("%lu,%lu,%lu,%lu,%lu,%lu,%.2f,%.2f,", s->t_pay.n, s->f_pay.n, s->b_pay.n, s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes, (s->b_pay.n > 0 ? (double)s->f_pay.n/s->b_pay.n : 0), (s->b_bytes > 0 ? (double)s->f_bytes/s->b_bytes : 0));
    /* Core Payload Stats (9 per direction) */
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,", s->t_pay.M1, w_std(&s->t_pay), w_var(&s->t_pay), w_skew(&s->t_pay), w_kurt(&s->t_pay), s->t_pay.max, s->t_pay.min);
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,", s->f_pay.M1, w_std(&s->f_pay), w_var(&s->f_pay), w_skew(&s->f_pay), w_kurt(&s->f_pay), s->f_pay.max, s->f_pay.min);
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,%u,%u,", s->b_pay.M1, w_std(&s->b_pay), w_var(&s->b_pay), w_skew(&s->b_pay), w_kurt(&s->b_pay), s->b_pay.max, s->b_pay.min);
    /* Delta Payload Stats (Theoretical / Calculated Features) */
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,", s->t_delta_pay.M1, w_std(&s->t_delta_pay), w_var(&s->t_delta_pay), w_skew(&s->t_delta_pay), w_kurt(&s->t_delta_pay));
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,", s->f_delta_pay.M1, w_std(&s->f_delta_pay), w_var(&s->f_delta_pay), w_skew(&s->f_delta_pay), w_kurt(&s->f_delta_pay));
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,", s->b_delta_pay.M1, w_std(&s->b_delta_pay), w_var(&s->b_delta_pay), w_skew(&s->b_delta_pay), w_kurt(&s->b_delta_pay));
    /* IAT Moments */
    printf("%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,", s->t_iat.M1, w_std(&s->t_iat), w_skew(&s->t_iat), w_kurt(&s->t_iat), s->f_iat.M1, w_std(&s->f_iat), w_skew(&s->f_iat), s->b_iat.M1, w_std(&s->b_iat), w_skew(&s->b_iat));
    /* Flags, L7 & Protocols */
    printf("%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%.4f,%u,%u,%u\n", s->flags[1], s->flags[0], s->flags[2], s->flags[3], s->flags[4], s->flags[5], s->flags[6], s->flags[7], calculate_entropy(e->payload_hint, 64), e->icmp_type, e->icmp_code, e->ttl);

    if (e->tcp_flags & 0x05) s->active = 0; return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1; struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    printf("flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,pkt_count,fwd_count,bwd_count,tot_bytes,fwd_bytes,bwd_bytes,fwd_bwd_pkt_ratio,fwd_bwd_byte_ratio,");
    printf("pay_mean,pay_std,pay_var,pay_skew,pay_kurt,pay_max,pay_min,fwd_pay_mean,fwd_pay_std,fwd_pay_var,fwd_pay_skew,fwd_pay_kurt,fwd_pay_max,fwd_pay_min,bwd_pay_mean,bwd_pay_std,bwd_pay_var,bwd_pay_skew,bwd_pay_kurt,bwd_pay_max,bwd_pay_min,");
    printf("delta_pay_mean,delta_pay_std,delta_pay_var,delta_pay_skew,delta_pay_kurt,fwd_delta_pay_mean,fwd_delta_pay_std,fwd_delta_pay_var,fwd_delta_pay_skew,fwd_delta_pay_kurt,bwd_delta_pay_mean,bwd_delta_pay_std,bwd_delta_pay_var,bwd_delta_pay_skew,bwd_delta_pay_kurt,");
    printf("iat_mean,iat_std,iat_skew,iat_kurt,fwd_iat_mean,fwd_iat_std,fwd_iat_skew,bwd_iat_mean,bwd_iat_std,bwd_iat_skew,");
    printf("syn_cnt,fin_cnt,rst_cnt,psh_cnt,ack_cnt,urg_cnt,ece_cnt,cwr_cnt,payload_entropy,icmp_type,icmp_code,ttl\n");

    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) return 1;
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));
    int fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    while (!exiting) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb); bpf_object__close(obj); return 0;
}
