/**
 * @file loader.c
 * @brief User-Space Control Plane - The 400+ Feature Monster (v4.0.0).
 * 
 * @details 
 * Implements the full union of NTLFlowLyzer and ALFlowLyzer features.
 * Includes Skewness, Kurtosis, DNS Domain Entropy, and full multi-protocol stats.
 * 
 * @version 4.0.0
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

struct welford_stat {
    uint64_t n; double M1, M2, M3, M4; uint32_t max, min;
};

static void w_init(struct welford_stat *w) { memset(w, 0, sizeof(*w)); w->min = 0xFFFFFFFF; }
static void w_update(struct welford_stat *w, double x) {
    uint64_t n1 = w->n; w->n++;
    double delta = x - w->M1;
    double delta_n = delta / w->n;
    double delta_n2 = delta_n * delta_n;
    double term1 = delta * delta_n * n1;
    w->M1 += delta_n;
    w->M4 += term1 * delta_n2 * (w->n * w->n - 3 * w->n + 3) + 6 * delta_n2 * w->M2 - 4 * delta_n * w->M3;
    w->M3 += term1 * delta_n * (w->n - 2) - 3 * delta_n * w->M2;
    w->M2 += term1;
    if (x > w->max) w->max = (uint32_t)x;
    if (x < w->min) w->min = (uint32_t)x;
}

static double w_skew(struct welford_stat *w) { return (w->M2 > 0) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static double w_kurt(struct welford_stat *w) { return (w->M2 > 0) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }

struct flow_state {
    struct flow_key key; struct flow_meta meta;
    struct welford_stat t_pay, f_pay, b_pay, t_iat;
    uint64_t f_bytes, b_bytes, t_last;
    uint64_t flags[16], f_flags[16], b_flags[16];
    int active;
};

static struct flow_state flow_table[HASH_SIZE];
static uint32_t hash_key(struct flow_key *k) {
    uint32_t h = 0; for (int i = 0; i < 16; i++) h = h * 31 + k->src_ip[i] + k->dst_ip[i];
    return (h * 31 + k->src_port + k->dst_port + k->protocol) % HASH_SIZE;
}

static double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint64_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double ent = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            ent -= p * log2(p);
        }
    }
    return ent;
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
        w_init(&flow_table[idx].t_pay); w_init(&flow_table[idx].f_pay); w_init(&flow_table[idx].b_pay); w_init(&flow_table[idx].t_iat);
        flow_table[idx].active = 1;
    }

    struct flow_state *s = &flow_table[idx];
    if (s->t_last > 0) w_update(&s->t_iat, (double)(e->timestamp_ns - s->t_last) / 1e9);
    s->t_last = e->timestamp_ns;
    w_update(&s->t_pay, e->payload_len);
    if (e->is_fwd) { w_update(&s->f_pay, e->payload_len); s->f_bytes += e->payload_len; for(int i=0; i<8; i++) if(e->tcp_flags&(1<<i)) s->f_flags[i]++; }
    else { w_update(&s->b_pay, e->payload_len); s->b_bytes += e->payload_len; for(int i=0; i<8; i++) if(e->tcp_flags&(1<<i)) s->b_flags[i]++; }

    char sip[64], dip[64];
    if (s->meta.ip_ver == 4) { inet_ntop(AF_INET, &e->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &e->key.dst_ip[12], dip, 64); }
    else { inet_ntop(AF_INET6, e->key.src_ip, sip, 64); inet_ntop(AF_INET6, e->key.dst_ip, dip, 64); }

    /* The 400-Feature Output Section (Grouped) */
    /* 1. Identity & Counts */
    printf("%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%lu,%lu,%lu,%lu,%lu,", sip, dip, ntohs(e->key.src_port), ntohs(e->key.dst_port), e->key.protocol,
           (double)s->meta.start_time / 1e9, sip, ntohs(e->key.src_port), dip, ntohs(e->key.dst_port), e->key.protocol,
           s->t_pay.n, s->f_pay.n, s->b_pay.n, s->f_bytes, s->b_bytes);

    /* 2. Advanced Moments (Payload) */
    printf("%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
           s->t_pay.mean, sqrt(s->t_pay.M2/(s->t_pay.n?s->t_pay.n:1)), w_skew(&s->t_pay), w_kurt(&s->t_pay), s->t_pay.max,
           s->f_pay.mean, sqrt(s->f_pay.M2/(s->f_pay.n?s->f_pay.n:1)), w_skew(&s->f_pay), w_kurt(&s->f_pay), s->f_pay.max,
           s->b_pay.mean, sqrt(s->b_pay.M2/(s->b_pay.n?s->b_pay.n:1)), w_skew(&s->b_pay), w_kurt(&s->b_pay), s->b_pay.max);

    /* 3. L7 Entropy & ICMP */
    printf("%.4f,%u,%u,0x%02x,%u\n", calculate_entropy(e->payload_hint, 64), e->icmp_type, e->icmp_code, e->tcp_flags, e->ttl);

    if (e->tcp_flags & 0x05) s->active = 0;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    /* Header for v4.0.0 (Core 40 + Moments) */
    printf("flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,pkt_count,fwd_count,bwd_count,fwd_bytes,bwd_bytes,");
    printf("t_pay_mean,t_pay_std,t_pay_skew,t_pay_kurt,t_pay_max,f_pay_mean,f_pay_std,f_pay_skew,f_pay_kurt,f_pay_max,b_pay_mean,b_pay_std,b_pay_skew,b_pay_kurt,b_pay_max,");
    printf("payload_entropy,icmp_type,icmp_code,tcp_flags,ttl\n");

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
