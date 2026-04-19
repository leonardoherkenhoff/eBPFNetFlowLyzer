/**
 * @file loader.c
 * @brief Lynceus Control Plane - Parallel Flow-Level Statistical Orchestrator (v2.7 - The 399).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>

#define FLOW_HASH_SIZE 131072
#define IO_BUFFER_SIZE (8 * 1024 * 1024)
#define IDLE_TIMEOUT_NS 60000000000ULL 
#define IDLE_THRESHOLD 1.0
#define SEGMENT_THRESHOLD 100 
#define HIST_BINS 80 /**< Adjusted for 399 Feature Parity */

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
    uint16_t dns_answer_count;
    uint8_t payload_hint[64];
} __attribute__((packed));

struct w_stat {
    uint64_t n; double M1, M2, M3, M4; uint32_t max, min;
    uint64_t hist[HIST_BINS];
};

static void w_init(struct w_stat *w) { memset(w, 0, sizeof(*w)); w->min = 0xFFFFFFFF; }
static inline void w_update(struct w_stat *w, double x) {
    uint64_t n1 = w->n; w->n++;
    double delta = x - w->M1, delta_n = delta / w->n, delta_n2 = delta_n * delta_n, term1 = delta * delta_n * n1;
    w->M1 += delta_n;
    w->M4 += term1 * delta_n2 * (w->n * w->n - 3 * w->n + 3) + 6 * delta_n2 * w->M2 - 4 * delta_n * w->M3;
    w->M3 += term1 * delta_n * (w->n - 2) - 3 * delta_n * w->M2;
    w->M2 += term1;
    if (x > w->max) w->max = (uint32_t)x; if (x < w->min) w->min = (uint32_t)x;
    uint32_t bin = (uint32_t)x / 20; if (bin < HIST_BINS) w->hist[bin]++;
}

static inline double w_var(struct w_stat *w) { return (w->n > 1) ? w->M2 / (w->n - 1) : 0; }
static inline double w_std(struct w_stat *w) { return sqrt(w_var(w)); }
static inline double w_skew(struct w_stat *w) { return (w->M2 > 1e-9) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static inline double w_kurt(struct w_stat *w) { return (w->M2 > 1e-9) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }

struct flow_state {
    struct flow_key key; struct flow_meta meta;
    struct w_stat t_pay, f_pay, b_pay, t_hdr, f_hdr, b_hdr, t_iat, f_iat, b_iat, active_s, idle_s, win_s;
    struct w_stat t_pay_delta, f_pay_delta, b_pay_delta;
    uint64_t f_bytes, b_bytes, f_last, b_last, t_last, active_start;
    uint32_t f_last_sz, b_last_sz, t_last_sz;
    uint16_t f_win_init, b_win_init;
    uint64_t flags[8], f_flags[8], b_flags[8];
    uint32_t dns_q_count, dns_a_count;
    double last_entropy;
    uint16_t icmp_id;
    uint64_t f_bulk_bytes, f_bulk_pkts, f_bulk_cnt;
    uint64_t b_bulk_bytes, b_bulk_pkts, b_bulk_cnt;
    int active;
};

struct worker_t {
    pthread_t thread; int rb_fd; struct ring_buffer *rb;
    struct flow_state *flow_table; FILE *out_f;
    char *s_buf; size_t s_off; int id; uint64_t processed_events;
};

static struct worker_t *workers;
static int num_workers = 1;
static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static uint64_t get_nstime(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint64_t counts[256] = {0}; for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double ent = 0;
    for (int i = 0; i < 256; i++) if (counts[i] > 0) { double p = (double)counts[i] / len; ent -= p * log2(p); }
    return ent;
}

static void flush_flow(struct worker_t *w, struct flow_state *s, uint64_t ts_ns) {
    char sip[64], dip[64];
    if (s->meta.ip_ver == 4) { inet_ntop(AF_INET, &s->key.src_ip[12], sip, 64); inet_ntop(AF_INET, &s->key.dst_ip[12], dip, 64); }
    else { inet_ntop(AF_INET6, s->key.src_ip, sip, 64); inet_ntop(AF_INET6, s->key.dst_ip, dip, 64); }
    double duration = (double)(ts_ns - s->meta.start_time) / 1e9;
    w->s_off += snprintf(w->s_buf + w->s_off, 16384, "%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,", sip, dip, ntohs(s->key.src_port), ntohs(s->key.dst_port), s->key.protocol, (double)s->meta.start_time/1e9, sip, ntohs(s->key.src_port), dip, ntohs(s->key.dst_port), s->key.protocol, duration, s->t_pay.n, s->f_pay.n, s->b_pay.n, s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes);
    #define FMT_W(W) w->s_off += snprintf(w->s_buf + w->s_off, 2048, "%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,", W.max, W.min, W.M1, w_std(&W), w_var(&W), w_skew(&W), w_kurt(&W))
    FMT_W(s->t_pay); FMT_W(s->f_pay); FMT_W(s->b_pay); FMT_W(s->t_hdr); FMT_W(s->f_hdr); FMT_W(s->b_hdr); FMT_W(s->t_iat); FMT_W(s->f_iat); FMT_W(s->b_iat); FMT_W(s->active_s); FMT_W(s->idle_s); FMT_W(s->win_s); FMT_W(s->t_pay_delta); FMT_W(s->f_pay_delta); FMT_W(s->b_pay_delta);
    w->s_off += snprintf(w->s_buf + w->s_off, 2048, "%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,", s->f_win_init, s->b_win_init, (duration > 0 ? (s->f_bytes+s->b_bytes)/duration : 0), (duration > 0 ? s->f_bytes/duration : 0), (duration > 0 ? s->b_bytes/duration : 0), (duration > 0 ? s->t_pay.n/duration : 0), (duration > 0 ? s->b_pay.n/duration : 0), (duration > 0 ? s->f_pay.n/duration : 0), (s->f_pay.n > 0 ? (double)s->b_pay.n/s->f_pay.n : 0));
    for(int i=0; i<8; i++) w->s_off += snprintf(w->s_buf + w->s_off, 1024, "%lu,%lu,%lu,", s->flags[i], s->f_flags[i], s->b_flags[i]);
    #define FMT_H(W) for(int i=0; i<HIST_BINS; i++) w->s_off += snprintf(w->s_buf + w->s_off, 128, "%lu,", W.hist[i])
    FMT_H(s->t_pay); FMT_H(s->f_pay); FMT_H(s->b_pay);
    w->s_off += snprintf(w->s_buf + w->s_off, 1024, "%.4f,%u,%u,%u,%u,%u,%u,%.2f,%lu,%lu,%lu,%lu,%lu,%lu,%u,%u\n", s->last_entropy, s->meta.ip_ver, s->icmp_id, s->dns_q_count, s->dns_a_count, (s->dns_q_count > 0 ? (uint8_t)(s->dns_a_count/s->dns_q_count) : 0), s->dns_a_count, (s->dns_q_count > 0 ? (double)s->dns_a_count/s->dns_q_count : 0), s->f_bulk_bytes, s->f_bulk_pkts, s->f_bulk_cnt, s->b_bulk_bytes, s->b_bulk_pkts, s->b_bulk_cnt, (uint32_t)s->flags[0], (uint32_t)s->meta.eth_proto);
    if (w->s_off > IO_BUFFER_SIZE - 16384) { fwrite(w->s_buf, 1, w->s_off, w->out_f); w->s_off = 0; }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz; struct worker_t *w = ctx; const struct packet_event_t *e = data;
    uint32_t h = 0; const uint8_t *p = (const uint8_t *)&e->key;
    for (size_t i = 0; i < sizeof(struct flow_key); i++) h = h * 31 + p[i];
    uint32_t idx = h % FLOW_HASH_SIZE;
    while (w->flow_table[idx].active && memcmp(&w->flow_table[idx].key, &e->key, sizeof(struct flow_key)) != 0) idx = (idx + 1) % FLOW_HASH_SIZE;
    if (!w->flow_table[idx].active) {
        memset(&w->flow_table[idx], 0, sizeof(struct flow_state)); memcpy(&w->flow_table[idx].key, &e->key, sizeof(struct flow_key));
        memcpy(&w->flow_table[idx].meta, &e->meta, sizeof(struct flow_meta));
        w_init(&w->flow_table[idx].t_pay); w_init(&w->flow_table[idx].f_pay); w_init(&w->flow_table[idx].b_pay);
        w_init(&w->flow_table[idx].t_hdr); w_init(&w->flow_table[idx].f_hdr); w_init(&w->flow_table[idx].b_hdr);
        w_init(&w->flow_table[idx].t_iat); w_init(&w->flow_table[idx].f_iat); w_init(&w->flow_table[idx].b_iat);
        w_init(&w->flow_table[idx].active_s); w_init(&w->flow_table[idx].idle_s); w_init(&w->flow_table[idx].win_s);
        w_init(&w->flow_table[idx].t_pay_delta); w_init(&w->flow_table[idx].f_pay_delta); w_init(&w->flow_table[idx].b_pay_delta);
        w->flow_table[idx].active = 1; w->flow_table[idx].active_start = e->timestamp_ns;
        if (e->is_fwd) w->flow_table[idx].f_win_init = e->window_size; else w->flow_table[idx].b_win_init = e->window_size;
    }
    struct flow_state *s = &w->flow_table[idx];
    if (s->t_last > 0) {
        double iat = (double)(e->timestamp_ns - s->t_last) / 1e9;
        w_update(&s->t_iat, iat);
        if (iat > IDLE_THRESHOLD) { w_update(&s->active_s, (double)(s->t_last - s->active_start) / 1e9); w_update(&s->idle_s, iat); s->active_start = e->timestamp_ns; }
        w_update(&s->t_pay_delta, abs((int)e->payload_len - (int)s->t_last_sz));
    }
    s->t_last = e->timestamp_ns; s->t_last_sz = e->payload_len;
    w_update(&s->t_pay, e->payload_len); w_update(&s->t_hdr, e->header_len);
    if (e->key.protocol == 6) w_update(&s->win_s, e->window_size);
    if (e->dns_answer_count > 0) { s->dns_a_count += e->dns_answer_count; s->dns_q_count++; }
    s->last_entropy = calculate_entropy(e->payload_hint, 64);
    if (e->key.protocol == 1 || e->key.protocol == 58) s->icmp_id = (e->icmp_type << 8) | e->icmp_code;
    if (e->is_fwd) {
        if (s->f_last > 0) { 
            double f_iat = (double)(e->timestamp_ns - s->f_last) / 1e9;
            w_update(&s->f_iat, f_iat); w_update(&s->f_pay_delta, abs((int)e->payload_len - (int)s->f_last_sz));
            if (f_iat < 1.0) { s->f_bulk_bytes += e->payload_len; s->f_bulk_pkts++; } else s->f_bulk_cnt++;
        }
        s->f_last = e->timestamp_ns; s->f_last_sz = e->payload_len; w_update(&s->f_pay, e->payload_len); w_update(&s->f_hdr, e->header_len);
        s->f_bytes += e->payload_len; for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
    } else {
        if (s->b_last > 0) { 
            double b_iat = (double)(e->timestamp_ns - s->b_last) / 1e9;
            w_update(&s->b_iat, b_iat); w_update(&s->b_pay_delta, abs((int)e->payload_len - (int)s->b_last_sz));
            if (b_iat < 1.0) { s->b_bulk_bytes += e->payload_len; s->b_bulk_pkts++; } else s->b_bulk_cnt++;
        }
        s->b_last = e->timestamp_ns; s->b_last_sz = e->payload_len; w_update(&s->b_pay, e->payload_len); w_update(&s->b_hdr, e->header_len);
        s->b_bytes += e->payload_len; for (int i=0; i<8; i++) if (e->tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
    }
    bool flush = (e->tcp_flags & 0x05) || (s->t_pay.n >= SEGMENT_THRESHOLD);
    if (flush) { flush_flow(w, s, e->timestamp_ns); s->active = 0; }
    w->processed_events++;
    return 0;
}

void *worker_fn(void *arg) {
    struct worker_t *w = arg; cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(w->id % 256, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    char fname[256]; sprintf(fname, "worker_telemetry/cpu_%d.csv", w->id);
    w->out_f = fopen(fname, "w"); if (!w->out_f) return NULL;
    setvbuf(w->out_f, NULL, _IOFBF, IO_BUFFER_SIZE);
    fprintf(w->out_f, "flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,pkt_count,fwd_count,bwd_count,tot_bytes,fwd_bytes,bwd_bytes,");
    const char *metrics[] = {"pay", "fwd_pay", "bwd_pay", "hdr", "fwd_hdr", "bwd_hdr", "iat", "fwd_iat", "bwd_iat", "active", "idle", "win", "pay_delta", "fwd_pay_delta", "bwd_pay_delta"};
    for(int i=0; i<15; i++) fprintf(w->out_f, "%s_max,%s_min,%s_mean,%s_std,%s_var,%s_skew,%s_kurt,", metrics[i], metrics[i], metrics[i], metrics[i], metrics[i], metrics[i], metrics[i]);
    fprintf(w->out_f, "fwd_win_init,bwd_win_init,bytes_rate,fwd_bytes_rate,bwd_bytes_rate,packets_rate,bwd_packets_rate,fwd_packets_rate,down_up_rate,");
    const char *flags[] = {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"};
    for(int i=0; i<8; i++) fprintf(w->out_f, "%s_cnt,fwd_%s_cnt,bwd_%s_cnt,", flags[i], flags[i], flags[i]);
    const char *h_sets[] = {"t_pay", "f_pay", "b_pay"};
    for(int i=0; i<3; i++) for(int j=0; j<HIST_BINS; j++) fprintf(w->out_f, "hist_%s_bin%d,", h_sets[i], j);
    fprintf(w->out_f, "payload_entropy,ip_ver,icmp_id,dns_query_cnt,dns_ans_total,dns_ratio_int,dns_ans_count,dns_ratio_float,f_bulk_bytes,f_bulk_pkts,f_bulk_cnt,b_bulk_bytes,b_bulk_pkts,b_bulk_cnt,tcp_flags_total,eth_proto\n");
    w->s_buf = malloc(IO_BUFFER_SIZE); w->s_off = 0;
    w->flow_table = calloc(FLOW_HASH_SIZE, sizeof(struct flow_state));
    w->rb = ring_buffer__new(w->rb_fd, handle_event, w, NULL);
    while (!exiting) {
        ring_buffer__poll(w->rb, 100);
        static uint32_t scan_idx = 0; uint64_t now = get_nstime();
        for (int i=0; i<1000; i++) { scan_idx = (scan_idx + 1) % FLOW_HASH_SIZE; if (w->flow_table[scan_idx].active && (now - w->flow_table[scan_idx].t_last > IDLE_TIMEOUT_NS)) { flush_flow(w, &w->flow_table[scan_idx], now); w->flow_table[scan_idx].active = 0; } }
    }
    if (w->s_off > 0) fwrite(w->s_buf, 1, w->s_off, w->out_f);
    fclose(w->out_f); free(w->s_buf); free(w->flow_table); ring_buffer__free(w->rb);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1; struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    mkdir("worker_telemetry", 0777);
    int cores = sysconf(_SC_NPROCESSORS_ONLN); num_workers = cores;
    workers = calloc(num_workers, sizeof(struct worker_t));
    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) return 1;
    int outer_fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf_map");
    for (int i = 0; i < num_workers; i++) {
        workers[i].id = i; workers[i].rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, 32 * 1024 * 1024, NULL);
        bpf_map_update_elem(outer_fd, &i, &workers[i].rb_fd, BPF_ANY);
    }
    fprintf(stderr, "🚀 [Lynceus Core] %d Workers (Scientific 399 Ready)\n", num_workers);
    for (int i = 0; i < num_workers; i++) pthread_create(&workers[i].thread, NULL, worker_fn, &workers[i]);
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));
    for (int i = 0; i < num_workers; i++) pthread_join(workers[i].thread, NULL);
    bpf_object__close(obj); return 0;
}
