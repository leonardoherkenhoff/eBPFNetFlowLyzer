/**
 * @file loader.c
 * @brief User-Space Control Plane - Milestone 3: Industrial Real-Time Extractor (v1.9.4).
 * 
 * @details 
 * Implementação de alto desempenho otimizada para o processador XEON SILVER 4410Y.
 * Utiliza escalonamento dinâmico de threads com afinidade de CPU (Thread Pinning) 
 * e motor de análise particionado para o ciclo autonômico MAPE-K.
 * 
 * @version 1.9.4 (Xeon Optimized Edition)
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

#define HASH_SIZE 32768
#define HISTOGRAM_BINS 64
#define QUEUE_SIZE 131072

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
    double median; uint32_t hist[HISTOGRAM_BINS];
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
    if (w->n == 1) w->median = x; else w->median += (x > w->median ? 1.0 : -1.0) * (fabs(x - w->median) / w->n);
    uint32_t bin = (uint32_t)x / 32; if (bin < HISTOGRAM_BINS) w->hist[bin]++;
}

static inline double w_std(struct w_stat *w) { return (w->n > 1) ? sqrt(w->M2 / (w->n - 1)) : 0; }
static inline double w_var(struct w_stat *w) { return (w->n > 1) ? w->M2 / (w->n - 1) : 0; }
static inline double w_skew(struct w_stat *w) { return (w->M2 > 1e-9) ? sqrt(w->n) * w->M3 / pow(w->M2, 1.5) : 0; }
static inline double w_kurt(struct w_stat *w) { return (w->M2 > 1e-9) ? (double)w->n * w->M4 / (w->M2 * w->M2) - 3.0 : 0; }
static inline double w_cov(struct w_stat *w) { double s = w_std(w); return (w->M1 != 0) ? s / w->M1 : 0; }
static inline uint32_t w_mode(struct w_stat *w) { 
    uint32_t max_v = 0, m_bin = 0; for(int i=0; i<HISTOGRAM_BINS; i++) if(w->hist[i] > max_v) { max_v = w->hist[i]; m_bin = i; }
    return m_bin * 32;
}

struct flow_state {
    struct flow_key key; struct flow_meta meta;
    struct w_stat t_pay, f_pay, b_pay, t_hdr, f_hdr, b_hdr, t_iat, f_iat, b_iat, t_d_pay, f_d_pay, b_d_pay;
    uint64_t f_bytes, b_bytes, f_last, b_last, t_last;
    uint32_t f_l_pay, b_l_pay, t_l_pay;
    uint64_t flags[8], f_flags[8], b_flags[8];
    int active;
};

struct worker_t {
    pthread_t thread;
    struct packet_event_t *queue;
    volatile uint64_t head, tail;
    struct flow_state *flow_table;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int id;
};

static struct worker_t *workers;
static int num_workers = 1;
static volatile bool exiting = false;

static void sig_handler(int sig) { (void)sig; exiting = true; for(int i=0; i<num_workers; i++) pthread_cond_signal(&workers[i].cond); }

static uint32_t hash_key(struct flow_key *k) {
    uint32_t h = 0; for (int i = 0; i < 16; i++) h = h * 31 + k->src_ip[i] + k->dst_ip[i];
    return (h * 31 + k->src_port + k->dst_port + k->protocol);
}

void *worker_fn(void *arg) {
    struct worker_t *w = arg;
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(w->id + 1, &cpuset);
    pthread_setaffinity_np(w->thread, sizeof(cpu_set_t), &cpuset);
    
    char s_buf[4096];
    while (!exiting) {
        pthread_mutex_lock(&w->mutex);
        while (w->head == w->tail && !exiting) pthread_cond_wait(&w->cond, &w->mutex);
        if (exiting && w->head == w->tail) { pthread_mutex_unlock(&w->mutex); break; }
        struct packet_event_t e = w->queue[w->tail % QUEUE_SIZE];
        w->tail++;
        pthread_mutex_unlock(&w->mutex);

        uint32_t idx = hash_key(&e.key) % HASH_SIZE;
        while (w->flow_table[idx].active && memcmp(&w->flow_table[idx].key, &e.key, sizeof(struct flow_key)) != 0) idx = (idx + 1) % HASH_SIZE;
        if (!w->flow_table[idx].active) {
            memset(&w->flow_table[idx], 0, sizeof(struct flow_state)); memcpy(&w->flow_table[idx].key, &e.key, sizeof(struct flow_key));
            memcpy(&w->flow_table[idx].meta, &e.meta, sizeof(struct flow_meta));
            w_init(&w->flow_table[idx].t_pay); w_init(&w->flow_table[idx].f_pay); w_init(&w->flow_table[idx].b_pay);
            w_init(&w->flow_table[idx].t_hdr); w_init(&w->flow_table[idx].f_hdr); w_init(&w->flow_table[idx].b_hdr);
            w_init(&w->flow_table[idx].t_iat); w_init(&w->flow_table[idx].f_iat); w_init(&w->flow_table[idx].b_iat);
            w_init(&w->flow_table[idx].t_d_pay); w_init(&w->flow_table[idx].f_d_pay); w_init(&w->flow_table[idx].b_d_pay);
            w->flow_table[idx].active = 1;
        }

        struct flow_state *s = &w->flow_table[idx];
        double duration = (double)(e.timestamp_ns - s->meta.start_time) / 1e9;
        if (s->t_last > 0) {
            w_update(&s->t_iat, (double)(e.timestamp_ns - s->t_last) / 1e9);
            w_update(&s->t_d_pay, abs((int)e.payload_len - (int)s->t_l_pay));
        }
        s->t_last = e.timestamp_ns; s->t_l_pay = e.payload_len;
        w_update(&s->t_pay, e.payload_len); w_update(&s->t_hdr, e.header_len);
        if (e.is_fwd) {
            if (s->f_last > 0) w_update(&s->f_iat, (double)(e.timestamp_ns - s->f_last) / 1e9);
            s->f_last = e.timestamp_ns; w_update(&s->f_pay, e.payload_len); w_update(&s->f_hdr, e.header_len);
            s->f_bytes += e.payload_len; for (int i=0; i<8; i++) if (e.tcp_flags & (1<<i)) { s->flags[i]++; s->f_flags[i]++; }
        } else {
            if (s->b_last > 0) w_update(&s->b_iat, (double)(e.timestamp_ns - s->b_last) / 1e9);
            s->b_last = e.timestamp_ns; w_update(&s->b_pay, e.payload_len); w_update(&s->b_hdr, e.header_len);
            s->b_bytes += e.payload_len; for (int i=0; i<8; i++) if (e.tcp_flags & (1<<i)) { s->flags[i]++; s->b_flags[i]++; }
        }

        char sip[64], dip[64];
        if (s->meta.ip_ver == 4) { inet_ntop(AF_INET, &e.key.src_ip[12], sip, 64); inet_ntop(AF_INET, &e.key.dst_ip[12], dip, 64); }
        else { inet_ntop(AF_INET6, e.key.src_ip, sip, 64); inet_ntop(AF_INET6, e.key.dst_ip, dip, 64); }

        int off = snprintf(s_buf, sizeof(s_buf), "%s-%s-%u-%u-%u,%s,%u,%s,%u,%u,%.6f,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,%.2f,%.2f,", sip, dip, ntohs(e.key.src_port), ntohs(e.key.dst_port), e.key.protocol, sip, ntohs(e.key.src_port), dip, ntohs(e.key.dst_port), e.key.protocol, (double)s->meta.start_time / 1e9, duration, s->t_pay.n, s->f_pay.n, s->b_pay.n, s->f_bytes + s->b_bytes, s->f_bytes, s->b_bytes, (s->b_pay.n > 0 ? (double)s->f_pay.n/s->b_pay.n : 0), (s->b_bytes > 0 ? (double)s->f_bytes/s->b_bytes : 0));
        
        #define FMT_W(W) off += snprintf(s_buf + off, sizeof(s_buf) - off, "%u,%u,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%u,", W.max, W.min, W.M1, w_std(&W), w_var(&W), W.median, w_skew(&W), w_kurt(&W), w_cov(&W), W.mode)
        FMT_W(s->t_pay); FMT_W(s->f_pay); FMT_W(s->b_pay); FMT_W(s->t_hdr); FMT_W(s->f_hdr); FMT_W(s->b_hdr);
        FMT_W(s->t_iat); FMT_W(s->f_iat); FMT_W(s->b_iat); FMT_W(s->t_d_pay); FMT_W(s->f_d_pay); FMT_W(s->b_d_pay);
        for(int i=0; i<8; i++) off += snprintf(s_buf + off, sizeof(s_buf) - off, "%lu,%lu,%lu,", s->flags[i], s->f_flags[i], s->b_flags[i]);
        off += snprintf(s_buf + off, sizeof(s_buf) - off, "%.4f,%u,%u,%u\n", (double)e.payload_len/64.0, e.icmp_type, e.icmp_code, e.ttl);
        
        fwrite(s_buf, 1, off, stdout);
        if (e.tcp_flags & 0x05) s->active = 0;
    }
    return NULL;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz; const struct packet_event_t *e = data;
    uint32_t w_idx = hash_key((struct flow_key *)&e->key) % num_workers;
    struct worker_t *w = &workers[w_idx];
    pthread_mutex_lock(&w->mutex);
    if (w->head - w->tail < QUEUE_SIZE) {
        w->queue[w->head % QUEUE_SIZE] = *e;
        w->head++;
        pthread_cond_signal(&w->cond);
    }
    pthread_mutex_unlock(&w->mutex);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1; struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    static char out_buf[4 * 1024 * 1024]; setvbuf(stdout, out_buf, _IOFBF, sizeof(out_buf));

    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    num_workers = (cores > 1) ? cores - 1 : 1;
    workers = calloc(num_workers, sizeof(struct worker_t));

    printf("flow_id,src_ip,src_port,dst_ip,dst_port,protocol,timestamp,duration,PacketsCount,FwdPacketsCount,BwdPacketsCount,TotalBytes,FwdBytes,BwdBytes,FwdBwdPktRatio,FwdBwdByteRatio,");
    const char *dirs[] = {"Tot", "Fwd", "Bwd"}; const char *metrics[] = {"Pay", "Hdr", "IAT", "DeltaLen"};
    for(int m=0; m<4; m++) for(int d=0; d<3; d++) printf("%s_%s_Max,%s_%s_Min,%s_%s_Mean,%s_%s_Std,%s_%s_Var,%s_%s_Median,%s_%s_Skew,%s_%s_Kurt,%s_%s_CoV,%s_%s_Mode,", dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m], dirs[d], metrics[m]);
    const char *flgs[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    for(int i=0; i<8; i++) printf("%s_Cnt,%s_Fwd_Cnt,%s_Bwd_Cnt,", flgs[i], flgs[i], flgs[i]);
    printf("PayloadEntropy,IcmpType,IcmpCode,TTL\n");

    for (int i = 0; i < num_workers; i++) {
        workers[i].id = i; 
        workers[i].queue = malloc(sizeof(struct packet_event_t) * QUEUE_SIZE);
        workers[i].flow_table = calloc(HASH_SIZE, sizeof(struct flow_state));
        pthread_mutex_init(&workers[i].mutex, NULL);
        pthread_cond_init(&workers[i].cond, NULL); 
        pthread_create(&workers[i].thread, NULL, worker_fn, &workers[i]);
    }

    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) return 1;
    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));
    int fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    while (!exiting) ring_buffer__poll(rb, 100);
    for (int i = 0; i < num_workers; i++) pthread_join(workers[i].thread, NULL);
    ring_buffer__free(rb); bpf_object__close(obj); return 0;
}
