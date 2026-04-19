/**
 * @file loader.c
 * @brief User-Space Control Plane - Streaming Welford Orchestrator (v1.9.0).
 * 
 * @details 
 * Calculates progressive statistical moments (Mean, Variance, StdDev) for every 
 * packet event in a flow using Welford's Algorithm.
 * 
 * @version 1.9.0
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

#define HASH_SIZE 65536

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
    uint64_t count;
    double mean;
    double M2;
};

struct flow_state {
    struct flow_key key;
    struct welford_stat fwd_stats;
    struct welford_stat bwd_stats;
    uint64_t last_pkt_ts;
    int active;
};

static struct flow_state flow_table[HASH_SIZE];

static inline void welford_update(struct welford_stat *w, double val) {
    w->count++;
    double delta = val - w->mean;
    w->mean += delta / w->count;
    double delta2 = val - w->mean;
    w->M2 += delta * delta2;
}

static inline double welford_std(struct welford_stat *w) {
    return (w->count > 1) ? sqrt(w->M2 / (w->count - 1)) : 0.0;
}

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
        flow_table[idx].active = 1;
    }

    struct flow_state *s = &flow_table[idx];
    if (e->is_fwd) welford_update(&s->fwd_stats, e->payload_len);
    else welford_update(&s->bwd_stats, e->payload_len);

    char s_ip[64], d_ip[64];
    if (e->meta.ip_ver == 4) {
        inet_ntop(AF_INET, &e->key.src_ip[12], s_ip, 64);
        inet_ntop(AF_INET, &e->key.dst_ip[12], d_ip, 64);
    } else {
        inet_ntop(AF_INET6, e->key.src_ip, s_ip, 64);
        inet_ntop(AF_INET6, e->key.dst_ip, d_ip, 64);
    }

    /* Output high-resolution streaming telemetry */
    printf("%s,%s,%u,%u,%u,%u,%u,%lu,%lu,%.2f,%.2f,%.2f,%.2f,0x%02x,%u\n",
           s_ip, d_ip, ntohs(e->key.src_port), ntohs(e->key.dst_port), 
           e->key.protocol, e->payload_len, e->is_fwd,
           s->fwd_stats.count, s->bwd_stats.count,
           s->fwd_stats.mean, welford_std(&s->fwd_stats),
           s->bwd_stats.mean, welford_std(&s->bwd_stats),
           e->tcp_flags, e->ttl);

    if (e->tcp_flags & 0x05) s->active = 0; // Clear on FIN/RST

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <interface>\n", argv[0]); return 1; }
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    printf("src_ip,dst_ip,src_port,dst_port,protocol,pkt_len,is_fwd,fwd_count,bwd_count,fwd_mean,fwd_std,bwd_mean,bwd_std,tcp_flags,ttl\n");
    
    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) return 1;

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));

    int fd = bpf_object__find_map_fd_by_name(obj, "pkt_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    while (!exiting) { ring_buffer__poll(rb, 100); }
    
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
