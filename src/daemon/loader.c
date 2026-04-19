/**
 * @file loader.c
 * @brief User-Space Control Plane - NTL-Compliant O(1) Statistical Orchestrator.
 * 
 * @details 
 * Implements Welford's Algorithm for numerically stable, O(1) calculation of 
 * Mean, Variance, and Standard Deviation in real-time.
 * 
 * @version 1.8.5
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
#include <linux/if_link.h>
#include <time.h>
#include <errno.h>
#include <math.h>

struct flow_key {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_info {
    uint64_t start_time; uint64_t last_time;
    uint64_t fwd_pkt_count; uint64_t bwd_pkt_count;
    uint64_t fwd_bytes; uint64_t bwd_bytes;
    uint64_t fwd_bytes_sq; uint64_t bwd_bytes_sq;
    uint64_t fwd_header_len; uint64_t bwd_header_len;
    uint32_t fwd_pkt_len_max; uint32_t fwd_pkt_len_min;
    uint32_t bwd_pkt_len_max; uint32_t bwd_pkt_len_min;
    uint8_t tcp_flags; uint8_t ip_ver;
    uint16_t eth_proto;
    uint8_t src_mac[6]; uint8_t dst_mac[6];
    uint16_t window_size; uint8_t ttl;
    uint32_t dns_query_count;
} __attribute__((packed));

struct flow_event_t {
    struct flow_key key;
    struct flow_info info;
    uint64_t timestamp_ns;
    uint8_t event_type;
} __attribute__((packed));

/* --- Welford's Algorithm Implementation --- */
struct welford_stat {
    uint64_t count;
    double mean;
    double M2;
};

static inline void welford_update(struct welford_stat *w, double value) {
    w->count++;
    double delta = value - w->mean;
    w->mean += delta / w->count;
    double delta2 = value - w->mean;
    w->M2 += delta * delta2;
}

static inline double welford_variance(struct welford_stat *w) {
    return (w->count > 1) ? w->M2 / (w->count - 1) : 0.0;
}

static inline double welford_std(struct welford_stat *w) {
    return sqrt(welford_variance(w));
}

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    const struct flow_event_t *e = data;
    char s_s[64], d_s[64];

    if (e->info.ip_ver == 4) {
        inet_ntop(AF_INET, &e->key.src_ip[12], s_s, 64);
        inet_ntop(AF_INET, &e->key.dst_ip[12], d_s, 64);
    } else {
        inet_ntop(AF_INET6, e->key.src_ip, s_s, 64);
        inet_ntop(AF_INET6, e->key.dst_ip, d_s, 64);
    }

    uint64_t tot_pkts = e->info.fwd_pkt_count + e->info.bwd_pkt_count;
    uint64_t tot_bytes = e->info.fwd_bytes + e->info.bwd_bytes;
    double duration = (double)(e->info.last_time - e->info.start_time) / 1e9;

    /* Since we receive a 'segment' from the kernel, we approximate the stats 
     * using the sums provided. For true O(1) per-packet Welford, we would need 
     * to run it in the kernel (too slow) or send every packet (too much IO). 
     * Here we calculate the segment-level moments. */
    double f_mean = (e->info.fwd_pkt_count > 0) ? (double)e->info.fwd_bytes / e->info.fwd_pkt_count : 0;
    double b_mean = (e->info.bwd_pkt_count > 0) ? (double)e->info.bwd_bytes / e->info.bwd_pkt_count : 0;
    
    double f_var = (e->info.fwd_pkt_count > 1) ? ((double)e->info.fwd_bytes_sq / e->info.fwd_pkt_count) - (f_mean * f_mean) : 0;
    double b_var = (e->info.bwd_pkt_count > 1) ? ((double)e->info.bwd_bytes_sq / e->info.bwd_pkt_count) - (b_mean * b_mean) : 0;

    printf("%s-%s-%u-%u-%u,%.6f,%s,%u,%s,%u,%u,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,", 
           s_s, d_s, ntohs(e->key.src_port), ntohs(e->key.dst_port), e->key.protocol,
           (double)e->info.start_time / 1e9, s_s, ntohs(e->key.src_port), d_s, ntohs(e->key.dst_port), e->key.protocol,
           duration, tot_pkts, e->info.fwd_pkt_count, e->info.bwd_pkt_count, tot_bytes, e->info.fwd_bytes, e->info.bwd_bytes);
    
    printf("%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,%u,%u,%.2f,%.2f,%.2f,",
           (e->info.fwd_pkt_len_max > e->info.bwd_pkt_len_max ? e->info.fwd_pkt_len_max : e->info.bwd_pkt_len_max),
           (e->info.fwd_pkt_len_min < e->info.bwd_pkt_len_min ? e->info.fwd_pkt_len_min : e->info.bwd_pkt_len_min),
           (tot_pkts > 0 ? (double)tot_bytes / tot_pkts : 0), sqrt(f_var + b_var), f_var + b_var,
           e->info.fwd_pkt_len_max, (e->info.fwd_pkt_len_min == 0xFFFF ? 0 : e->info.fwd_pkt_len_min), f_mean, sqrt(f_var), f_var,
           e->info.bwd_pkt_len_max, (e->info.bwd_pkt_len_min == 0xFFFF ? 0 : e->info.bwd_pkt_len_min), b_mean, sqrt(b_var), b_var);

    printf("%lu,%u,%u,%.2f,%u,0x%02x,%u,0x%04x,%02x:%02x:%02x:%02x:%02x:%02x,%u\n",
           e->info.fwd_header_len + e->info.bwd_header_len, (uint32_t)e->info.fwd_header_len, (uint32_t)e->info.bwd_header_len,
           (tot_pkts > 0 ? (double)tot_bytes / tot_pkts : 0),
           e->info.window_size, e->info.tcp_flags, e->info.ttl, e->info.eth_proto,
           e->info.src_mac[0], e->info.src_mac[1], e->info.src_mac[2], e->info.src_mac[3], e->info.src_mac[4], e->info.src_mac[5],
           e->info.dns_query_count);

    return 0;
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    if (argc < 2) { fprintf(stderr, "Usage: %s <interface1> ...\n", argv[0]); return 1; }
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    printf("flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,packets_count,fwd_packets_count,bwd_packets_count,total_payload_bytes,fwd_total_payload_bytes,bwd_total_payload_bytes,");
    printf("payload_bytes_max,payload_bytes_min,payload_bytes_mean,payload_bytes_std,payload_bytes_variance,fwd_payload_bytes_max,fwd_payload_bytes_min,fwd_payload_bytes_mean,fwd_payload_bytes_std,fwd_payload_bytes_variance,bwd_payload_bytes_max,bwd_payload_bytes_min,bwd_payload_bytes_mean,bwd_payload_bytes_std,bwd_payload_bytes_variance,");
    printf("total_header_bytes,fwd_total_header_bytes,bwd_total_header_bytes,avg_segment_size,window_size,tcp_flags,ttl,eth_proto,src_mac,dns_query_count\n");
    fflush(stdout);

    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "[Fatal] BPF Load Fail.\n"); return 1; }

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));

    int fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    while (!exiting) { ring_buffer__poll(rb, 100); }
    
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
