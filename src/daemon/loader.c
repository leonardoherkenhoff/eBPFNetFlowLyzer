/**
 * @file loader.c
 * @brief User-Space Control Plane - NTLFlowLyzer Hybrid Orchestrator.
 * 
 * Version: 1.6.0
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

struct flow_key {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct flow_info {
    uint64_t start_time; uint64_t last_time;
    uint64_t fwd_pkt_count; uint64_t bwd_pkt_count;
    uint64_t fwd_bytes; uint64_t bwd_bytes;
    uint64_t fwd_header_len; uint64_t bwd_header_len;
    uint32_t fwd_pkt_len_max; uint32_t fwd_pkt_len_min;
    uint32_t bwd_pkt_len_max; uint32_t bwd_pkt_len_min;
    uint8_t tcp_flags; uint8_t ip_ver;
    uint16_t eth_proto;
    uint8_t src_mac[6]; uint8_t dst_mac[6];
    uint16_t window_size; uint8_t ttl;
} __attribute__((packed));

struct flow_event_t {
    struct flow_key key;
    struct flow_info info;
    uint64_t timestamp_ns;
} __attribute__((packed));

static volatile bool exiting = false;
static int raw_pkt_map_fd = -1;

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

    double duration = (double)(e->info.last_time - e->info.start_time) / 1000000.0; // ms
    double fwd_mean = (e->info.fwd_pkt_count > 0) ? (double)e->info.fwd_bytes / e->info.fwd_pkt_count : 0;
    double bwd_mean = (e->info.bwd_pkt_count > 0) ? (double)e->info.bwd_bytes / e->info.bwd_pkt_count : 0;

    printf("%s,%s,%u,%u,%u,0x%04x,%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x,%lu,%.4f,%lu,%lu,%lu,%lu,%u,%u,%.2f,%u,%u,%.2f,%lu,%lu,0x%02x,%u,%u\n",
           s_s, d_s, ntohs(e->key.src_port), ntohs(e->key.dst_port), (unsigned int)e->key.protocol,
           e->info.eth_proto,
           e->info.src_mac[0], e->info.src_mac[1], e->info.src_mac[2], e->info.src_mac[3], e->info.src_mac[4], e->info.src_mac[5],
           e->info.dst_mac[0], e->info.dst_mac[1], e->info.dst_mac[2], e->info.dst_mac[3], e->info.dst_mac[4], e->info.dst_mac[5],
           e->info.start_time, duration,
           e->info.fwd_pkt_count, e->info.bwd_pkt_count, e->info.fwd_bytes, e->info.bwd_bytes,
           e->info.fwd_pkt_len_max, (e->info.fwd_pkt_len_min == 0xFFFF ? 0 : e->info.fwd_pkt_len_min), fwd_mean,
           e->info.bwd_pkt_len_max, (e->info.bwd_pkt_len_min == 0xFFFF ? 0 : e->info.bwd_pkt_len_min), bwd_mean,
           e->info.fwd_header_len, e->info.bwd_header_len,
           (unsigned int)e->info.tcp_flags, (unsigned int)e->info.window_size, (unsigned int)e->info.ttl);
    
    return 0;
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    if (argc < 2) { fprintf(stderr, "Usage: %s <interface1> ...\n", argv[0]); return 1; }
    
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    printf("src_ip,dst_ip,src_port,dst_port,protocol,eth_proto,src_mac,dst_mac,timestamp,flow_duration,tot_fwd_pkts,tot_bwd_pkts,tot_len_fwd_pkts,tot_len_bwd_pkts,fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,fwd_header_len,bwd_header_len,tcp_flags,window_size,ttl\n");
    fflush(stdout);

    struct bpf_object *obj = bpf_object__open_file("build/main.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "[Fatal] BPF Load Fail.\n"); return 1; }

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "xdp_prog");
    for (int i = 1; i < argc; i++) bpf_program__attach_xdp(p, if_nametoindex(argv[i]));

    int fd = bpf_object__find_map_fd_by_name(obj, "flows_ringbuf");
    struct ring_buffer *rb = ring_buffer__new(fd, handle_event, NULL, NULL);
    
    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }
    
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
