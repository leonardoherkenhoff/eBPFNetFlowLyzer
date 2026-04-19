/**
 * @file loader.c
 * @brief User-Space Control Plane - Stateless Telemetry Orchestrator.
 * 
 * @details 
 * Manages the lifecycle of the eBPF Data Plane and provides a high-throughput 
 * bridge between the kernel RingBuffer and the research CSV storage. 
 * Optimized for stateless packet-level traces where every event is exported 
 * without aggregation to preserve temporal entropy for Machine Learning models.
 * 
 * Performance Considerations:
 * - Uses Libbpf RingBuffer API for lockless event consumption.
 * - Redirects diagnostic forensics to stderr to prevent CSV header pollution.
 * - Supports multi-interface attachment for topological visibility.
 * 
 * @version 1.5.0
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

struct flow_event_t {
    uint8_t src_ip[16]; uint8_t dst_ip[16];
    uint16_t src_port; uint16_t dst_port;
    uint8_t protocol; uint8_t ip_ver;
    uint16_t payload_length; uint16_t header_length;
    uint8_t tcp_flags; uint8_t ttl;
    uint16_t window_size; uint64_t timestamp_ns;
    uint16_t eth_proto;
    uint8_t src_mac[6]; uint8_t dst_mac[6];
    uint8_t sni_hostname[64];
    uint8_t dns_payload_raw[256];
} __attribute__((packed));

static volatile bool exiting = false;
static int raw_pkt_map_fd = -1;

static void sig_handler(int sig) { (void)sig; exiting = true; }

/** @brief Optimized CSV exporter for atomic packet events. */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    const struct flow_event_t *e = data;
    char s_s[64], d_s[64];

    if (e->ip_ver == 4) {
        inet_ntop(AF_INET, &e->src_ip[12], s_s, 64);
        inet_ntop(AF_INET, &e->dst_ip[12], d_s, 64);
    } else if (e->ip_ver == 6) {
        inet_ntop(AF_INET6, e->src_ip, s_s, 64);
        inet_ntop(AF_INET6, e->dst_ip, d_s, 64);
    } else {
        snprintf(s_s, 64, "0.0.0.0"); snprintf(d_s, 64, "0.0.0.0");
    }

    /* Format: timestamp,eth_proto,src_mac,dst_mac,src_ip,dst_ip,src_p,dst_p,proto,len,ttl,flags... */
    printf("%lu,0x%04x,%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x,%s,%s,%u,%u,%u,%u,%u,0x%02x,%u\n",
           e->timestamp_ns, e->eth_proto,
           e->src_mac[0], e->src_mac[1], e->src_mac[2], e->src_mac[3], e->src_mac[4], e->src_mac[5],
           e->dst_mac[0], e->dst_mac[1], e->dst_mac[2], e->dst_mac[3], e->dst_mac[4], e->dst_mac[5],
           s_s, d_s, ntohs(e->src_port), ntohs(e->dst_port), 
           (unsigned int)e->protocol, (unsigned int)e->payload_length, (unsigned int)e->ttl, 
           (unsigned int)e->tcp_flags, (unsigned int)ntohs(e->window_size));
    
    return 0;
}

void print_diagnostics(struct bpf_object *obj) {
    uint32_t key = 0; uint64_t raw = 0;
    if (raw_pkt_map_fd >= 0) bpf_map_lookup_elem(raw_pkt_map_fd, &key, &raw);
    fprintf(stderr, "\n📊 [Diagnostic] High-Res Packets Exported: %lu\n", raw);
    
    int err_fd = bpf_object__find_map_fd_by_name(obj, "error_stats");
    if (err_fd >= 0) {
        uint32_t e_key = 0, next_e_key; uint64_t e_val;
        fprintf(stderr, "   ⚠️ [System Health]:\n");
        while (bpf_map_get_next_key(err_fd, &e_key, &next_e_key) == 0) {
            bpf_map_lookup_elem(err_fd, &next_e_key, &e_val);
            if (next_e_key == 6) fprintf(stderr, "      - RingBuffer Overflows: %lu\n", e_val);
            e_key = next_e_key;
        }
    }
    fflush(stderr);
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}; setrlimit(RLIMIT_MEMLOCK, &r);
    if (argc < 2) { fprintf(stderr, "Usage: %s <interface1> [interface2] ...\n", argv[0]); return 1; }
    
    /* Redirect diagnostics to stderr for CSV purity */
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    /* Scientific Header Definition */
    printf("timestamp_ns,eth_proto,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,protocol,pkt_len,ttl,tcp_flags,window_size\n");
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
    raw_pkt_map_fd = bpf_object__find_map_fd_by_name(obj, "raw_pkt_count");

    time_t last_diag = time(NULL);
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;
        
        if (time(NULL) - last_diag >= 5) {
            print_diagnostics(obj);
            last_diag = time(NULL);
        }
    }

    print_diagnostics(obj);
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
