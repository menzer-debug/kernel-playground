#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

static volatile int g_running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static const char *ip_str(__u32 ip_net)
{
    struct in_addr addr = { .s_addr = ip_net };
    return inet_ntoa(addr);
}

static void print_blacklist(int bl_fd)
{
    printf("\n=== BLACKLISTED SCANNERS ===\n");
    __u32 prev_key = 0, key = 0;
    __u8  val = 0;
    int   count = 0, first = 1;
    while (bpf_map_get_next_key(bl_fd, first ? NULL : &prev_key, &key) == 0) {
        first = 0;
        prev_key = key;
        if (bpf_map_lookup_elem(bl_fd, &key, &val) == 0) {
            printf("  BLOCKED: %s\n", ip_str(key));
            count++;
        }
    }
    if (count == 0)
        printf("  (none yet)\n");
}

static void print_tracker(int tr_fd)
{
    printf("\n=== TRACKED IPs ===\n");
    printf("  %-20s %10s %10s %s\n", "Source IP", "UniqPorts", "TotalSYNs", "Status");
    __u32 prev_key = 0, key = 0;
    struct ip_scan_info info;
    int shown = 0, first = 1;
    while (shown < 10 && bpf_map_get_next_key(tr_fd, first ? NULL : &prev_key, &key) == 0) {
        first = 0;
        prev_key = key;
        if (bpf_map_lookup_elem(tr_fd, &key, &info) != 0)
            continue;
        if (info.total_syns == 0)
            continue;
        const char *status = (info.unique_port_count >= PORT_SCAN_THRESHOLD) ? "SCANNER!" : "watching";
        printf("  %-20s %10llu %10llu  [%s]\n", ip_str(key), info.unique_port_count, info.total_syns, status);
        shown++;
    }
    if (shown == 0)
        printf("  (no SYN traffic yet)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *ifname  = argv[1];
    int         ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found: %s\n", ifname, strerror(errno));
        return EXIT_FAILURE;
    }
    struct bpf_object *obj = bpf_object__open("e5_kern.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open e5_kern.bpf.o\n");
        return EXIT_FAILURE;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object.\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "port_scanner_detect");
    if (!prog) {
        fprintf(stderr, "Program not found.\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        perror("bpf_xdp_attach");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    struct bpf_map *bl_map = bpf_object__find_map_by_name(obj, "blacklist");
    struct bpf_map *tr_map = bpf_object__find_map_by_name(obj, "syn_tracker");
    if (!bl_map || !tr_map) {
        fprintf(stderr, "Could not find BPF maps.\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    int bl_fd = bpf_map__fd(bl_map);
    int tr_fd = bpf_map__fd(tr_map);
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    printf("=== E5 Port Scanner Detector ===\n");
    printf("Interface : %s\n", ifname);
    printf("Threshold : %d unique ports / 10s\n", PORT_SCAN_THRESHOLD);
    printf("Press Ctrl+C to stop.\n");
    while (g_running) {
        sleep(3);
        if (!g_running) break;
        print_blacklist(bl_fd);
        print_tracker(tr_fd);
        printf("\n---------------------------------\n");
    }
    printf("\nDetaching from %s...\n", ifname);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("Done.\n");
    return EXIT_SUCCESS;
}
