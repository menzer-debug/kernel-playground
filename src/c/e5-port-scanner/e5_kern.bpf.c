// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_IPS);
    __type(key,   __u32);
    __type(value, struct ip_scan_info);
} syn_tracker SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PORT_ENTRIES);
    __type(key,   __u64);
    __type(value, __u64);
} seen_ports SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST);
    __type(key,   __u32);
    __type(value, __u8);
} blacklist SEC(".maps");

static __always_inline int
parse_tcp_syn(struct xdp_md *ctx, __u32 *out_src_ip, __u16 *out_dst_port)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    if (ip->ihl < 5)
        return -1;

    if (ip->protocol != IPPROTO_TCP)
        return -1;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return -1;

    if (!tcp->syn || tcp->ack)
        return -1;

    *out_src_ip   = ip->saddr;
    *out_dst_port = bpf_ntohs(tcp->dest);
    return 0;
}

SEC("xdp")
int port_scanner_detect(struct xdp_md *ctx)
{
    __u32 src_ip   = 0;
    __u16 dst_port = 0;

    if (parse_tcp_syn(ctx, &src_ip, &dst_port) != 0)
        return XDP_PASS;

    __u8 *blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked) {
        bpf_printk("[E5] DROP blacklisted %x -> port %d\n",
                   bpf_ntohl(src_ip), dst_port);
        return XDP_DROP;
    }

    __u64 now  = bpf_ktime_get_ns();
    struct ip_scan_info *info = bpf_map_lookup_elem(&syn_tracker, &src_ip);

    if (!info) {
        struct ip_scan_info fresh = {
            .window_start_ns   = now,
            .unique_port_count = 0,
            .total_syns        = 0,
        };
        bpf_map_update_elem(&syn_tracker, &src_ip, &fresh, BPF_NOEXIST);
        info = bpf_map_lookup_elem(&syn_tracker, &src_ip);
        if (!info)
            return XDP_PASS;
    }

    if (now - info->window_start_ns > WINDOW_NS) {
        info->window_start_ns   = now;
        info->unique_port_count = 0;
        info->total_syns        = 0;
    }

    __u64 port_key       = ((__u64)src_ip << 16) | (__u64)dst_port;
    __u64 *port_window_ts = bpf_map_lookup_elem(&seen_ports, &port_key);

    info->total_syns++;

    if (!port_window_ts || *port_window_ts != info->window_start_ns) {
        bpf_map_update_elem(&seen_ports, &port_key,
                            &info->window_start_ns, BPF_ANY);
        info->unique_port_count++;

        bpf_printk("[E5] SYN %x -> port %d\n",
           bpf_ntohl(src_ip), dst_port);
    }

    if (info->unique_port_count >= PORT_SCAN_THRESHOLD) {
        __u8 one = 1;
        bpf_map_update_elem(&blacklist, &src_ip, &one, BPF_ANY);
        bpf_printk("[E5] *** SCANNER BLACKLISTED %x (%llu ports) ***\n",
                   bpf_ntohl(src_ip), info->unique_port_count);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
