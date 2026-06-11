/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#define PORT_SCAN_THRESHOLD   15
#define WINDOW_NS  (10ULL * 1000000000ULL)
#define MAX_TRACKED_IPS    65536
#define MAX_PORT_ENTRIES   (MAX_TRACKED_IPS * 4)
#define MAX_BLACKLIST       10000

struct ip_scan_info {
    __u64 window_start_ns;
    __u64 unique_port_count;
    __u64 total_syns;
};
