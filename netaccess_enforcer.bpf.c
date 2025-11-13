// SPDX-License-Identifier: GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <bpf/bpf_endian.h>
#ifndef AF_INET
#define AF_INET 2
#endif

// ===== Maps =====

// Whitelisted remote IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32);
} ip_map SEC(".maps");

// Processes allowed to be checked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

// Local IP addresses that bypass port check
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __type(key, __u32);
    __type(value, __u32);
} loc_ip_map SEC(".maps");

// ===== LSM Program =====
SEC("lsm/socket_connect")
int BPF_PROG(check_connect, struct socket *sock, struct sockaddr *uaddr, int addrlen)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!uaddr || uaddr->sa_family != AF_INET)
        return 0;

    if (addrlen < sizeof(struct sockaddr_in))
        return 0;

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    __u32 ip = sin->sin_addr.s_addr;
    __u16 port = bpf_ntohs(sin->sin_port);

    // Only enforce for processes in proc_map
    __u32 *found_proc = bpf_map_lookup_elem(&proc_map, &tgid);
    if (!found_proc)
        return 0;

    // Allow local IPs
    __u32 *local_ip = bpf_map_lookup_elem(&loc_ip_map, &ip);
    if (local_ip)
        return 0;

    // Only allow IPs in ip_map
    __u32 *allowed_ip = bpf_map_lookup_elem(&ip_map, &ip);
    __u8 b1 = ip & 0xFF;
    __u8 b2 = (ip >> 8) & 0xFF;
    __u8 b3 = (ip >> 16) & 0xFF;
    __u8 b4 = (ip >> 24) & 0xFF;

    if (!allowed_ip) {
        bpf_printk("socket_connect: tgid %d tried ip %d.%d.%d.%d not allowed\n",
                   tgid, b1, b2, b3, b4);
        return -EACCES;
    }

    // Enforce port 80 or 443
    if (port != 80 && port != 443) {
        bpf_printk("socket_connect: tgid %d tried ip %d.%d.%d.%d port %d not allowed\n",
                   tgid, b1, b2, b3, b4, port);
        return -EACCES;
    }

    bpf_printk("socket_connect: tgid %d tried ip %d.%d.%d.%d port %d allowed\n",
               tgid, b1, b2, b3, b4, port);

    return 0;
}

// ===== License =====
char LICENSE[] SEC("license") = "GPL";

