#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

int tcp_filter(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    // Check if it is a TCP packet and on port 80
    if (ip->protocol == IPPROTO_TCP && ntohs(tcp->dest) == 80) {
        bpf_trace_printk("Captured TCP packet on port 80\\n");
    }

    return BPF_PERF_HIST;
}
