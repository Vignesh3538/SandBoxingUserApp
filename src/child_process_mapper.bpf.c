#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct proc_key {
    __u32 tgid;
    __u32 pad;
    __u64 start_time_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct proc_key);
    __type(value, __u32);
} proc_policy_map SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(on_task_alloc, struct task_struct *child, unsigned long flags)
{
    struct task_struct *parent;
    __u32 ptgid, ctgid;
    __u32 *policy;
    __u64 start_time_child;

    parent = BPF_CORE_READ(child, real_parent);
    if (!parent)
        return 0;

    ptgid = (__u32)BPF_CORE_READ(parent, tgid);
    ctgid = (__u32)BPF_CORE_READ(child, tgid);

    policy = bpf_map_lookup_elem(&proc_map, &ptgid);
    if (!policy)
        return 0;

    bpf_map_update_elem(&proc_map, &ctgid, policy, BPF_ANY);

    start_time_child = BPF_CORE_READ(child, start_time);

    struct proc_key ck = {
        .tgid = ctgid,
        .pad = 0,
        .start_time_ns = start_time_child
    };

    bpf_map_update_elem(&proc_policy_map, &ck, policy, BPF_ANY);
    bpf_printk("started tracking forked tgid=%u start_time_ns=%llu from [task_alloc]\n",
           ctgid, start_time_child);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

