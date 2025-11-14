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
    __type(key, struct proc_key);
    __type(value, __u32);
} proc_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

SEC("lsm/task_free")
int BPF_PROG(on_task_free, struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);
    __u64 start_time = BPF_CORE_READ(task, start_time);

    struct proc_key pk = {
        .tgid = tgid,
        .pad = 0,                // keep consistent zero padding
        .start_time_ns = start_time,
    };

    __u32 *policy_id_ptr = bpf_map_lookup_elem(&proc_policy_map, &pk);
    if (!policy_id_ptr) {
        return 0;
    }

    __u32 policy_id = *policy_id_ptr;
    bpf_map_delete_elem(&proc_policy_map, &pk);
    bpf_map_delete_elem(&proc_map, &tgid);
    bpf_printk("stopped tracking tgid=%u start_time_ns=%llu from [task_free]\n",
           tgid, start_time);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

