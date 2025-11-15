#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(on_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    __u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *pcount = bpf_map_lookup_elem(&proc_map, &parent_tgid);
    if (!pcount) {
        return 0;
    }
    __u32 child_tgid = task->tgid;
    __u32 *ccount = bpf_map_lookup_elem(&proc_map, &child_tgid);
    if (ccount) {
        bpf_printk("[task_alloc] proc_map increment: tgid=%u\n", child_tgid);
        __sync_fetch_and_add(ccount, 1);
    } else {
        __u32 init_val = 1;
        bpf_printk("[task_alloc] proc_map new task: tgid=%u\n", child_tgid);
        
        bpf_map_update_elem(&proc_map, &child_tgid, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

