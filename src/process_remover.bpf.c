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


SEC("lsm/task_free")
int BPF_PROG(on_task_free, struct task_struct *task)
{
    __u32 tgid = BPF_CORE_READ(task, tgid);

    __u32 *cnt = bpf_map_lookup_elem(&proc_map, &tgid);
    if (!cnt)
        return 0;     

    if (*cnt > 1) {
        __sync_fetch_and_add(cnt, -1);
        bpf_printk("[task_free] proc_map: tgid=%u decremented to %u\n", tgid, *cnt - 1);
        return 0;
    }

    bpf_map_delete_elem(&proc_map, &tgid);
    bpf_printk("[task_free] proc_map: removed tgid=%u\n", tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

