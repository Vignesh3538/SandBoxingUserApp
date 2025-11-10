// clang -O2 -target bpf -g -c curl_mark_free.bpf.c -o curl_mark_free.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
 * Define the key with explicit 4-byte padding between tgid (4 bytes)
 * and start_time_ns (8 bytes). This ensures sizeof(struct proc_key) == 16
 * and the in-memory layout matches what kernel emits when inserted.
 */
struct proc_key {
    __u32 tgid;
    __u32 pad;              // explicit 4-byte padding
    __u64 start_time_ns;
};

/* ---------- proc_policy_map ----------
 * Key:   proc_key { tgid, pad=0, start_time }
 * Value: policy_id (u32)
 * Pinned and shared with the mark program.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct proc_key);
    __type(value, __u32);
} proc_policy_map SEC(".maps");

/* ---------- proc_map ----------
 * Key:   tgid (u32)
 * Value: policy_id (u32)
 * Used for fast lookup by tgid only.
 */
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

    //bpf_printk("task_free: removing pid=%u start_time=%llu\n", tgid, start_time);

    __u32 *policy_id_ptr = bpf_map_lookup_elem(&proc_policy_map, &pk);
    if (!policy_id_ptr) {
        //bpf_printk("task_free: not found pid=%u start=%llu\n", tgid, start_time);
        return 0;
    }

    __u32 policy_id = *policy_id_ptr;
    bpf_printk("task_free: found pid=%u start=%llu policy=%u\n",
               tgid, start_time, policy_id);

    bpf_map_delete_elem(&proc_policy_map, &pk);
    bpf_map_delete_elem(&proc_map, &tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

