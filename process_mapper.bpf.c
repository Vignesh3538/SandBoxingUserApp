// curl_mark.bpf.c
// Compile:
//   sudo clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
//       -c curl_mark.bpf.c -o curl_mark.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Keys/structs */
struct inode_key {
    __u64 dev;
    __u64 ino;
};

/*
 * Explicitly padded version (16 bytes total):
 * [ tg_id (4B) | pad (4B) | start_time_ns (8B) ]
 * Ensures consistent alignment between producer and consumer programs.
 */
struct proc_key {
    __u32 tgid;
    __u32 pad;              // <-- explicit 4-byte padding
    __u64 start_time_ns;
};

/* ---------- inodepolicy_map ----------
 * Key:   inode_key { dev, ino }
 * Value: policy_id (u32)
 * This map is created and pinned manually from userspace.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct inode_key);
    __type(value, __u32);
} inodepolicy_map SEC(".maps");

/* ---------- proc_policy_map ----------
 * Key:   proc_key { tgid, pad=0, start_time }
 * Value: policy_id (u32)
 * Tracks which processes are managed by a policy.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct proc_key);
    __type(value, __u32);
} proc_policy_map SEC(".maps");

/* ---------- proc_map ----------
 * New map keyed by tgid only for fast lookup by other BPF programs.
 * Key:   __u32 tgid
 * Value: __u32 policy_id (dummy)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

/* ========== LSM Hook ==========
 * Triggered on every execve() through bprm_check_security()
 * before the binary is executed.
 *
 * Behavior:
 *  - If the inode of the executing binary matches an entry in inodepolicy_map,
 *    insert an entry into proc_policy_map keyed by (tgid, start_time) -> policy_id.
 *  - Also insert (tgid -> policy_id) into proc_map for fast tgid-only lookups.
 *  - If proc_map insert fails after proc_policy_map succeed, roll back proc_policy_map.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm)
{
    struct file *file = NULL;

    /* 1) Get bprm->file pointer */
    if (bpf_core_read(&file, sizeof(file), &bprm->file) < 0 || !file) {
        return 0;
    }

    /* 2) Read inode & device numbers */
    __u64 ino = 0, dev = 0;
    ino = BPF_CORE_READ(file, f_inode, i_ino);
    dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

    /* 3) Build key for inodepolicy_map lookup */
    struct inode_key ik = {
        .dev = dev,
        .ino = ino,
    };

    /* 4) Lookup policy */
    __u32 *policy_ptr = bpf_map_lookup_elem(&inodepolicy_map, &ik);
    if (!policy_ptr) {
        return 0;
    }

    __u32 policy_id = *policy_ptr;

    /* 5) Identify process (TGID, unique start_time) */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        bpf_printk("[bprm_check] no task_struct for tgid=%u\n", tgid);
        return 0;
    }

    __u64 start_time = BPF_CORE_READ(task, start_time);
    
    bpf_printk("[bprm_check] matched policy=%u for tgid=%u start=%llu (dev=%llu ino=%llu)\n",
               policy_id, tgid, (unsigned long long)start_time,
               (unsigned long long)dev, (unsigned long long)ino);

    /* 6) Store process policy mapping in proc_policy_map */
    struct proc_key pk = {
        .tgid = tgid,
        .pad = 0, // ensure zero padding
        .start_time_ns = start_time,
    };

    long ret = bpf_map_update_elem(&proc_policy_map, &pk, &policy_id, BPF_ANY);
    if (ret != 0) {
        bpf_printk("[bprm_check] failed to update proc_policy_map for tgid=%u err=%ld\n",
                   tgid, ret);
        return 0;
    }

    /* 7) Also store tgid->policy_id in proc_map */
    __u32 tkey = tgid;
    ret = bpf_map_update_elem(&proc_map, &tkey, &policy_id, BPF_ANY);
    if (ret != 0) {
        bpf_printk("[bprm_check] failed to update proc_map for tgid=%u err=%ld, rolling back proc_policy_map\n",
                   tgid, ret);
        bpf_map_delete_elem(&proc_policy_map, &pk);
        return 0;
    }

    bpf_printk("[bprm_check] successfully inserted proc_policy_map and proc_map for tgid=%u policy=%u\n",
               tgid, policy_id);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

