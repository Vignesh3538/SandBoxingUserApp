#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

struct inode_key { __u64 dev; __u64 ino; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct inode_key);
    __type(value, __u32);
} inodepolicy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);     
    __type(value, __u32);   
} proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, char[32]);
    __type(value, __u32);
} block_env_arr SEC(".maps");


SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    __u32 *existing = bpf_map_lookup_elem(&proc_map, &tgid);
    if (existing) {
        bpf_printk("[bprm_check_security] proc_map hit: tgid=%u, skipping\n", tgid);
        return 0;
    }

    struct file *file = NULL;
    if (bpf_core_read(&file, sizeof(file), &bprm->file) < 0 || !file)
        return 0;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u64 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    struct inode_key ik = { .dev = dev, .ino = ino };

    __u32 *policy_ptr = bpf_map_lookup_elem(&inodepolicy_map, &ik);
    if (!policy_ptr) {
        return 0;
    }

    __u32 one = 1;
    bpf_map_update_elem(&proc_map, &tgid, &one, BPF_ANY);
    bpf_printk("[bprm_check_security] proc_map add: tgid=%u\n", tgid);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long s = BPF_CORE_READ(mm, env_start);
        unsigned long e = BPF_CORE_READ(mm, env_end);
        if (s && e > s) {

            #define MAXSCAN 70
            #define NBUF 128
            #define KEYSZ 32

            unsigned long cur = s;
            int loop = 0;
            int env_idx = 0;

            for (; loop < MAXSCAN && cur < e; loop++) {
                char buf[NBUF];
                int got = bpf_probe_read_str(buf, sizeof(buf), (void *)cur);
                if (got <= 0) break;

                bool truncated = (got == NBUF) || (buf[NBUF - 1] != '\0');

                if (!truncated) {
                    int namelen = 0;
                    #pragma unroll
                    for (int i = 0; i < KEYSZ; i++) {
                        char c = buf[i];
                        if (c == '=' || c == '\0') { namelen = i; break; }
                        if (i == KEYSZ - 1) namelen = KEYSZ;
                    }

                    if (namelen > 0 && namelen < KEYSZ) {
                        char key[KEYSZ];
                        #pragma unroll
                        for (int j = 0; j < KEYSZ; j++) {
                            key[j] = (j < namelen) ? buf[j] : '\0';
                        }

                        __u32 *val = bpf_map_lookup_elem(&block_env_arr, &key);
                        if (val) {
                            bpf_printk("blocked env var: %s\n", key);
                            return -EACCES;
                        }
                    }
                }

                cur += (unsigned long)got;
            }

            #undef MAXSCAN
            #undef NBUF
            #undef KEYSZ
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

