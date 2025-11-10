// filewrite_enforcer.bpf.c
// Compile:
// clang -O2 -target bpf -g -c filewrite_enforcer.bpf.c -o filewrite_enforcer.bpf.o
// sudo bpftool prog load filewrite_enforcer.bpf.o /sys/fs/bpf/filewrite_enforcer type lsm

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define MAX_ANCESTOR_DEPTH 32
#define FMODE_WRITE 0x2

/* ---------------- Map Definitions ---------------- */

struct inode_key {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct inode_key);
    __type(value, __u32);
} allow_wdir_map SEC(".maps");

/* ---------------- Helpers ---------------- */

/*
 * Kernel internally stores s_dev as an encoded value.
 * We must re-encode it in the same way userspace encoded
 * using make_kernel_dev() ((major << 20) | minor).
 */
static __always_inline __u64 normalize_dev(__u64 dev)
{
    __u32 major_num = (dev >> 20) & 0xFFF; // 12 bits for major
    __u32 minor_num = dev & ((1 << 20) - 1); // 20 bits for minor
    return ((__u64)major_num << 20) | minor_num;
}

/* ---------------- Enforcement Hook ---------------- */

SEC("lsm/file_open")
int BPF_PROG(enforce_allowed_write_dirs, struct file *file)
{
    if (!file)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    __u32 *policy_ptr = bpf_map_lookup_elem(&proc_map, &tgid);
    if (!policy_ptr)
        return 0;

    unsigned int f_mode = 0;
    if (bpf_core_read(&f_mode, sizeof(f_mode), &file->f_mode) < 0)
        return 0;

    if (!(f_mode & FMODE_WRITE))
        return 0;

    struct path fpath = {};
    if (bpf_core_read(&fpath, sizeof(fpath), &file->f_path) < 0)
        return -EACCES;

    struct dentry *parent = NULL;
    if (bpf_core_read(&parent, sizeof(parent), &fpath.dentry) < 0 || !parent)
        return -EACCES;
    
    for (int depth = 0; depth < MAX_ANCESTOR_DEPTH; depth++) {
        struct inode *inode = NULL;
        if (bpf_core_read(&inode, sizeof(inode), &parent->d_inode) < 0 || !inode)
            break;

        __u64 ino = 0, raw_dev = 0;
        struct super_block *sb = NULL;
        if (bpf_core_read(&ino, sizeof(ino), &inode->i_ino) < 0)
            break;
        if (bpf_core_read(&sb, sizeof(sb), &inode->i_sb) < 0 || !sb)
            break;
        if (bpf_core_read(&raw_dev, sizeof(raw_dev), &sb->s_dev) < 0)
            break;

        // Normalize dev like userspace encoding
        __u64 dev = normalize_dev(raw_dev);

        struct inode_key ik = { .dev = dev, .ino = ino };

        bpf_printk("[DEBUG] tgid=%u depth=%d raw_dev=%llu norm_dev=%llu ino=%llu\n",
                   tgid, depth, raw_dev, dev, ino);

        __u32 *val = bpf_map_lookup_elem(&allow_wdir_map, &ik);
        if (val) {
            bpf_printk("[ALLOW] tgid=%u matched allowed dir dev=%llu ino=%llu\n",
                       tgid, dev, ino);
            return 0;
        }

        struct dentry *next_parent = NULL;
        if (bpf_core_read(&next_parent, sizeof(next_parent), &parent->d_parent) < 0)
            break;
        if (!next_parent || next_parent == parent)
            break;

        parent = next_parent;
    }

    bpf_printk("[DENY] tgid=%u denied write-open\n", tgid);
    return -EACCES;
}

char LICENSE[] SEC("license") = "GPL";

