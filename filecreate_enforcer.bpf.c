// filecreate_enforcer.bpf.c
// Compile:
//   clang -O2 -target bpf -g -c filecreate_enforcer.bpf.c -o filecreate_enforcer.bpf.o
// Load as LSM:
//   sudo bpftool prog load filecreate_enforcer.bpf.o /sys/fs/bpf/filecreate_enforcer type lsm

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define MAX_ANCESTOR_DEPTH 32

/* Map key for allowed write/create directories */
struct inode_key {
    __u64 dev;
    __u64 ino;
};

/* proc_map: tgid -> policy_id */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} proc_map SEC(".maps");

/* allow_wdir_map: (dev, ino) -> dummy/policy_id */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct inode_key);
    __type(value, __u32);
} allow_wdir_map SEC(".maps");

/* Normalize kernel s_dev into (major<<20)|minor encoding to match userspace makedev */
static __always_inline __u64 normalize_dev(__u64 dev)
{
    /* this mirrors (major << 20) | minor used earlier */
    __u32 major_num = (dev >> 20) & 0xFFF;
    __u32 minor_num = dev & ((1u << 20) - 1);
    return ((__u64)major_num << 20) | minor_num;
}

/* Walk ancestor dentry chain starting from parent_dentry.
 * Return 1 if any ancestor matches allow_wdir_map, 0 otherwise.
 * On kernel read failures return 0 (we treat as "no match" and caller may deny).
 */
static __always_inline int check_allowed_ancestors_from_dentry(struct dentry *start)
{
    struct dentry *parent = start;
    #pragma clang loop unroll(disable)
    for (int depth = 0; depth < MAX_ANCESTOR_DEPTH; depth++) {
        if (!parent)
            break;

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

        __u64 dev = normalize_dev(raw_dev);
        struct inode_key ik = { .dev = dev, .ino = ino };

        __u32 *val = bpf_map_lookup_elem(&allow_wdir_map, &ik);
        if (val)
            return 1;

        struct dentry *next_parent = NULL;
        if (bpf_core_read(&next_parent, sizeof(next_parent), &parent->d_parent) < 0)
            break;
        if (!next_parent || next_parent == parent)
            break;

        parent = next_parent;
    }
    return 0;
}

/* LSM hook: inode_create
 * Signature: inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
 *
 * dir: parent inode (where new entry will be created)
 * dentry: name dentry for the new entry (dentry->d_parent points to parent dentry)
 *
 * Logic:
 *  - If current process is NOT in proc_map => allow (return 0)
 *  - Else, walk parent dentry chain starting from dentry->d_parent and check allow_wdir_map
 *  - If any ancestor matches => allow (0)
 *  - Otherwise => deny (-EACCES)
 */
SEC("lsm/inode_create")
int BPF_PROG(enforce_create_allowed_dirs, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    /* Basic sanity */
    if (!dentry)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    /* Only enforce for tracked processes */
    __u32 *policy_ptr = bpf_map_lookup_elem(&proc_map, &tgid);
    if (!policy_ptr)
        return 0;

    /* Start from the parent dentry of the new entry (dentry->d_parent) */
    struct dentry *parent_dentry = NULL;
    if (bpf_core_read(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent) < 0 || !parent_dentry) {
        /* Can't read parent dentry — be conservative and deny creation for tracked processes */
        bpf_printk("[DENY_CREATE] tgid=%u cannot read parent dentry, deny\n", tgid);
        return -EACCES;
    }

    /* If any ancestor (including parent) matches allow_wdir_map, allow creation */
    int ok = check_allowed_ancestors_from_dentry(parent_dentry);
    if (ok) {
        bpf_printk("[ALLOW_CREATE] tgid=%u creation allowed under ancestor\n", tgid);
        return 0;
    }

    bpf_printk("[DENY_CREATE] tgid=%u denied create in parent inode\n", tgid);
    return -EACCES;
}

char LICENSE[] SEC("license") = "GPL";

