/* attachlsm_loader.c
 *
 * Compile:
 *   clang -O2 -g -Wall -o attachlsm_loader attachlsm_loader.c \
 *     -I/usr/include -lbpf -lelf -lz
 *
 * Run as root.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>

#include "process_mapper.skel.h"
#include "process_remover.skel.h"
#include "filewrite_enforcer.skel.h"
#include "filecreate_enforcer.skel.h" /* NEW: filecreate skeleton */
#include "netaccess_enforcer.skel.h"  /* NEW: netaccess skeleton */

static struct process_mapper_bpf *g_skel = NULL;
static struct process_remover_bpf *g_remover = NULL;
static struct filewrite_enforcer_bpf *g_enforcer = NULL;
static struct filecreate_enforcer_bpf *g_creator = NULL; /* NEW */
static struct netaccess_enforcer_bpf *g_net = NULL;     /* NEW */

static struct bpf_link *g_link_bprm = NULL;
static struct bpf_link *g_link_task_free = NULL;
static struct bpf_link *g_link_enforcer = NULL;
static struct bpf_link *g_link_creator = NULL; /* NEW */
static struct bpf_link *g_link_net = NULL;     /* NEW */

static int g_fd_inodepolicy = -1;
static int g_fd_proc_policy = -1;
static int g_fd_proc = -1;
static int g_fd_allow_wdir = -1;
static int g_fd_block_env = -1;
static int g_fd_ip = -1; /* NEW for ip_map */
static int g_fd_loc_ip = -1; /* NEW for loc_ip_map */

/* Pinned map paths - adjust if you pinned maps elsewhere */
#define PIN_INODE_MAP      "/sys/fs/bpf/inodepolicy_map"
#define PIN_PROC_POLICY    "/sys/fs/bpf/proc_policy_map"
#define PIN_PROC_MAP       "/sys/fs/bpf/proc_map"
#define PIN_ALLOW_WDIR_MAP "/sys/fs/bpf/allow_wdir_map"
#define PIN_BLOCK_ENV_ARR  "/sys/fs/bpf/block_env_arr"
#define PIN_IP_MAP         "/sys/fs/bpf/ip_map"                /* NEW */
#define PIN_LOC_IP_MAP    "/sys/fs/bpf/loc_ip_map"  /* NEW */

/* Pinned link paths */
#define PIN_LINK_MAPPER    "/sys/fs/bpf/process_mapper"
#define PIN_LINK_REMOVER   "/sys/fs/bpf/process_remover"
#define PIN_LINK_ENFORCER  "/sys/fs/bpf/filewrite_enforcer"
#define PIN_LINK_CREATOR   "/sys/fs/bpf/filecreate_enforcer"    /* NEW */
#define PIN_LINK_NETACCESS "/sys/fs/bpf/netaccess_enforcer"    /* NEW */

static void show_dmesg_tail(void)
{
    fprintf(stderr, "\n----- dmesg tail -----\n");
    system("dmesg | tail -n 30");
    fprintf(stderr, "----------------------\n\n");
}

static void cleanup_and_exit(int signum)
{
    (void)signum;
    fprintf(stderr, "\n[loader] cleaning up...\n");

    if (g_link_net) { bpf_link__destroy(g_link_net); g_link_net = NULL; }
    unlink(PIN_LINK_NETACCESS);

    if (g_link_creator) { bpf_link__destroy(g_link_creator); g_link_creator = NULL; }
    unlink(PIN_LINK_CREATOR);

    if (g_link_enforcer) { bpf_link__destroy(g_link_enforcer); g_link_enforcer = NULL; }
    unlink(PIN_LINK_ENFORCER);

    if (g_link_task_free) { bpf_link__destroy(g_link_task_free); g_link_task_free = NULL; }
    unlink(PIN_LINK_REMOVER);

    if (g_link_bprm) { bpf_link__destroy(g_link_bprm); g_link_bprm = NULL; }
    unlink(PIN_LINK_MAPPER);

    if (g_net) { netaccess_enforcer_bpf__destroy(g_net); g_net = NULL; }
    if (g_creator) { filecreate_enforcer_bpf__destroy(g_creator); g_creator = NULL; }
    if (g_enforcer) { filewrite_enforcer_bpf__destroy(g_enforcer); g_enforcer = NULL; }
    if (g_remover) { process_remover_bpf__destroy(g_remover); g_remover = NULL; }
    if (g_skel) { process_mapper_bpf__destroy(g_skel); g_skel = NULL; }

    if (g_fd_inodepolicy >= 0) { close(g_fd_inodepolicy); g_fd_inodepolicy = -1; }
    if (g_fd_proc_policy >= 0) { close(g_fd_proc_policy); g_fd_proc_policy = -1; }
    if (g_fd_proc >= 0) { close(g_fd_proc); g_fd_proc = -1; }
    if (g_fd_allow_wdir >= 0) { close(g_fd_allow_wdir); g_fd_allow_wdir = -1; }
    if (g_fd_block_env >= 0) { close(g_fd_block_env); g_fd_block_env = -1; }
    if (g_fd_ip >= 0) { close(g_fd_ip); g_fd_ip = -1; }

    fprintf(stderr, "[loader] done. exiting.\n");
    exit(0);
}

static int safe_reuse_map_fd(struct bpf_map *map, int fd, const char *name)
{
    if (!map) {
        fprintf(stderr, "ERROR: skeleton map pointer for %s is NULL\n", name);
        return -EINVAL;
    }

    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        int e = -err;
        fprintf(stderr, "ERROR: bpf_map__reuse_fd(%s) failed: ret=%d errno=%d (%s)\n",
                name, err, e, strerror(e));
    } else {
        printf("-> reused map %s (fd=%d)\n", name, fd);
    }
    return err;
}

int main(int argc, char **argv)
{
    int err;

    /* open skeletons */
    g_skel = process_mapper_bpf__open();
    g_remover = process_remover_bpf__open();
    g_enforcer = filewrite_enforcer_bpf__open();
    g_creator = filecreate_enforcer_bpf__open(); /* NEW */
    g_net = netaccess_enforcer_bpf__open();     /* NEW */

    if (!g_skel || !g_remover || !g_enforcer || !g_creator || !g_net) {
        fprintf(stderr, "ERROR: failed to open one or more skeletons\n");
        show_dmesg_tail();
        cleanup_and_exit(0);
    }
    printf("-> skeletons opened\n");

    /* open pinned maps (these must exist) */
    g_fd_inodepolicy = bpf_obj_get(PIN_INODE_MAP);
    if (g_fd_inodepolicy < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_INODE_MAP, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_proc_policy = bpf_obj_get(PIN_PROC_POLICY);
    if (g_fd_proc_policy < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_PROC_POLICY, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_proc = bpf_obj_get(PIN_PROC_MAP);
    if (g_fd_proc < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_PROC_MAP, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_allow_wdir = bpf_obj_get(PIN_ALLOW_WDIR_MAP);
    if (g_fd_allow_wdir < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_ALLOW_WDIR_MAP, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_block_env = bpf_obj_get(PIN_BLOCK_ENV_ARR);
    if (g_fd_block_env < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_BLOCK_ENV_ARR, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_ip = bpf_obj_get(PIN_IP_MAP); /* NEW */
    if (g_fd_ip < 0) {
        fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_IP_MAP, strerror(errno));
        cleanup_and_exit(0);
    }
    g_fd_loc_ip = bpf_obj_get(PIN_LOC_IP_MAP);
if (g_fd_loc_ip < 0) {
    fprintf(stderr, "ERROR: bpf_obj_get(%s) failed: %s\n", PIN_LOC_IP_MAP, strerror(errno));
    cleanup_and_exit(0);
}
    printf("-> opened pinned maps: inode=%d proc_policy=%d proc_map=%d allow_wdir=%d ip_map=%d\n",
           g_fd_inodepolicy, g_fd_proc_policy, g_fd_proc, g_fd_allow_wdir, g_fd_ip);

    /* ===== Map reuse according to your requested scheme ===== */

    /* process_mapper: inodepolicy_map, proc_policy_map, proc_map */
    if ((err = safe_reuse_map_fd(g_skel->maps.inodepolicy_map, g_fd_inodepolicy, "inodepolicy_map"))) goto fail;
    if ((err = safe_reuse_map_fd(g_skel->maps.proc_policy_map, g_fd_proc_policy, "proc_policy_map"))) goto fail;
    if ((err = safe_reuse_map_fd(g_skel->maps.proc_map, g_fd_proc, "proc_map"))) goto fail;
    if ((err = safe_reuse_map_fd(g_skel->maps.block_env_arr, g_fd_block_env, "block_env_arr")) != 0) goto fail;

    /* process_remover: proc_policy_map, proc_map */
    if ((err = safe_reuse_map_fd(g_remover->maps.proc_policy_map, g_fd_proc_policy, "proc_policy_map(remover)"))) goto fail;
    if ((err = safe_reuse_map_fd(g_remover->maps.proc_map, g_fd_proc, "proc_map(remover)"))) goto fail;

    /* filewrite_enforcer: proc_map, allow_wdir_map */
    if ((err = safe_reuse_map_fd(g_enforcer->maps.proc_map, g_fd_proc, "proc_map(enforcer)"))) goto fail;
    if ((err = safe_reuse_map_fd(g_enforcer->maps.allow_wdir_map, g_fd_allow_wdir, "allow_wdir_map(enforcer)"))) goto fail;

    /* NEW: filecreate_enforcer should reuse proc_map and allow_wdir_map */
    if ((err = safe_reuse_map_fd(g_creator->maps.proc_map, g_fd_proc, "proc_map(creator)"))) goto fail;
    if ((err = safe_reuse_map_fd(g_creator->maps.allow_wdir_map, g_fd_allow_wdir, "allow_wdir_map(creator)"))) goto fail;

    /* NEW: netaccess_enforcer: reuse proc_map and ip_map */
    if ((err = safe_reuse_map_fd(g_net->maps.proc_map, g_fd_proc, "proc_map(net)"))) goto fail;
    if ((err = safe_reuse_map_fd(g_net->maps.ip_map, g_fd_ip, "ip_map(net)"))) goto fail;
    if ((err = safe_reuse_map_fd(g_net->maps.loc_ip_map, g_fd_loc_ip, "loc_ip_map(net)"))) goto fail;
    /* ===== Load skeletons (programs). No new maps will be created. ===== */
    if ((err = process_mapper_bpf__load(g_skel)) != 0) {
        fprintf(stderr, "ERROR: process_mapper_bpf__load failed: %d\n", err);
        show_dmesg_tail();
        goto fail;
    }
    printf("-> process_mapper loaded\n");

    if ((err = process_remover_bpf__load(g_remover)) != 0) {
        fprintf(stderr, "ERROR: process_remover_bpf__load failed: %d\n", err);
        show_dmesg_tail();
        goto fail;
    }
    printf("-> process_remover loaded\n");

    if ((err = filewrite_enforcer_bpf__load(g_enforcer)) != 0) {
        fprintf(stderr, "ERROR: filewrite_enforcer_bpf__load failed: %d\n", err);
        show_dmesg_tail();
        goto fail;
    }
    printf("-> filewrite_enforcer loaded\n");

    /* NEW: load filecreate enforcer skeleton */
    if ((err = filecreate_enforcer_bpf__load(g_creator)) != 0) {
        fprintf(stderr, "ERROR: filecreate_enforcer_bpf__load failed: %d\n", err);
        show_dmesg_tail();
        goto fail;
    }
    printf("-> filecreate_enforcer loaded\n");

    /* NEW: load netaccess enforcer skeleton */
    if ((err = netaccess_enforcer_bpf__load(g_net)) != 0) {
        fprintf(stderr, "ERROR: netaccess_enforcer_bpf__load failed: %d\n", err);
        show_dmesg_tail();
        goto fail;
    }
    printf("-> netaccess_enforcer loaded\n");

    /* ===== Attach and pin LSM program links (and populate skeleton link handles) ===== */

    /* process_mapper: attach bprm_check */
    g_link_bprm = bpf_program__attach_lsm(g_skel->progs.bprm_check);
    if (!g_link_bprm) {
        fprintf(stderr, "ERROR: attaching bprm_check failed: %s\n", strerror(errno));
        show_dmesg_tail();
        goto fail;
    }
    g_skel->links.bprm_check = g_link_bprm;
    if (bpf_link__pin(g_link_bprm, PIN_LINK_MAPPER) < 0) {
        fprintf(stderr, "WARNING: bpf_link__pin mapper failed: %s\n", strerror(errno));
    } else {
        printf("-> pinned mapper link to %s\n", PIN_LINK_MAPPER);
    }

    /* process_remover: attach task_free */
    g_link_task_free = bpf_program__attach_lsm(g_remover->progs.on_task_free);
    if (!g_link_task_free) {
        fprintf(stderr, "ERROR: attaching on_task_free failed: %s\n", strerror(errno));
        show_dmesg_tail();
        goto fail;
    }
    g_remover->links.on_task_free = g_link_task_free;
    if (bpf_link__pin(g_link_task_free, PIN_LINK_REMOVER) < 0) {
        fprintf(stderr, "WARNING: bpf_link__pin remover failed: %s\n", strerror(errno));
    } else {
        printf("-> pinned remover link to %s\n", PIN_LINK_REMOVER);
    }

    /* filewrite_enforcer: attach file_open enforcement */
    g_link_enforcer = bpf_program__attach_lsm(g_enforcer->progs.enforce_allowed_write_dirs);
    if (!g_link_enforcer) {
        fprintf(stderr, "ERROR: attaching enforcer failed: %s\n", strerror(errno));
        show_dmesg_tail();
        goto fail;
    }
    g_enforcer->links.enforce_allowed_write_dirs = g_link_enforcer;
    if (bpf_link__pin(g_link_enforcer, PIN_LINK_ENFORCER) < 0) {
        fprintf(stderr, "WARNING: bpf_link__pin enforcer failed: %s\n", strerror(errno));
    } else {
        printf("-> pinned enforcer link to %s\n", PIN_LINK_ENFORCER);
    }

    /* NEW: filecreate_enforcer: attach inode_create enforcement */
    g_link_creator = bpf_program__attach_lsm(g_creator->progs.enforce_create_allowed_dirs);
    if (!g_link_creator) {
        fprintf(stderr, "ERROR: attaching creator failed: %s\n", strerror(errno));
        show_dmesg_tail();
        goto fail;
    }
    g_creator->links.enforce_create_allowed_dirs = g_link_creator;
    if (bpf_link__pin(g_link_creator, PIN_LINK_CREATOR) < 0) {
        fprintf(stderr, "WARNING: bpf_link__pin creator failed: %s\n", strerror(errno));
    } else {
        printf("-> pinned creator link to %s\n", PIN_LINK_CREATOR);
    }

    /* NEW: netaccess_enforcer: attach socket_connect LSM and pin */
    g_link_net = bpf_program__attach_lsm(g_net->progs.check_connect);
    if (!g_link_net) {
        fprintf(stderr, "ERROR: attaching netaccess check_connect failed: %s\n", strerror(errno));
        show_dmesg_tail();
        goto fail;
    }
    g_net->links.check_connect = g_link_net;
    if (bpf_link__pin(g_link_net, PIN_LINK_NETACCESS) < 0) {
        fprintf(stderr, "WARNING: bpf_link__pin netaccess failed: %s\n", strerror(errno));
    } else {
        printf("-> pinned netaccess link to %s\n", PIN_LINK_NETACCESS);
    }

    /* success: show loaded programs and wait */
    printf("All programs attached and (where possible) pinned.\n");
    printf("Verify with: sudo bpftool prog show\n");
    printf("Trace output: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    return 0;
/*
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    while (1) pause();
*/
fail:
    //show_dmesg_tail();
    cleanup_and_exit(0);
    return 1;
}

