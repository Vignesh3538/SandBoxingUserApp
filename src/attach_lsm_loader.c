#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "process_mapper.skel.h"
#include "process_remover.skel.h"
#include "filewrite_enforcer.skel.h"
#include "filecreate_enforcer.skel.h"
#include "netaccess_enforcer.skel.h"
#include "child_process_mapper.skel.h"

static struct process_mapper_bpf *g_skel = NULL;
static struct process_remover_bpf *g_remover = NULL;
static struct filewrite_enforcer_bpf *g_enforcer = NULL;
static struct filecreate_enforcer_bpf *g_creator = NULL;
static struct netaccess_enforcer_bpf *g_net = NULL;
static struct child_process_mapper_bpf *g_child = NULL;

static struct bpf_link *g_link_bprm = NULL;
static struct bpf_link *g_link_task_free = NULL;
static struct bpf_link *g_link_enforcer = NULL;
static struct bpf_link *g_link_creator = NULL;
static struct bpf_link *g_link_net = NULL;
static struct bpf_link *g_link_child = NULL;

static int g_fd_inodepolicy = -1;
static int g_fd_proc_policy = -1;
static int g_fd_proc = -1;
static int g_fd_allow_wdir = -1;
static int g_fd_block_env = -1;
static int g_fd_ip = -1;
static int g_fd_loc_ip = -1;

#define PIN_INODE_MAP      "/sys/fs/bpf/inodepolicy_map"
#define PIN_PROC_POLICY    "/sys/fs/bpf/proc_policy_map"
#define PIN_PROC_MAP       "/sys/fs/bpf/proc_map"
#define PIN_ALLOW_WDIR_MAP "/sys/fs/bpf/allow_wdir_map"
#define PIN_BLOCK_ENV_ARR  "/sys/fs/bpf/block_env_arr"
#define PIN_IP_MAP         "/sys/fs/bpf/ip_map"
#define PIN_LOC_IP_MAP     "/sys/fs/bpf/loc_ip_map"

#define PIN_LINK_MAPPER    "/sys/fs/bpf/process_mapper"
#define PIN_LINK_REMOVER   "/sys/fs/bpf/process_remover"
#define PIN_LINK_ENFORCER  "/sys/fs/bpf/filewrite_enforcer"
#define PIN_LINK_CREATOR   "/sys/fs/bpf/filecreate_enforcer"
#define PIN_LINK_NETACCESS "/sys/fs/bpf/netaccess_enforcer"
#define PIN_LINK_CHILD     "/sys/fs/bpf/child_process_mapper"

static void cleanup_and_exit(int signum)
{
    (void)signum;

    fprintf(stderr, "[loader] cleaning up resources\n");

    if (g_link_net) { bpf_link__destroy(g_link_net); g_link_net = NULL; unlink(PIN_LINK_NETACCESS); }
    if (g_link_child) { bpf_link__destroy(g_link_child); g_link_child = NULL; unlink(PIN_LINK_CHILD); }
    if (g_link_creator) { bpf_link__destroy(g_link_creator); g_link_creator = NULL; unlink(PIN_LINK_CREATOR); }
    if (g_link_enforcer) { bpf_link__destroy(g_link_enforcer); g_link_enforcer = NULL; unlink(PIN_LINK_ENFORCER); }
    if (g_link_task_free) { bpf_link__destroy(g_link_task_free); g_link_task_free = NULL; unlink(PIN_LINK_REMOVER); }
    if (g_link_bprm) { bpf_link__destroy(g_link_bprm); g_link_bprm = NULL; unlink(PIN_LINK_MAPPER); }

    if (g_net) { netaccess_enforcer_bpf__destroy(g_net); g_net = NULL; }
    if (g_child) { child_process_mapper_bpf__destroy(g_child); g_child = NULL; }
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
    if (g_fd_loc_ip >= 0) { close(g_fd_loc_ip); g_fd_loc_ip = -1; }

    fprintf(stderr, "[loader] cleanup complete; exiting now\n");
    exit(0);
}

static int safe_reuse_map_fd(struct bpf_map *map, int fd, const char *name)
{
    if (!map) {
        fprintf(stderr, "error: skeleton map pointer for '%s' is NULL\n", name);
        return -EINVAL;
    }

    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        int e = -err;
        fprintf(stderr, "error: bpf_map__reuse_fd('%s') returned %d (errno=%d: %s)\n",
                name, err, e, strerror(e));
        return err;
    }

    printf("map reused: %s (fd=%d)\n", name, fd);
    return 0;
}

static int open_all_skeletons(void)
{
    g_skel = process_mapper_bpf__open();
    g_remover = process_remover_bpf__open();
    g_enforcer = filewrite_enforcer_bpf__open();
    g_creator = filecreate_enforcer_bpf__open();
    g_net = netaccess_enforcer_bpf__open();
    g_child = child_process_mapper_bpf__open();

    if (!g_skel || !g_remover || !g_enforcer || !g_creator || !g_net || !g_child) {
        fprintf(stderr, "error: failed to open one or more skeletons\n");
        return -ENOENT;
    }

    printf("skeletons opened successfully\n");
    return 0;
}

static int open_pinned_maps(void)
{
    g_fd_inodepolicy = bpf_obj_get(PIN_INODE_MAP);
    if (g_fd_inodepolicy < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_INODE_MAP, strerror(errno)); return -errno; }

    g_fd_proc_policy = bpf_obj_get(PIN_PROC_POLICY);
    if (g_fd_proc_policy < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_PROC_POLICY, strerror(errno)); return -errno; }

    g_fd_proc = bpf_obj_get(PIN_PROC_MAP);
    if (g_fd_proc < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_PROC_MAP, strerror(errno)); return -errno; }

    g_fd_allow_wdir = bpf_obj_get(PIN_ALLOW_WDIR_MAP);
    if (g_fd_allow_wdir < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_ALLOW_WDIR_MAP, strerror(errno)); return -errno; }

    g_fd_block_env = bpf_obj_get(PIN_BLOCK_ENV_ARR);
    if (g_fd_block_env < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_BLOCK_ENV_ARR, strerror(errno)); return -errno; }

    g_fd_ip = bpf_obj_get(PIN_IP_MAP);
    if (g_fd_ip < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_IP_MAP, strerror(errno)); return -errno; }

    g_fd_loc_ip = bpf_obj_get(PIN_LOC_IP_MAP);
    if (g_fd_loc_ip < 0) { fprintf(stderr, "error: opening %s: %s\n", PIN_LOC_IP_MAP, strerror(errno)); return -errno; }

    printf("pinned maps opened: inode=%d proc_policy=%d proc_map=%d allow_wdir=%d ip_map=%d loc_ip_map=%d\n",
           g_fd_inodepolicy, g_fd_proc_policy, g_fd_proc, g_fd_allow_wdir, g_fd_ip, g_fd_loc_ip);

    return 0;
}

static int reuse_maps_for_skeletons(void)
{
    int err;

    if ((err = safe_reuse_map_fd(g_skel->maps.inodepolicy_map, g_fd_inodepolicy,
                                 "inodepolicy_map(process_mapper)"))) return err;
    if ((err = safe_reuse_map_fd(g_skel->maps.proc_policy_map, g_fd_proc_policy,
                                 "proc_policy_map(process_mapper)"))) return err;
    if ((err = safe_reuse_map_fd(g_skel->maps.proc_map, g_fd_proc,
                                 "proc_map(process_mapper)"))) return err;
    if ((err = safe_reuse_map_fd(g_skel->maps.block_env_arr, g_fd_block_env,
                                 "block_env_arr(process_mapper)"))) return err;

    if ((err = safe_reuse_map_fd(g_remover->maps.proc_policy_map, g_fd_proc_policy,
                                 "proc_policy_map(process_remover)"))) return err;
    if ((err = safe_reuse_map_fd(g_remover->maps.proc_map, g_fd_proc,
                                 "proc_map(process_remover)"))) return err;

    if ((err = safe_reuse_map_fd(g_enforcer->maps.proc_map, g_fd_proc,
                                 "proc_map(filewrite_enforcer)"))) return err;
    if ((err = safe_reuse_map_fd(g_enforcer->maps.allow_wdir_map, g_fd_allow_wdir,
                                 "allow_wdir_map(filewrite_enforcer)"))) return err;

    if ((err = safe_reuse_map_fd(g_creator->maps.proc_map, g_fd_proc,
                                 "proc_map(filecreate_enforcer)"))) return err;
    if ((err = safe_reuse_map_fd(g_creator->maps.allow_wdir_map, g_fd_allow_wdir,
                                 "allow_wdir_map(filecreate_enforcer)"))) return err;

    if ((err = safe_reuse_map_fd(g_net->maps.proc_map, g_fd_proc,
                                 "proc_map(netaccess_enforcer)"))) return err;
    if ((err = safe_reuse_map_fd(g_net->maps.ip_map, g_fd_ip,
                                 "ip_map(netaccess_enforcer)"))) return err;
    if ((err = safe_reuse_map_fd(g_net->maps.loc_ip_map, g_fd_loc_ip,
                                 "loc_ip_map(netaccess_enforcer)"))) return err;

    if ((err = safe_reuse_map_fd(g_child->maps.proc_policy_map, g_fd_proc_policy,
                                 "proc_policy_map(child_process_mapper)"))) return err;
    
    if ((err = safe_reuse_map_fd(g_child->maps.proc_map, g_fd_proc,
                                 "proc_map(child_process_mapper)"))) return err;

    printf("All maps successfully reused across all eBPF programs.\n");
    return 0;
}


static int load_all_skeletons(void)
{
    int err;

    if ((err = process_mapper_bpf__load(g_skel)) != 0) { fprintf(stderr, "error: process_mapper_bpf__load returned %d\n", err); return err; }
    printf("process_mapper loaded\n");

    if ((err = process_remover_bpf__load(g_remover)) != 0) { fprintf(stderr, "error: process_remover_bpf__load returned %d\n", err); return err; }
    printf("process_remover loaded\n");

    if ((err = filewrite_enforcer_bpf__load(g_enforcer)) != 0) { fprintf(stderr, "error: filewrite_enforcer_bpf__load returned %d\n", err); return err; }
    printf("filewrite_enforcer loaded\n");

    if ((err = filecreate_enforcer_bpf__load(g_creator)) != 0) { fprintf(stderr, "error: filecreate_enforcer_bpf__load returned %d\n", err); return err; }
    printf("filecreate_enforcer loaded\n");

    if ((err = netaccess_enforcer_bpf__load(g_net)) != 0) { fprintf(stderr, "error: netaccess_enforcer_bpf__load returned %d\n", err); return err; }
    printf("netaccess_enforcer loaded\n");

    if ((err = child_process_mapper_bpf__load(g_child)) != 0) { fprintf(stderr, "error: child_process_mapper_bpf__load returned %d\n", err); return err; }
    printf("child_process_mapper loaded\n");

    return 0;
}

static int attach_and_pin(struct bpf_program *prog, struct bpf_link **plink, const char *pin_path, const char *desc)
{
    *plink = bpf_program__attach_lsm(prog);
    if (!*plink) {
        fprintf(stderr, "error: attaching %s: %s\n", desc, strerror(errno));
        return -errno;
    }

    if (bpf_link__pin(*plink, pin_path) < 0) {
        fprintf(stderr, "warning: failed to pin %s to %s: %s\n", desc, pin_path, strerror(errno));
    } else {
        printf("%s attached and pinned at %s\n", desc, pin_path);
    }
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int err;

    if ((err = open_all_skeletons()) != 0) goto fail;
    if ((err = open_pinned_maps()) != 0) goto fail;
    if ((err = reuse_maps_for_skeletons()) != 0) goto fail;
    if ((err = load_all_skeletons()) != 0) goto fail;

    if ((err = attach_and_pin(g_skel->progs.bprm_check, &g_link_bprm, PIN_LINK_MAPPER, "process_mapper (bprm_check)")) != 0) goto fail;
    if ((err = attach_and_pin(g_remover->progs.on_task_free, &g_link_task_free, PIN_LINK_REMOVER, "process_remover (on_task_free)")) != 0) goto fail;
    if ((err = attach_and_pin(g_enforcer->progs.enforce_allowed_write_dirs, &g_link_enforcer, PIN_LINK_ENFORCER, "filewrite_enforcer (enforce_allowed_write_dirs)")) != 0) goto fail;
    if ((err = attach_and_pin(g_creator->progs.enforce_create_allowed_dirs, &g_link_creator, PIN_LINK_CREATOR, "filecreate_enforcer (enforce_create_allowed_dirs)")) != 0) goto fail;
    if ((err = attach_and_pin(g_net->progs.check_connect, &g_link_net, PIN_LINK_NETACCESS, "netaccess_enforcer (check_connect)")) != 0) goto fail;
    if ((err = attach_and_pin(g_child->progs.on_task_alloc, &g_link_child, PIN_LINK_CHILD, "child_process_mapper (on_task_alloc)")) != 0) goto fail;

    printf("all programs attached; links have been pinned\n");
    return 0;

fail:
    cleanup_and_exit(0);
    return 1;
}

