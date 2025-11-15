#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#define PIN_DOM_MAP        "/sys/fs/bpf/dom_map"
#define PIN_INODE_MAP      "/sys/fs/bpf/inodepolicy_map"
//#define PIN_PROC_POLICY    "/sys/fs/bpf/proc_policy_map"
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

void cleanup_bpf_resources(void)
{
    fprintf(stderr, "[cleanup] Unlinking and destroying BPF resources\n");

    if (unlink(PIN_LINK_NETACCESS) < 0) {
        perror("Error unlinking " PIN_LINK_NETACCESS);
    } else {
        printf("Unlinked %s\n", PIN_LINK_NETACCESS);
    }

    if (unlink(PIN_LINK_CHILD) < 0) {
        perror("Error unlinking " PIN_LINK_CHILD);
    } else {
        printf("Unlinked %s\n", PIN_LINK_CHILD);
    }

    if (unlink(PIN_LINK_CREATOR) < 0) {
        perror("Error unlinking " PIN_LINK_CREATOR);
    } else {
        printf("Unlinked %s\n", PIN_LINK_CREATOR);
    }

    if (unlink(PIN_LINK_ENFORCER) < 0) {
        perror("Error unlinking " PIN_LINK_ENFORCER);
    } else {
        printf("Unlinked %s\n", PIN_LINK_ENFORCER);
    }

    if (unlink(PIN_LINK_REMOVER) < 0) {
        perror("Error unlinking " PIN_LINK_REMOVER);
    } else {
        printf("Unlinked %s\n", PIN_LINK_REMOVER);
    }

    if (unlink(PIN_LINK_MAPPER) < 0) {
        perror("Error unlinking " PIN_LINK_MAPPER);
    } else {
        printf("Unlinked %s\n", PIN_LINK_MAPPER);
    }

    if (unlink(PIN_INODE_MAP) < 0) {
        perror("Error unlinking " PIN_INODE_MAP);
    } else {
        printf("Unlinked %s\n", PIN_INODE_MAP);
    }
    
    if (unlink(PIN_DOM_MAP) < 0) {
        perror("Error unlinking " PIN_DOM_MAP);
    } else {
        printf("Unlinked %s\n", PIN_DOM_MAP);
    }
    
    /*if (unlink(PIN_PROC_POLICY) < 0) {
        perror("Error unlinking " PIN_PROC_POLICY);
    } else {
        printf("Unlinked %s\n", PIN_PROC_POLICY);
    }*/

    if (unlink(PIN_PROC_MAP) < 0) {
        perror("Error unlinking " PIN_PROC_MAP);
    } else {
        printf("Unlinked %s\n", PIN_PROC_MAP);
    }

    if (unlink(PIN_ALLOW_WDIR_MAP) < 0) {
        perror("Error unlinking " PIN_ALLOW_WDIR_MAP);
    } else {
        printf("Unlinked %s\n", PIN_ALLOW_WDIR_MAP);
    }

    if (unlink(PIN_BLOCK_ENV_ARR) < 0) {
        perror("Error unlinking " PIN_BLOCK_ENV_ARR);
    } else {
        printf("Unlinked %s\n", PIN_BLOCK_ENV_ARR);
    }

    if (unlink(PIN_IP_MAP) < 0) {
        perror("Error unlinking " PIN_IP_MAP);
    } else {
        printf("Unlinked %s\n", PIN_IP_MAP);
    }

    if (unlink(PIN_LOC_IP_MAP) < 0) {
        perror("Error unlinking " PIN_LOC_IP_MAP);
    } else {
        printf("Unlinked %s\n", PIN_LOC_IP_MAP);
    }

    fprintf(stderr, "[cleanup] All BPF resources unlinked and cleaned up\n");
}

int main(void)
{
    cleanup_bpf_resources();

    return 0;
}

