#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#define DOM_MAP_PATH "/sys/fs/bpf/dom_map"
#define IP_MAP_PATH  "/sys/fs/bpf/ip_map"
#define MAX_DOM_LEN  256
#define MAX_DOMAINS  64
#define MAX_IPS     8192

// Helper: check if IP already exists in array
static int ip_exists(__u32 *arr, int count, __u32 ip) {
    for (int i = 0; i < count; i++)
        if (arr[i] == ip) return 1;
    return 0;
}

int main(void) {
    int dom_fd = bpf_obj_get(DOM_MAP_PATH);
    if (dom_fd < 0) { perror("bpf_obj_get dom_map"); return EXIT_FAILURE; }

    int ip_fd = bpf_obj_get(IP_MAP_PATH);
    if (ip_fd < 0) { perror("bpf_obj_get ip_map"); close(dom_fd); return EXIT_FAILURE; }

    __u8 dom_key[MAX_DOM_LEN], next_key[MAX_DOM_LEN];
    struct { char domain[MAX_DOM_LEN]; } domains[MAX_DOMAINS];
    int domain_count = 0;

    memset(dom_key, 0, sizeof(dom_key));
    while (bpf_map_get_next_key(dom_fd, domain_count == 0 ? NULL : &dom_key, &next_key) == 0) {
        memcpy(dom_key, next_key, MAX_DOM_LEN);
        dom_key[MAX_DOM_LEN-1] = '\0';
        strncpy(domains[domain_count].domain, (char*)dom_key, MAX_DOM_LEN);
        domain_count++;
        if (domain_count >= MAX_DOMAINS) break;
    }

    if (domain_count == 0) {
        fprintf(stderr, "No domains in dom_map\n");
        close(dom_fd); close(ip_fd); return EXIT_FAILURE;
    }

    printf("Total domains retrieved from dom_map: %d\n", domain_count);
    for (int i = 0; i < domain_count; i++)
        printf("Domain #%d retrieved from dom_map: %s\n", i+1, domains[i].domain);

    // Resolve all domains
    struct in_addr resolved_ips[MAX_IPS];
    int ip_count = 0;
    int all_resolved = 1;

    for (int i = 0; i < domain_count; i++) {
        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;

        printf("Resolving domain: %s\n", domains[i].domain);
        if (getaddrinfo(domains[i].domain, NULL, &hints, &res) != 0) {
            fprintf(stderr, "Failed to resolve domain: %s\n", domains[i].domain);
            all_resolved = 0;
            break;
        }

        for (p = res; p != NULL; p = p->ai_next) {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            if (!ip_exists((__u32*)resolved_ips, ip_count, sin->sin_addr.s_addr)) {
                if (ip_count < MAX_IPS) resolved_ips[ip_count++] = sin->sin_addr;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                printf("Resolved %s → %s\n", domains[i].domain, ip_str);
            }
        }
        freeaddrinfo(res);
    }

    if (!all_resolved) {
        fprintf(stderr, "Not all domains resolved; keeping existing ip_map.\n");
        close(dom_fd); close(ip_fd);
        return EXIT_FAILURE;
    }

    // Flush existing ip_map
    __u32 ip_key, next_ip;
    int ret = bpf_map_get_next_key(ip_fd, NULL, &next_ip);
    while (ret == 0) {
        ip_key = next_ip;
        bpf_map_delete_elem(ip_fd, &ip_key);
        ret = bpf_map_get_next_key(ip_fd, &ip_key, &next_ip);
    }

    // Insert unique IPs into ip_map
    for (int i = 0; i < ip_count; i++) {
        __u32 key = resolved_ips[i].s_addr;
        __u32 val = 1;
        if (bpf_map_update_elem(ip_fd, &key, &val, BPF_ANY) != 0) {
            perror("bpf_map_update_elem (ip_map)");
        } else {
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr = resolved_ips[i];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            printf("Added IP %s to ip_map\n", ip_str);
        }
    }

    close(dom_fd); close(ip_fd);
    return EXIT_SUCCESS;
}

