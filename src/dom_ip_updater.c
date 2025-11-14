#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>

#define DOM_MAP_PATH "/sys/fs/bpf/dom_map"
#define IP_MAP_PATH  "/sys/fs/bpf/ip_map"
#define MAX_DOM_LEN  256
#define MAX_DOMAINS  64
#define MAX_IPS      8192

static int ip_exists(__u32 *arr, int count, __u32 ip) {
    for (int i = 0; i < count; i++)
        if (arr[i] == ip) return 1;
    return 0;
}

int main(void) {
    int dom_fd = bpf_obj_get(DOM_MAP_PATH);
    if (dom_fd < 0) {
        perror("Failed to open dom_map");
        return EXIT_FAILURE;
    }

    int ip_fd = bpf_obj_get(IP_MAP_PATH);
    if (ip_fd < 0) {
        perror("Failed to open ip_map");
        close(dom_fd);
        return EXIT_FAILURE;
    }

    __u8 dom_key[MAX_DOM_LEN], next_key[MAX_DOM_LEN];
    struct { char domain[MAX_DOM_LEN]; } domains[MAX_DOMAINS];
    int domain_count = 0;

    memset(dom_key, 0, sizeof(dom_key));

    while (bpf_map_get_next_key(dom_fd, domain_count == 0 ? NULL : &dom_key, &next_key) == 0) {
        memcpy(dom_key, next_key, MAX_DOM_LEN);
        dom_key[MAX_DOM_LEN - 1] = '\0';
        strncpy(domains[domain_count].domain, (char*)dom_key, MAX_DOM_LEN);
        domain_count++;
        if (domain_count >= MAX_DOMAINS) break;
    }

    if (domain_count == 0) {
        fprintf(stderr, "No domains found in dom_map. Nothing to resolve.\n");
        close(dom_fd);
        close(ip_fd);
        return EXIT_FAILURE;
    }

    printf("Discovered %d domain entries in dom_map.\n", domain_count);
    for (int i = 0; i < domain_count; i++)
        printf("Loaded domain %d: %s\n", i + 1, domains[i].domain);

    struct in_addr resolved_ips[MAX_IPS];
    int ip_count = 0;
    int all_resolved = 1;

    for (int i = 0; i < domain_count; i++) {
        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;

        printf("Resolving domain: %s\n", domains[i].domain);

        if (getaddrinfo(domains[i].domain, NULL, &hints, &res) != 0) {
            fprintf(stderr, "Resolution failed for domain: %s\n", domains[i].domain);
            all_resolved = 0;
            break;
        }

        for (p = res; p != NULL; p = p->ai_next) {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;

            if (!ip_exists((__u32*)resolved_ips, ip_count, sin->sin_addr.s_addr)) {
                if (ip_count < MAX_IPS)
                    resolved_ips[ip_count++] = sin->sin_addr;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
                printf("Resolved %s to %s\n", domains[i].domain, ip_str);
            }
        }
        freeaddrinfo(res);
    }

    if (!all_resolved) {
        fprintf(stderr, "Some domains could not be resolved. ip_map update aborted.\n");
        close(dom_fd);
        close(ip_fd);
        return EXIT_FAILURE;
    }

    __u32 ip_key, next_ip;
    int ret = bpf_map_get_next_key(ip_fd, NULL, &next_ip);
    while (ret == 0) {
        ip_key = next_ip;
        bpf_map_delete_elem(ip_fd, &ip_key);
        ret = bpf_map_get_next_key(ip_fd, &ip_key, &next_ip);
    }

    printf("ip_map cleared. Inserting resolved IPs...\n");

    for (int i = 0; i < ip_count; i++) {
        __u32 key = resolved_ips[i].s_addr;
        __u32 val = 1;

        if (bpf_map_update_elem(ip_fd, &key, &val, BPF_ANY) != 0) {
            perror("Failed to insert IP into ip_map");
        } else {
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr = resolved_ips[i];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            printf("Inserted IP: %s\n", ip_str);
        }
    }

    printf("ip_map update complete. Total unique IPs inserted: %d\n", ip_count);

    close(dom_fd);
    close(ip_fd);

    return EXIT_SUCCESS;
}

