#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#define LOC_IP_MAP_PATH "/sys/fs/bpf/loc_ip_map"
#define INODEPOLICY_MAP_PATH "/sys/fs/bpf/inodepolicy_map"
#define ALLOW_WDIR_MAP_PATH "/sys/fs/bpf/allow_wdir_map"
#define BLOCK_ENV_ARR_PATH "/sys/fs/bpf/block_env_arr"
#define DOM_MAP_PATH "/sys/fs/bpf/dom_map"
#define RUN(cmd) if (system(cmd) != 0) perror(cmd)


struct inode_key {
    __u64 dev;
    __u64 ino;
};

static inline __u64 make_kernel_dev(__u64 dev)
{
    unsigned int major_num = major(dev);
    unsigned int minor_num = minor(dev);
    return ((unsigned long long)major_num << 20) | minor_num;
}

void setup_crontab_and_logs() {
    char cwd[512];

    if (!getcwd(cwd, sizeof(cwd))) {
        perror("getcwd failed");
        return;
    }

    printf("current dir: %s\n", cwd);

    RUN("mkdir -p /var/log/dom_ip_updater");
    RUN("chown root:root /var/log/dom_ip_updater");
    RUN("chmod 700 /var/log/dom_ip_updater");

    char cron_line[1024];
    if (snprintf(cron_line, sizeof(cron_line),
        "0 * * * * %s/dom_ip_updater >> "
        "/var/log/dom_ip_updater/dom_ip_updater_$(date +\\%%Y\\%%m\\%%d_\\%%H\\%%M).log 2>&1\n",
        cwd) >= sizeof(cron_line))
    {
        fprintf(stderr, "cron_line truncated!\n");
        return;
    }

    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        perror("popen");
        return;
    }

    char existing[16384];
    size_t n = fread(existing, 1, sizeof(existing) - 1, fp);
    if (n == 0 && ferror(fp)) {
        perror("fread existing crontab failed");
        pclose(fp);
        return;
    }
    existing[n] = '\0';   

    pclose(fp);

    if (strstr(existing, cron_line) != NULL) {
        return;
    }

    FILE *tmp = fopen("/tmp/newcron.txt", "w");
    if (!tmp) {
        perror("fopen /tmp/newcron.txt");
        return;
    }

    if (fwrite(existing, 1, strlen(existing), tmp) != strlen(existing)) {
        perror("fwrite existing cron failed");
        fclose(tmp);
        unlink("/tmp/newcron.txt");
        return;
    }

    if (fwrite(cron_line, 1, strlen(cron_line), tmp) != strlen(cron_line)) {
        perror("fwrite cron_line failed");
        fclose(tmp);
        unlink("/tmp/newcron.txt");
        return;
    }

    fclose(tmp);

    if (system("crontab /tmp/newcron.txt") != 0) {
        perror("installing crontab failed");
    } else {
        printf("Added cron entry:\n%s", cron_line);
    }

    unlink("/tmp/newcron.txt");
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config.json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *config_path = argv[1];
    int policy_id = 1;

    int map_fd = bpf_obj_get(INODEPOLICY_MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open inodepolicy_map");
        return EXIT_FAILURE;
    }

    int wdir_map_fd = bpf_obj_get(ALLOW_WDIR_MAP_PATH);
    if (wdir_map_fd < 0) {
        perror("Failed to open allow_wdir_map");
        close(map_fd);
        return EXIT_FAILURE;
    }

    struct json_object *parsed = json_object_from_file(config_path);
    if (!parsed) {
        fprintf(stderr, "Error: Unable to parse configuration JSON: %s\n", config_path);
        close(map_fd);
        close(wdir_map_fd);
        return EXIT_FAILURE;
    }

    struct json_object *binaries;
    if (!json_object_object_get_ex(parsed, "binaries", &binaries)) {
        fprintf(stderr, "Error: 'binaries' field missing in configuration file.\n");
        json_object_put(parsed);
        close(map_fd);
        close(wdir_map_fd);
        return EXIT_FAILURE;
    }

    int arr_len = json_object_array_length(binaries);
    for (int i = 0; i < arr_len; i++) {
        const char *path = json_object_get_string(json_object_array_get_idx(binaries, i));
        if (!path) continue;

        struct stat st;
        if (stat(path, &st) != 0) {
            perror("Failed to stat binary path");
            continue;
        }

        struct inode_key key = {
            .dev = make_kernel_dev(st.st_dev),
            .ino = st.st_ino,
        };

        if (bpf_map_update_elem(map_fd, &key, &policy_id, BPF_ANY) != 0) {
            perror("Failed to update inodepolicy_map");
        } else {
            printf("Registered binary: %s (dev=%llu, ino=%llu) with policy_id=%d\n",
                   path,
                   (unsigned long long)key.dev,
                   (unsigned long long)key.ino,
                   policy_id);
        }
        policy_id++;
    }

    struct json_object *fs_policies, *allowed_dirs;
if (json_object_object_get_ex(parsed, "filesystem_policies", &fs_policies) &&
    json_object_object_get_ex(fs_policies, "allowed_write_dirs", &allowed_dirs)) {

    int dir_count = json_object_array_length(allowed_dirs);
    for (int i = 0; i < dir_count; i++) {
        const char *dir_path = json_object_get_string(json_object_array_get_idx(allowed_dirs, i));
        if (!dir_path) continue;

        struct stat st;
        if (stat(dir_path, &st) != 0) {

    /* instead of failing , create allowed dir if not exists and give rwx perms to all */
    if (mkdir(dir_path, 0777) != 0) {
        fprintf(stderr,
                "Failed to create allowed write directory '%s': %s\n",
                dir_path, strerror(errno));
        continue;
    }

    /* stat again to get inode + dev of newly created directory */
    if (stat(dir_path, &st) != 0) {
        fprintf(stderr,
                "Failed to stat newly created directory '%s': %s\n",
                dir_path, strerror(errno));
        continue;
    }

    /* ensure directory has 0777 permissions (rwx for all) */
    if (chmod(dir_path, 0777) != 0) {
        fprintf(stderr,
                "Failed to chmod allowed write directory '%s': %s\n",
                dir_path, strerror(errno));
        /* Do not continue: directory exists; we still want to insert key */
    }

    printf("Created allowed write directory: %s with 0777 permissions\n",
           dir_path);
}


        struct inode_key dir_key = {
            .dev = make_kernel_dev(st.st_dev),
            .ino = st.st_ino,
        };

        __u32 allowed = 1;
        if (bpf_map_update_elem(wdir_map_fd, &dir_key, &allowed, BPF_ANY) != 0) {
            perror("Failed to update allow_wdir_map");
        } else {
           printf("Registered allowed write directory: %s (dev=%llu, ino=%llu)\n",
                   dir_path,
                   (unsigned long long)dir_key.dev,
                   (unsigned long long)dir_key.ino);
        }
    }
} else {
    fprintf(stderr, "Warning: 'filesystem_policies.allowed_write_dirs' not found.\n");
}


    int env_map_fd = bpf_obj_get(BLOCK_ENV_ARR_PATH);
    if (env_map_fd < 0) {
        perror("Failed to open block_env_arr map");
    } else {
        struct json_object *sec_policies, *blocked_env;
        if (json_object_object_get_ex(parsed, "security_policies", &sec_policies) &&
            json_object_object_get_ex(sec_policies, "blocked_environment", &blocked_env)) {

            int env_count = json_object_array_length(blocked_env);
            for (int i = 0; i < env_count && i < 32; i++) {
                const char *env_name = json_object_get_string(json_object_array_get_idx(blocked_env, i));
                if (!env_name || env_name[0] == '\0') continue;

                char key[32] = {0};
                __u32 val = 1;
                snprintf(key, sizeof(key), "%.*s", 31, env_name);

                if (bpf_map_update_elem(env_map_fd, key, &val, BPF_ANY) != 0) {
                    perror("Failed to update block_env_arr map");
                } else {
                    printf("Registered blocked environment variable: %s\n", key);
                }
            }
        } else {
            fprintf(stderr, "Warning: 'security_policies.blocked_environment' not found.\n");
        }
    }

    int dom_map_fd = bpf_obj_get(DOM_MAP_PATH);
    if (dom_map_fd < 0) {
        perror("Failed to open dom_map");
    } else {
        struct json_object *net_policies, *allowed_domains;
        if (json_object_object_get_ex(parsed, "network_policies", &net_policies) &&
            json_object_object_get_ex(net_policies, "allowed_domains", &allowed_domains)) {

            int dom_count = json_object_array_length(allowed_domains);
            printf("Discovered %d allowed domains in configuration.\n", dom_count);

            for (int i = 0; i < dom_count && i < 64; i++) {
                const char *domain = json_object_get_string(json_object_array_get_idx(allowed_domains, i));
                if (!domain) continue;

                printf("Processing domain %d: %s\n", i + 1, domain);

                __u8 key[256] = {0};
                size_t len = strlen(domain);
                if (len > 255) len = 255;
                memcpy(key, domain, len);

                __u32 val = 1;
                if (bpf_map_update_elem(dom_map_fd, key, &val, BPF_ANY) != 0) {
                    perror("Failed to update dom_map");
                } else {
                    printf("Registered allowed domain: %s\n", domain);
                }
            }
        } else {
            fprintf(stderr, "Warning: 'network_policies.allowed_domains' not found.\n");
        }
    }

    int loc_fd = bpf_obj_get(LOC_IP_MAP_PATH);
    if (loc_fd < 0) {
        perror("Failed to open loc_ip_map");
    }

    const char *local_ips[] = {
        "127.0.0.1",
        "127.0.1.1",
        "127.0.0.53"
    };

    for (int i = 0; i < 3; i++) {
        struct in_addr addr;
        if (inet_pton(AF_INET, local_ips[i], &addr) != 1) {
            fprintf(stderr, "Invalid IP address format: %s\n", local_ips[i]);
            continue;
        }

        __u32 key = addr.s_addr;
        __u32 val = 1;

        if (bpf_map_update_elem(loc_fd, &key, &val, BPF_ANY) != 0) {
            perror("Failed to update loc_ip_map");
        } else {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            printf("Registered local IP address: %s\n", buf);
        }
    }
setup_crontab_and_logs();
    
    json_object_put(parsed);
    close(loc_fd);
    close(map_fd);
    close(dom_map_fd);
    close(wdir_map_fd);
    close(env_map_fd);
    printf("starting dom_ip_updater\n");
    execl("./dom_ip_updater", "dom_ip_updater", (char*)NULL);
    perror("Execution of dom_ip_updater failed\n");

    return EXIT_FAILURE;
}

