#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>   // for major(), minor()
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

struct inode_key {
    __u64 dev;
    __u64 ino;
};

static inline __u64 make_kernel_dev(__u64 dev)
{
    unsigned int major_num = major(dev);
    unsigned int minor_num = minor(dev);
    /* Match kernel's new_encode_dev() (see include/linux/kdev_t.h) */
    return ((unsigned long long)major_num << 20) | minor_num;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config.json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *config_path = argv[1];
    int policy_id = 1;

    /* open pinned inodepolicy_map */
    int map_fd = bpf_obj_get("/sys/fs/bpf/inodepolicy_map");
    if (map_fd < 0) {
        perror("bpf_obj_get inodepolicy_map");
        return EXIT_FAILURE;
    }

    /* open pinned allow_wdir_map */
    int wdir_map_fd = bpf_obj_get("/sys/fs/bpf/allow_wdir_map");
    if (wdir_map_fd < 0) {
        perror("bpf_obj_get allow_wdir_map");
        close(map_fd);
        return EXIT_FAILURE;
    }

    struct json_object *parsed = json_object_from_file(config_path);
    if (!parsed) {
        fprintf(stderr, "Failed to parse JSON: %s\n", config_path);
        close(map_fd);
        close(wdir_map_fd);
        return EXIT_FAILURE;
    }

    /* ---------- STEP 1: binaries[] ---------- */
    struct json_object *binaries;
    if (!json_object_object_get_ex(parsed, "binaries", &binaries)) {
        fprintf(stderr, "No 'binaries' field in JSON\n");
        json_object_put(parsed);
        close(map_fd);
        close(wdir_map_fd);
        return EXIT_FAILURE;
    }

    int arr_len = json_object_array_length(binaries);
    for (int i = 0; i < arr_len; i++) {
        const char *path = json_object_get_string(json_object_array_get_idx(binaries, i));
        if (!path)
            continue;

        struct stat st;
        if (stat(path, &st) != 0) {
            perror("stat (binary)");
            continue;
        }

        struct inode_key key = {
            .dev = make_kernel_dev(st.st_dev),
            .ino = st.st_ino,
        };

        if (bpf_map_update_elem(map_fd, &key, &policy_id, BPF_ANY) != 0) {
            perror("bpf_map_update_elem (inodepolicy_map)");
        } else {
            printf("Added %s (dev=%llu, ino=%llu) → policy_id=%d\n",
                   path,
                   (unsigned long long)key.dev,
                   (unsigned long long)key.ino,
                   policy_id);
        }

        policy_id++;
    }

    /* ---------- STEP 2: filesystem_policies.allowed_write_dirs[] ---------- */
    struct json_object *fs_policies, *allowed_dirs;
    if (json_object_object_get_ex(parsed, "filesystem_policies", &fs_policies) &&
        json_object_object_get_ex(fs_policies, "allowed_write_dirs", &allowed_dirs)) {

        int dir_count = json_object_array_length(allowed_dirs);
        for (int i = 0; i < dir_count; i++) {
            const char *dir_path = json_object_get_string(json_object_array_get_idx(allowed_dirs, i));
            if (!dir_path)
                continue;

            struct stat st;
            if (stat(dir_path, &st) != 0) {
                perror("stat (allow_wdir)");
                continue;
            }

            struct inode_key dir_key = {
                .dev = make_kernel_dev(st.st_dev),
                .ino = st.st_ino,
            };

            /* any nonzero value marks allowed dir */
            __u32 allowed = 1;

            if (bpf_map_update_elem(wdir_map_fd, &dir_key, &allowed, BPF_ANY) != 0) {
                perror("bpf_map_update_elem (allow_wdir_map)");
            } else {
                printf("Added allowed write dir %s (dev=%llu, ino=%llu)\n",
                       dir_path,
                       (unsigned long long)dir_key.dev,
                       (unsigned long long)dir_key.ino);
            }
        }
    } else {
        fprintf(stderr, "No 'filesystem_policies.allowed_write_dirs' found in config.\n");
    }

    int env_map_fd = bpf_obj_get("/sys/fs/bpf/block_env_arr");
    if (env_map_fd < 0) {
        perror("bpf_obj_get block_env_arr");
    } else {
    struct json_object *sec_policies, *blocked_env;
    if (json_object_object_get_ex(parsed, "security_policies", &sec_policies) &&
        json_object_object_get_ex(sec_policies, "blocked_environment", &blocked_env)) {

        int env_count = json_object_array_length(blocked_env);
        for (int i = 0; i < env_count && i < 32; i++) {
            const char *env_name =
                json_object_get_string(json_object_array_get_idx(blocked_env, i));
            if (!env_name || env_name[0] == '\0')
                continue;

            char key[32] = {0};
            __u32 val = 1;

            /* copy up to 15 chars of env name (16th is '\0') */
            snprintf(key, sizeof(key), "%.*s", 31, env_name);

            if (bpf_map_update_elem(env_map_fd, key, &val, BPF_ANY) != 0) {
                perror("bpf_map_update_elem (block_env_arr)");
            } else {
                printf("Added blocked env = '%s'\n", key);
            }
        }
    } else {
        fprintf(stderr, "No 'security_policies.blocked_environment' found in config.\n");
    }
    }

    json_object_put(parsed);
    close(map_fd);
    close(wdir_map_fd);
    close(env_map_fd);
    return EXIT_SUCCESS;
}

