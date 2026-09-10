// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *managed_maps[] = {
    "scx_task_profiles",
    "scx_vm_stats",
    "scx_enqueue_ts",
    "scx_last_event_ns",
    "scx_events",
};

static int mkdir_p(const char *path)
{
    char *tmp = strdup(path);
    char *p;
    int rc = 0;

    if (!tmp)
        return -1;
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) && errno != EEXIST) {
            rc = -1;
            goto out;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0755) && errno != EEXIST)
        rc = -1;
out:
    free(tmp);
    return rc;
}

static void best_effort_unlink(const char *path)
{
    if (unlink(path) && errno != ENOENT)
        fprintf(stderr, "warning: unlink %s: %s\n", path, strerror(errno));
}

static int ensure_memlock(void)
{
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (!setrlimit(RLIMIT_MEMLOCK, &rl) || errno == EPERM)
        return 0;
    return -1;
}

static int path_join(char *out, size_t len, const char *root,
                      const char *kind, const char *name)
{
    int n = snprintf(out, len, "%s/%s/%s", root, kind, name);
    if (n < 0 || (size_t)n >= len) {
        fprintf(stderr, "path too long: %s/%s/%s\n", root, kind, name);
        return -1;
    }
    return 0;
}

static void cleanup_pins(const char *root)
{
    char path[4096];
    size_t i;

    if (!path_join(path, sizeof(path), root, "links", "scheduler"))
        best_effort_unlink(path);
    for (i = 0; i < sizeof(managed_maps) / sizeof(managed_maps[0]); i++) {
        if (!path_join(path, sizeof(path), root, "maps", managed_maps[i]))
            best_effort_unlink(path);
    }
}

static int pin_map(struct bpf_object *obj, const char *root, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    char path[4096];

    if (!map) {
        fprintf(stderr, "required map %s missing from object\n", name);
        return -1;
    }
    if (path_join(path, sizeof(path), root, "maps", name))
        return -1;
    if (bpf_map__pin(map, path)) {
        fprintf(stderr, "pin map %s failed: %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

static int start_cmd(const char *objpath, const char *root)
{
    struct bpf_object *obj = NULL;
    struct bpf_map *ops = NULL;
    struct bpf_link *link = NULL;
    char maps[4096], links[4096], link_path[4096];
    size_t i;
    int rc = 1;

    if (snprintf(maps, sizeof(maps), "%s/maps", root) >= (int)sizeof(maps)
        || snprintf(links, sizeof(links), "%s/links", root) >= (int)sizeof(links)
        || path_join(link_path, sizeof(link_path), root, "links", "scheduler")) {
        fprintf(stderr, "pin-root path too long\n");
        return 2;
    }
    if (access(link_path, F_OK) == 0) {
        fprintf(stderr, "FluxVM sched_ext link already pinned at %s\n", link_path);
        return 3;
    }
    if (mkdir_p(maps) || mkdir_p(links)) {
        fprintf(stderr, "creating pin directories failed: %s\n", strerror(errno));
        return 4;
    }
    cleanup_pins(root);
    if (ensure_memlock()) {
        fprintf(stderr, "raising RLIMIT_MEMLOCK failed: %s\n", strerror(errno));
        return 4;
    }

    obj = bpf_object__open_file(objpath, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "opening %s failed\n", objpath);
        obj = NULL;
        goto out;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "loading sched_ext BPF object failed: %s\n", strerror(errno));
        goto out;
    }

    ops = bpf_object__find_map_by_name(obj, "fluxvm_scx_ops");
    if (!ops) {
        fprintf(stderr, "struct_ops map fluxvm_scx_ops missing\n");
        goto out;
    }
    for (i = 0; i < sizeof(managed_maps) / sizeof(managed_maps[0]); i++) {
        if (pin_map(obj, root, managed_maps[i]))
            goto out;
    }

    link = bpf_map__attach_struct_ops(ops);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "sched_ext struct_ops attach failed; another scheduler may be active or the kernel ABI is incompatible\n");
        link = NULL;
        goto out;
    }
    if (bpf_link__pin(link, link_path)) {
        fprintf(stderr, "pinning sched_ext link failed: %s\n", strerror(errno));
        goto out;
    }

    printf("{\"attached\":true,\"pin_root\":\"%s\",\"ops\":\"fluxvm_scx\"}\n", root);
    rc = 0;
out:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    if (rc)
        cleanup_pins(root);
    return rc;
}

static int verify_cmd(const char *objpath)
{
    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);

    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "open failed\n");
        return 4;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "BPF verifier/load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 5;
    }
    bpf_object__close(obj);
    puts("{\"verified\":true}");
    return 0;
}

static int status_cmd(const char *root)
{
    char link_path[4096];
    int fd;

    if (path_join(link_path, sizeof(link_path), root, "links", "scheduler"))
        return 2;
    fd = bpf_obj_get(link_path);
    if (fd < 0) {
        puts("{\"attached\":false}");
        return 0;
    }
    close(fd);
    printf("{\"attached\":true,\"pin_root\":\"%s\"}\n", root);
    return 0;
}

static int stop_cmd(const char *root)
{
    char link_path[4096];

    if (path_join(link_path, sizeof(link_path), root, "links", "scheduler"))
        return 2;
    if (unlink(link_path) && errno != ENOENT) {
        fprintf(stderr, "unpin scheduler link failed: %s\n", strerror(errno));
        return 4;
    }
    cleanup_pins(root);
    puts("{\"attached\":false}");
    return 0;
}

int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (argc == 4 && !strcmp(argv[1], "start"))
        return start_cmd(argv[2], argv[3]);
    if (argc == 3 && !strcmp(argv[1], "verify"))
        return verify_cmd(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "status"))
        return status_cmd(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "stop"))
        return stop_cmd(argv[2]);
    fprintf(stderr, "usage: %s start <bpf-object> <pin-root> | verify <bpf-object> | status <pin-root> | stop <pin-root>\n", argv[0]);
    return 2;
}
