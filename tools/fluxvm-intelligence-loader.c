// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof(tmp) - 1);
    if (len == 0 || len >= sizeof(tmp) - 1)
        return -EINVAL;
    memcpy(tmp, path, len);
    tmp[len] = '\0';
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(tmp, 0755) && errno != EEXIST) return -errno;
        *p = '/';
    }
    if (mkdir(tmp, 0755) && errno != EEXIST) return -errno;
    return 0;
}

static int unlink_cb(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st; (void)type; (void)ftw;
    return remove(path);
}

static int unload_root(const char *root)
{
    if (!root || root[0] != '/') return -EINVAL;
    if (access(root, F_OK) != 0) return errno == ENOENT ? 0 : -errno;
    if (nftw(root, unlink_cb, 32, FTW_DEPTH | FTW_PHYS) != 0) return -errno;
    return 0;
}

static void sanitize(char *s)
{
    for (; *s; s++) if (*s == '/' || *s == ':') *s = '_';
}

static int tracepoint_available(const char *section)
{
    const char *prefix = "tracepoint/";
    if (strncmp(section, prefix, strlen(prefix)) != 0) return 1;
    const char *name = section + strlen(prefix);
    char path[PATH_MAX];
    const char *roots[] = { "/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events" };
    for (size_t i = 0; i < sizeof(roots)/sizeof(roots[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/%s/id", roots[i], name) >= (int)sizeof(path)) continue;
        if (access(path, R_OK) == 0) return 1;
    }
    return 0;
}

static int load_object(const char *object_path, const char *root)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link **links = NULL;
    size_t link_count = 0, link_cap = 0;
    char map_dir[PATH_MAX], link_dir[PATH_MAX], link_path[PATH_MAX];
    int err = 0;

    if (snprintf(map_dir, sizeof(map_dir), "%s/maps", root) >= (int)sizeof(map_dir) ||
        snprintf(link_dir, sizeof(link_dir), "%s/links", root) >= (int)sizeof(link_dir))
        return -ENAMETOOLONG;
    err = mkdir_p(map_dir); if (err) return err;
    err = mkdir_p(link_dir); if (err) return err;

    obj = bpf_object__open_file(object_path, NULL);
    err = libbpf_get_error(obj);
    if (err) { fprintf(stderr, "open %s: %s\n", object_path, strerror(-err)); return err; }
    err = bpf_object__load(obj);
    if (err) { fprintf(stderr, "load %s: %s\n", object_path, strerror(-err)); goto out; }
    err = bpf_object__pin_maps(obj, map_dir);
    if (err) { fprintf(stderr, "pin maps at %s: %s\n", map_dir, strerror(-err)); goto out; }

    bpf_object__for_each_program(prog, obj) {
        const char *section = bpf_program__section_name(prog);
        if (!tracepoint_available(section)) {
            fprintf(stderr, "skip unavailable tracepoint: %s\n", section);
            continue;
        }
        struct bpf_link *link = bpf_program__attach(prog);
        long lerr = libbpf_get_error(link);
        if (lerr) {
            fprintf(stderr, "attach %s (%s): %s\n", bpf_program__name(prog), section, strerror((int)-lerr));
            err = (int)lerr; goto out;
        }
        if (link_count == link_cap) {
            size_t next = link_cap ? link_cap * 2 : 8;
            void *p = realloc(links, next * sizeof(*links));
            if (!p) { bpf_link__destroy(link); err = -ENOMEM; goto out; }
            links = p; link_cap = next;
        }
        links[link_count++] = link;
        char name[256]; snprintf(name, sizeof(name), "%s", bpf_program__name(prog)); sanitize(name);
        if (snprintf(link_path, sizeof(link_path), "%s/%s", link_dir, name) >= (int)sizeof(link_path)) { err = -ENAMETOOLONG; goto out; }
        unlink(link_path);
        err = bpf_link__pin(link, link_path);
        if (err) { fprintf(stderr, "pin link %s: %s\n", link_path, strerror(-err)); goto out; }
    }
    if (link_count == 0) { fprintf(stderr, "no supported tracepoints were attached\n"); err = -ENOTSUP; goto out; }
    printf("FluxVM runtime intelligence loaded: %s -> %s (%zu links)\n", object_path, root, link_count);
out:
    if (err) unload_root(root);
    for (size_t i = 0; i < link_count; i++) bpf_link__destroy(links[i]);
    free(links); bpf_object__close(obj); return err;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--unload") == 0) return unload_root(argv[2]) ? 1 : 0;
    if (argc != 4 || strcmp(argv[1], "--load") != 0) {
        fprintf(stderr, "usage: %s --load <bpf-object> <pin-root>\n       %s --unload <pin-root>\n", argv[0], argv[0]);
        return 2;
    }
    unload_root(argv[3]);
    return load_object(argv[2], argv[3]) ? 1 : 0;
}
