// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp))
        return -ENAMETOOLONG;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) && errno != EEXIST)
            return -errno;
        *p = '/';
    }
    if (mkdir(tmp, 0755) && errno != EEXIST)
        return -errno;
    return 0;
}

/* GCC's -Wformat-truncation cannot prove a runtime `dir`/`name` combination
 * stays inside a PATH_MAX buffer, so it flags every raw "%s/%s" snprintf
 * into one as a possible truncation under -Werror. Check the return value
 * explicitly instead of silencing the warning -- this also makes an
 * actually-too-long path a real, reported error rather than a silently
 * truncated (and therefore wrong) one. */
static int join_path(char *out, size_t out_size, const char *dir, const char *name)
{
    int n = snprintf(out, out_size, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_size) {
        fprintf(stderr, "path too long: %s/%s\n", dir, name);
        return -1;
    }
    return 0;
}

static int reuse_map(struct bpf_object *obj, const char *name, const char *path, int required)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map) {
        fprintf(stderr, "map %s missing from object\n", name);
        return -ENOENT;
    }
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        if (!required && errno == ENOENT)
            return 1; /* caller will pin the freshly-created map after load */
        fprintf(stderr, "open pinned map %s: %s\n", path, strerror(errno));
        return -errno;
    }
    int err = bpf_map__reuse_fd(map, fd);
    if (err) {
        close(fd);
        fprintf(stderr, "reuse map %s: %s\n", name, strerror(-err));
        return err;
    }
    return 0; /* libbpf owns fd after successful reuse */
}

static int pin_map_if_new(struct bpf_object *obj, const char *name, const char *path)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map)
        return -ENOENT;
    if (access(path, F_OK) == 0)
        return 0;
    int err = bpf_map__pin(map, path);
    if (err && err != -EEXIST) {
        fprintf(stderr, "pin map %s at %s: %s\n", name, path, strerror(-err));
        return err;
    }
    return 0;
}

static int pin_link(struct bpf_link *link, const char *path)
{
    if (!link || libbpf_get_error(link))
        return -EINVAL;
    if (access(path, F_OK) == 0) {
        bpf_link__destroy(link);
        return 0;
    }
    int err = bpf_link__pin(link, path);
    if (err) {
        fprintf(stderr, "pin link %s: %s\n", path, strerror(-err));
        bpf_link__destroy(link);
        return err;
    }
    bpf_link__destroy(link); /* pin keeps the attachment alive */
    return 0;
}

static int attach_tracepoint(struct bpf_object *obj, const char *prog_name,
                             const char *category, const char *event,
                             const char *link_path)
{
    if (access(link_path, F_OK) == 0)
        return 1;
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog)
        return -ENOENT;
    struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, event);
    long err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "optional tracepoint %s/%s unavailable: %s\n",
                category, event, strerror((int)-err));
        return 0;
    }
    return pin_link(link, link_path) ? -1 : 1;
}

static int attach_kprobe(struct bpf_object *obj, const char *prog_name, int retprobe,
                         const char *func, const char *link_path)
{
    if (access(link_path, F_OK) == 0)
        return 1;
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog)
        return -ENOENT;
    struct bpf_link *link = bpf_program__attach_kprobe(prog, retprobe, func);
    long err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "optional %sprobe %s unavailable: %s\n",
                retprobe ? "kret" : "k", func, strerror((int)-err));
        return 0;
    }
    return pin_link(link, link_path) ? -1 : 1;
}

static int attach_pair_tp(struct bpf_object *obj, const char *a_prog, const char *a_event,
                          const char *a_pin, const char *b_prog, const char *b_event,
                          const char *b_pin)
{
    int a = attach_tracepoint(obj, a_prog, "vmscan", a_event, a_pin);
    int b = attach_tracepoint(obj, b_prog, "vmscan", b_event, b_pin);
    if (a < 0 || b < 0)
        return -1;
    if ((a == 0) != (b == 0)) {
        /* A half pair cannot produce reliable duration samples. */
        if (a > 0)
            unlink(a_pin);
        if (b > 0)
            unlink(b_pin);
        fprintf(stderr, "direct-reclaim tracepoint pair incomplete; disabled\n");
        return 0;
    }
    return a > 0 && b > 0;
}

static int attach_pair_kprobe(struct bpf_object *obj, const char *enter_pin, const char *exit_pin)
{
    int a = attach_kprobe(obj, "fluxvm_memprof_fault_enter", 0, "handle_mm_fault", enter_pin);
    int b = attach_kprobe(obj, "fluxvm_memprof_fault_exit", 1, "handle_mm_fault", exit_pin);
    if (a < 0 || b < 0)
        return -1;
    if ((a == 0) != (b == 0)) {
        if (a > 0)
            unlink(enter_pin);
        if (b > 0)
            unlink(exit_pin);
        fprintf(stderr, "handle_mm_fault kprobe pair incomplete; disabled\n");
        return 0;
    }
    return a > 0 && b > 0;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s <fluxvm_memprof.bpf.o> <intelligence-pin-root> [--replace-links]\n", argv[0]);
        return 2;
    }
    const char *obj_path = argv[1];
    const char *root = argv[2];
    int replace_links = argc == 4 && strcmp(argv[3], "--replace-links") == 0;
    if (argc == 4 && !replace_links) {
        fprintf(stderr, "unknown option %s\n", argv[3]);
        return 2;
    }

    char maps_dir[PATH_MAX], links_dir[PATH_MAX];
    if (join_path(maps_dir, sizeof(maps_dir), root, "memprof/maps") < 0 ||
        join_path(links_dir, sizeof(links_dir), root, "memprof/links") < 0) {
        return 1;
    }
    if (mkdir_p(maps_dir) || mkdir_p(links_dir)) {
        perror("mkdir memprof pin directories");
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    long open_err = libbpf_get_error(obj);
    if (open_err) {
        fprintf(stderr, "open %s: %s\n", obj_path, strerror((int)-open_err));
        return 1;
    }

    const char *shared[] = {"tracked_tgids", "tracked_tids", "tracked_cgroups"};
    for (size_t i = 0; i < sizeof(shared) / sizeof(shared[0]); i++) {
        char maps_subdir[PATH_MAX], path[PATH_MAX];
        if (join_path(maps_subdir, sizeof(maps_subdir), root, "maps") < 0 ||
            join_path(path, sizeof(path), maps_subdir, shared[i]) < 0) {
            bpf_object__close(obj);
            return 1;
        }
        if (reuse_map(obj, shared[i], path, 1)) {
            fprintf(stderr, "Runtime Intelligence shared maps must be loaded before Set 7\n");
            bpf_object__close(obj);
            return 1;
        }
    }

    const char *owned[] = {
        "memprof_fault_start", "memprof_reclaim_start", "memprof_stats",
        "memprof_hist", "memprof_first", "memprof_events",
    };
    for (size_t i = 0; i < sizeof(owned) / sizeof(owned[0]); i++) {
        char path[PATH_MAX];
        if (join_path(path, sizeof(path), maps_dir, owned[i]) < 0) {
            bpf_object__close(obj);
            return 1;
        }
        int r = reuse_map(obj, owned[i], path, 0);
        if (r < 0) {
            bpf_object__close(obj);
            return 1;
        }
    }

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load %s: %s\n", obj_path, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    for (size_t i = 0; i < sizeof(owned) / sizeof(owned[0]); i++) {
        char path[PATH_MAX];
        if (join_path(path, sizeof(path), maps_dir, owned[i]) < 0) {
            bpf_object__close(obj);
            return 1;
        }
        if (pin_map_if_new(obj, owned[i], path)) {
            bpf_object__close(obj);
            return 1;
        }
    }

    const char *link_names[] = {
        "kvm_entry", "fault_enter", "fault_exit", "reclaim_begin", "reclaim_end", "vhost_wakeup",
    };
    if (replace_links) {
        for (size_t i = 0; i < sizeof(link_names) / sizeof(link_names[0]); i++) {
            char path[PATH_MAX];
            if (join_path(path, sizeof(path), links_dir, link_names[i]) == 0)
                unlink(path);
        }
    }

    char kvm_pin[PATH_MAX], fe_pin[PATH_MAX], fx_pin[PATH_MAX], rb_pin[PATH_MAX], re_pin[PATH_MAX], vh_pin[PATH_MAX];
    if (join_path(kvm_pin, sizeof(kvm_pin), links_dir, "kvm_entry") < 0 ||
        join_path(fe_pin, sizeof(fe_pin), links_dir, "fault_enter") < 0 ||
        join_path(fx_pin, sizeof(fx_pin), links_dir, "fault_exit") < 0 ||
        join_path(rb_pin, sizeof(rb_pin), links_dir, "reclaim_begin") < 0 ||
        join_path(re_pin, sizeof(re_pin), links_dir, "reclaim_end") < 0 ||
        join_path(vh_pin, sizeof(vh_pin), links_dir, "vhost_wakeup") < 0) {
        bpf_object__close(obj);
        return 1;
    }

    int kvm = attach_tracepoint(obj, "fluxvm_memprof_kvm_entry", "kvm", "kvm_entry", kvm_pin);
    int fault = attach_pair_kprobe(obj, fe_pin, fx_pin);
    int reclaim = attach_pair_tp(obj,
        "fluxvm_memprof_reclaim_begin", "mm_vmscan_direct_reclaim_begin", rb_pin,
        "fluxvm_memprof_reclaim_end", "mm_vmscan_direct_reclaim_end", re_pin);
    int vhost = attach_kprobe(obj, "fluxvm_memprof_vhost_wakeup", 0, "vhost_poll_wakeup", vh_pin);
    if (kvm < 0 || fault < 0 || reclaim < 0 || vhost < 0) {
        bpf_object__close(obj);
        return 1;
    }

    printf("{\"ok\":true,\"kvm_entry\":%s,\"page_fault\":%s,\"direct_reclaim\":%s,\"vhost\":%s}\n",
           kvm ? "true" : "false", fault ? "true" : "false",
           reclaim ? "true" : "false", vhost ? "true" : "false");
    bpf_object__close(obj);
    return 0;
}
