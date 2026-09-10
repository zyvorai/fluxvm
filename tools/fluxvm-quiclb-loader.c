// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int join_path(char *out, size_t out_size, const char *dir, const char *name)
{
    int n = snprintf(out, out_size, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_size) {
        fprintf(stderr, "path too long: %s/%s\n", dir, name);
        return -1;
    }
    return 0;
}

static int mkdir_p(const char *path)
{
    char *tmp = strdup(path);
    if (!tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0755) && errno != EEXIST) { free(tmp); return -1; }
        *p = '/';
    }
    int rc = (mkdir(tmp, 0755) && errno != EEXIST) ? -1 : 0;
    free(tmp);
    return rc;
}
static unsigned flags_for(const char *mode)
{
    if (!strcmp(mode, "native")) return XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (!strcmp(mode, "generic")) return XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (!strcmp(mode, "offload")) return XDP_FLAGS_HW_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    return 0;
}
static int current_id(int ifindex, unsigned mode, __u32 *id)
{
    unsigned q = mode & (XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE | XDP_FLAGS_HW_MODE);
    *id = 0;
    return bpf_xdp_query_id(ifindex, q, id);
}
static int any_owner(int ifindex, __u32 *id, const char **mode)
{
    static const unsigned f[] = {XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE, XDP_FLAGS_HW_MODE};
    static const char *n[] = {"native", "generic", "offload"};
    for (int i = 0; i < 3; i++) {
        __u32 x = 0;
        if (!bpf_xdp_query_id(ifindex, f[i], &x) && x) { *id = x; *mode = n[i]; return 1; }
    }
    return 0;
}
static int prog_id_fd(int fd, __u32 *id)
{
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len)) return -1;
    *id = info.id;
    return 0;
}
static int pin_loaded(struct bpf_object *obj, struct bpf_program *prog, const char *root)
{
    char maps[4096], progs[4096], pp[4096];
    if (join_path(maps, sizeof(maps), root, "maps") || join_path(progs, sizeof(progs), root, "progs")) return -1;
    if (mkdir_p(maps) || mkdir_p(progs)) return -1;
    if (bpf_object__pin_maps(obj, maps)) return -1;
    if (join_path(pp, sizeof(pp), progs, "quiclb")) return -1;
    return bpf_program__pin(prog, pp);
}
static int load_cmd(const char *objpath, const char *root, const char *iface, const char *mode)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "unknown interface %s\n", iface); return 2; }
    unsigned flags = flags_for(mode);
    if (!flags) { fprintf(stderr, "mode must be native|generic|offload\n"); return 2; }
    __u32 owner = 0;
    const char *owner_mode = NULL;
    if (any_owner(ifindex, &owner, &owner_mode)) {
        fprintf(stderr, "refusing to replace existing XDP owner id=%u mode=%s on %s\n", owner, owner_mode, iface);
        return 3;
    }
    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open failed\n"); return 4; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "fluxvm_quiclb");
    if (!prog) { fprintf(stderr, "program missing\n"); bpf_object__close(obj); return 4; }
    if (!strcmp(mode, "offload")) {
        bpf_program__set_ifindex(prog, ifindex);
        struct bpf_map *m;
        bpf_object__for_each_map(m, obj) bpf_map__set_ifindex(m, ifindex);
    }
    if (bpf_object__load(obj)) { fprintf(stderr, "BPF load failed: %s\n", strerror(errno)); bpf_object__close(obj); return 5; }
    int fd = bpf_program__fd(prog);
    __u32 pid = 0;
    if (prog_id_fd(fd, &pid)) { bpf_object__close(obj); return 5; }
    if (pin_loaded(obj, prog, root)) { fprintf(stderr, "pin failed: %s\n", strerror(errno)); bpf_object__close(obj); return 6; }
    if (bpf_xdp_attach(ifindex, fd, flags, NULL)) { fprintf(stderr, "XDP attach failed: %s\n", strerror(errno)); bpf_object__close(obj); return 7; }
    printf("{\"interface\":\"%s\",\"ifindex\":%d,\"mode\":\"%s\",\"program_id\":%u}\n", iface, ifindex, mode, pid);
    bpf_object__close(obj);
    return 0;
}
static int status_cmd(const char *root, const char *iface, const char *mode)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) return 2;
    unsigned flags = flags_for(mode);
    if (!flags) return 2;
    char pp[4096];
    if (join_path(pp, sizeof(pp), root, "progs/quiclb")) return 2;
    int fd = bpf_obj_get(pp);
    if (fd < 0) { printf("{\"attached\":false}\n"); return 0; }
    __u32 own = 0, live = 0;
    prog_id_fd(fd, &own);
    close(fd);
    current_id(ifindex, flags, &live);
    printf("{\"attached\":%s,\"program_id\":%u,\"live_program_id\":%u,\"mode\":\"%s\"}\n", (own && own == live) ? "true" : "false", own, live, mode);
    return 0;
}
static int detach_cmd(const char *root, const char *iface, const char *mode)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) return 2;
    unsigned flags = flags_for(mode);
    if (!flags) return 2;
    char pp[4096];
    if (join_path(pp, sizeof(pp), root, "progs/quiclb")) return 2;
    int fd = bpf_obj_get(pp);
    if (fd < 0) return 0;
    __u32 own = 0, live = 0;
    prog_id_fd(fd, &own);
    close(fd);
    current_id(ifindex, flags, &live);
    if (live && live != own) { fprintf(stderr, "refusing detach: live XDP owner %u is not FluxVM program %u\n", live, own); return 3; }
    if (live && bpf_xdp_detach(ifindex, flags & ~XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) { fprintf(stderr, "detach failed: %s\n", strerror(errno)); return 4; }
    return 0;
}
struct service_key { __u32 generation; unsigned char rest[20]; };
struct backend_key { __u32 generation; __u32 service_id; __u32 backend_id; };
struct maglev_key { __u32 generation; __u32 service_id; __u32 slot; };
static int delete_generation(int fd, size_t key_sz, __u32 generation)
{
    void *key = calloc(1, key_sz), *next = calloc(1, key_sz);
    if (!key || !next) { free(key); free(next); return -1; }
    int have = 0, deleted = 0;
    while (bpf_map_get_next_key(fd, have ? key : NULL, next) == 0) {
        memcpy(key, next, key_sz);
        have = 1;
        __u32 g = 0;
        memcpy(&g, key, sizeof(g));
        if (g == generation) {
            if (!bpf_map_delete_elem(fd, key)) deleted++;
            have = 0;
        }
    }
    free(key); free(next);
    return deleted;
}
static int gc_map(const char *root, const char *name, size_t key_sz, __u32 generation)
{
    char maps[4096], p[4096];
    if (join_path(maps, sizeof(maps), root, "maps") || join_path(p, sizeof(p), maps, name)) return -1;
    int fd = bpf_obj_get(p);
    if (fd < 0) return -1;
    int n = delete_generation(fd, key_sz, generation);
    close(fd);
    return n;
}
static int gc_cmd(const char *root, const char *gstr)
{
    char *e = NULL;
    unsigned long x = strtoul(gstr, &e, 10);
    if (!e || *e || x > 0xffffffffu) return 2;
    __u32 g = (__u32)x;
    int a = gc_map(root, "fluxvm_quic_services", sizeof(struct service_key), g);
    int b = gc_map(root, "fluxvm_quic_backends", sizeof(struct backend_key), g);
    int c = gc_map(root, "fluxvm_quic_maglev", sizeof(struct maglev_key), g);
    printf("{\"generation\":%u,\"services\":%d,\"backends\":%d,\"maglev\":%d}\n", g, a, b, c);
    return 0;
}
int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (argc == 6 && !strcmp(argv[1], "load")) return load_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 5 && !strcmp(argv[1], "status")) return status_cmd(argv[2], argv[3], argv[4]);
    if (argc == 5 && !strcmp(argv[1], "detach")) return detach_cmd(argv[2], argv[3], argv[4]);
    if (argc == 4 && !strcmp(argv[1], "gc")) return gc_cmd(argv[2], argv[3]);
    fprintf(stderr, "usage: %s load <obj> <pin-root> <iface> <native|generic|offload> | status <pin-root> <iface> <mode> | detach <pin-root> <iface> <mode> | gc <pin-root> <generation>\n", argv[0]);
    return 2;
}
