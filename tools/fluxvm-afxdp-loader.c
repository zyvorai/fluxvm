// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define IFACE_ENABLED (1u << 0)

struct iface_cfg {
    uint64_t vm_key;
    uint32_t generation;
    uint16_t slot;
    uint16_t flags;
    uint32_t sample_rate;
    uint32_t reserved;
};

static int mkdir_p(const char *path)
{
    char tmp[4096];
    size_t n = strlen(path);
    if (!n || n >= sizeof(tmp)) return -ENAMETOOLONG;
    memcpy(tmp, path, n + 1);
    for (char *q = tmp + 1; *q; q++) {
        if (*q != '/') continue;
        *q = 0;
        if (mkdir(tmp, 0755) && errno != EEXIST) return -errno;
        *q = '/';
    }
    if (mkdir(tmp, 0755) && errno != EEXIST) return -errno;
    return 0;
}


static void remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) { (void)unlink(path); return; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >= (int)sizeof(child)) continue;
        struct stat st;
        if (!lstat(child, &st) && S_ISDIR(st.st_mode)) remove_tree(child);
        else (void)unlink(child);
    }
    closedir(d);
    (void)rmdir(path);
}

static int query_mode(int ifindex, uint32_t flags, uint32_t *id)
{
    *id = 0;
    int err = bpf_xdp_query_id(ifindex, flags, id);
    return err < 0 ? err : 0;
}

static int existing_owner(int ifindex, uint32_t *id, uint32_t *flags)
{
    const uint32_t modes[] = {XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE, XDP_FLAGS_HW_MODE};
    for (size_t i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
        uint32_t cur = 0;
        int err = query_mode(ifindex, modes[i], &cur);
        if (!err && cur) { *id = cur; *flags = modes[i]; return 1; }
    }
    *id = 0; *flags = 0;
    return 0;
}

static int attach_one(int ifindex, int prog_fd, uint32_t mode)
{
    return bpf_xdp_attach(ifindex, prog_fd, mode | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
}

static void detach_if_owned(int ifindex, uint32_t mode, uint32_t prog_id)
{
    uint32_t cur = 0;
    if (!query_mode(ifindex, mode, &cur) && cur == prog_id)
        (void)bpf_xdp_detach(ifindex, mode, NULL);
}

static int program_id(int prog_fd, uint32_t *id)
{
    struct bpf_prog_info info = {};
    uint32_t len = sizeof(info);
    int err = bpf_obj_get_info_by_fd(prog_fd, &info, &len);
    if (err) return -errno;
    *id = info.id;
    return 0;
}

static int try_pair(int a, int b, int prog_fd, uint32_t mode, uint32_t prog_id)
{
    int err = attach_one(a, prog_fd, mode);
    if (err) return err;
    err = attach_one(b, prog_fd, mode);
    if (err) {
        detach_if_owned(a, mode, prog_id);
        return err;
    }
    return 0;
}

static int update_iface(int map_fd, int ifindex, uint64_t vm_key, uint32_t generation,
                        uint16_t slot, uint32_t sample_rate)
{
    uint32_t key = (uint32_t)ifindex;
    struct iface_cfg v = {
        .vm_key = vm_key,
        .generation = generation,
        .slot = slot,
        .flags = IFACE_ENABLED,
        .sample_rate = sample_rate,
    };
    return bpf_map_update_elem(map_fd, &key, &v, BPF_ANY) ? -errno : 0;
}

static int do_load(const char *obj_path, const char *pin_root, const char *ifa,
                   const char *ifb, uint64_t vm_key, const char *mode_name,
                   uint32_t sample_rate)
{
    int a = if_nametoindex(ifa), b = if_nametoindex(ifb);
    if (!a || !b) { fprintf(stderr, "interface not found\n"); return 2; }
    if (a == b) { fprintf(stderr, "interfaces must be distinct\n"); return 2; }

    uint32_t owner = 0, owner_flags = 0;
    if (existing_owner(a, &owner, &owner_flags) > 0) {
        fprintf(stderr, "%s already has XDP program id %u; refusing replacement\n", ifa, owner);
        return 3;
    }
    if (existing_owner(b, &owner, &owner_flags) > 0) {
        fprintf(stderr, "%s already has XDP program id %u; refusing replacement\n", ifb, owner);
        return 3;
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) { fprintf(stderr, "open BPF object failed\n"); return 4; }
    int err = bpf_object__load(obj);
    if (err) { fprintf(stderr, "load BPF object: %s\n", strerror(-err)); bpf_object__close(obj); return 4; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "fluxvm_afxdp");
    if (!prog) { fprintf(stderr, "program fluxvm_afxdp missing\n"); bpf_object__close(obj); return 4; }
    int prog_fd = bpf_program__fd(prog), cfg_fd = bpf_object__find_map_fd_by_name(obj, "afxdp_ifaces");
    if (prog_fd < 0 || cfg_fd < 0) { fprintf(stderr, "required program/map missing\n"); bpf_object__close(obj); return 4; }
    uint32_t prog_id = 0;
    if (program_id(prog_fd, &prog_id)) { bpf_object__close(obj); return 4; }
    uint32_t generation = (uint32_t)getpid() ^ (uint32_t)time(NULL);
    if ((err = update_iface(cfg_fd, a, vm_key, generation, 0, sample_rate)) ||
        (err = update_iface(cfg_fd, b, vm_key, generation, 1, sample_rate))) {
        fprintf(stderr, "config map update failed: %s\n", strerror(-err)); bpf_object__close(obj); return 4;
    }

    uint32_t mode = 0;
    if (!strcmp(mode_name, "drv")) mode = XDP_FLAGS_DRV_MODE;
    else if (!strcmp(mode_name, "skb")) mode = XDP_FLAGS_SKB_MODE;
    else if (strcmp(mode_name, "auto")) { fprintf(stderr, "mode must be auto|drv|skb\n"); bpf_object__close(obj); return 2; }

    if (mode) err = try_pair(a, b, prog_fd, mode, prog_id);
    else {
        mode = XDP_FLAGS_DRV_MODE;
        err = try_pair(a, b, prog_fd, mode, prog_id);
        if (err) {
            mode = XDP_FLAGS_SKB_MODE;
            err = try_pair(a, b, prog_fd, mode, prog_id);
        }
    }
    if (err) { fprintf(stderr, "XDP attach pair failed: %s\n", strerror(-err)); bpf_object__close(obj); return 5; }

    char maps[4096], progpin[4096];
    snprintf(maps, sizeof(maps), "%s/maps", pin_root);
    snprintf(progpin, sizeof(progpin), "%s/prog", pin_root);
    if ((err = mkdir_p(pin_root)) || (err = mkdir_p(maps)) ||
        (err = bpf_object__pin_maps(obj, maps)) || (err = bpf_obj_pin(prog_fd, progpin))) {
        fprintf(stderr, "pinning failed: %s\n", strerror(err < 0 ? -err : errno));
        detach_if_owned(a, mode, prog_id);
        detach_if_owned(b, mode, prog_id);
        remove_tree(pin_root);
        bpf_object__close(obj); return 6;
    }
    printf("{\"ok\":true,\"program_id\":%u,\"generation\":%u,\"mode\":\"%s\",\"ifindex_a\":%d,\"ifindex_b\":%d}\n",
           prog_id, generation, mode == XDP_FLAGS_DRV_MODE ? "drv" : "skb", a, b);
    bpf_object__close(obj);
    return 0;
}

static int pinned_prog_id(const char *pin_root, uint32_t *id)
{
    char path[4096]; snprintf(path, sizeof(path), "%s/prog", pin_root);
    int fd = bpf_obj_get(path); if (fd < 0) return -errno;
    int err = program_id(fd, id); close(fd); return err;
}

static int owned_on(const char *ifname, uint32_t want, uint32_t *mode_out)
{
    int ifindex = if_nametoindex(ifname); if (!ifindex) return 0;
    const uint32_t modes[] = {XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE};
    for (size_t i = 0; i < 2; i++) {
        uint32_t cur = 0;
        if (!query_mode(ifindex, modes[i], &cur) && cur == want) { *mode_out = modes[i]; return 1; }
    }
    return 0;
}

static int do_status(const char *pin_root, const char *ifa, const char *ifb)
{
    uint32_t id = 0;
    if (pinned_prog_id(pin_root, &id)) { printf("{\"loaded\":false}\n"); return 0; }
    uint32_t ma = 0, mb = 0; int oa = owned_on(ifa, id, &ma), ob = owned_on(ifb, id, &mb);
    printf("{\"loaded\":true,\"program_id\":%u,\"owned_a\":%s,\"owned_b\":%s,\"mode_a\":\"%s\",\"mode_b\":\"%s\"}\n",
           id, oa?"true":"false", ob?"true":"false",
           ma==XDP_FLAGS_DRV_MODE?"drv":ma==XDP_FLAGS_SKB_MODE?"skb":"none",
           mb==XDP_FLAGS_DRV_MODE?"drv":mb==XDP_FLAGS_SKB_MODE?"skb":"none");
    return (oa && ob) ? 0 : 7;
}

static int do_unload(const char *pin_root, const char *ifa, const char *ifb)
{
    uint32_t id = 0; if (pinned_prog_id(pin_root, &id)) return 0;
    const char *names[] = {ifa, ifb};
    for (size_t n=0; n<2; n++) {
        int ifindex=if_nametoindex(names[n]); if (!ifindex) continue;
        const uint32_t modes[]={XDP_FLAGS_DRV_MODE,XDP_FLAGS_SKB_MODE};
        for (size_t i=0;i<2;i++) { uint32_t cur=0; if(!query_mode(ifindex,modes[i],&cur)&&cur==id) (void)bpf_xdp_detach(ifindex,modes[i],NULL); }
    }
    remove_tree(pin_root);
    printf("{\"ok\":true}\n"); return 0;
}

static void usage(const char *p)
{
    fprintf(stderr, "usage:\n  %s load <object> <pin-root> <iface-a> <iface-b> <vm-key> <auto|drv|skb> [sample-rate]\n  %s status <pin-root> <iface-a> <iface-b>\n  %s unload <pin-root> <iface-a> <iface-b>\n", p,p,p);
}

int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (argc >= 2 && !strcmp(argv[1], "load")) {
        if (argc < 8 || argc > 9) { usage(argv[0]); return 2; }
        char *end=NULL; errno=0; uint64_t key=strtoull(argv[6],&end,10);
        if(errno || !end || *end || !key){fprintf(stderr,"invalid vm-key\n");return 2;}
        uint32_t sample=argc==9?(uint32_t)strtoul(argv[8],NULL,10):0;
        return do_load(argv[2],argv[3],argv[4],argv[5],key,argv[7],sample);
    }
    if (argc==5 && !strcmp(argv[1],"status")) return do_status(argv[2],argv[3],argv[4]);
    if (argc==5 && !strcmp(argv[1],"unload")) return do_unload(argv[2],argv[3],argv[4]);
    usage(argv[0]); return 2;
}
