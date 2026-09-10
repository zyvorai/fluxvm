// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf)) return -ENAMETOOLONG;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0755) && errno != EEXIST) return -errno;
        *p = '/';
    }
    if (mkdir(buf, 0755) && errno != EEXIST) return -errno;
    return 0;
}

static uint32_t mode_flags(const char *mode)
{
    if (!mode || !strcmp(mode, "auto")) return 0;
    if (!strcmp(mode, "native")) return XDP_FLAGS_DRV_MODE;
    if (!strcmp(mode, "generic")) return XDP_FLAGS_SKB_MODE;
    return UINT32_MAX;
}

static int query_id(int ifindex, uint32_t flags, uint32_t *id)
{
    *id = 0;
    int rc = bpf_xdp_query_id(ifindex, flags, id);
    return rc < 0 ? rc : 0;
}

static int owned_program_id(const char *pin_dir, uint32_t *id)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/program", pin_dir);
    int fd = bpf_obj_get(path);
    if (fd < 0) return -errno;
    struct bpf_prog_info info = {};
    uint32_t len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(fd, &info, &len);
    close(fd);
    if (rc) return -errno;
    *id = info.id;
    return 0;
}

static int attach_cmd(const char *iface, const char *object, const char *pin_dir, const char *mode)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "unknown interface %s\n", iface); return 2; }
    uint32_t flags = mode_flags(mode);
    if (flags == UINT32_MAX) { fprintf(stderr, "mode must be auto|native|generic\n"); return 2; }

    uint32_t drv = 0, skb = 0;
    (void)query_id(ifindex, XDP_FLAGS_DRV_MODE, &drv);
    (void)query_id(ifindex, XDP_FLAGS_SKB_MODE, &skb);
    if (drv || skb) {
        fprintf(stderr, "refusing to replace existing XDP owner on %s (native=%u generic=%u)\n", iface, drv, skb);
        return 3;
    }

    struct bpf_object *obj = bpf_object__open_file(object, NULL);
    long err = libbpf_get_error(obj);
    if (err) { fprintf(stderr, "open %s: %s\n", object, strerror((int)-err)); return 4; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load %s failed\n", object); bpf_object__close(obj); return 4; }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "fluxvm_shield");
    if (!prog) { fprintf(stderr, "fluxvm_shield program missing\n"); bpf_object__close(obj); return 4; }

    char maps[4096], prog_pin[4096];
    snprintf(maps, sizeof(maps), "%s/maps", pin_dir);
    snprintf(prog_pin, sizeof(prog_pin), "%s/program", pin_dir);
    int rc = mkdir_p(maps);
    if (rc) { fprintf(stderr, "mkdir %s: %s\n", maps, strerror(-rc)); bpf_object__close(obj); return 4; }
    if (bpf_object__pin_maps(obj, maps)) { fprintf(stderr, "pin maps failed\n"); bpf_object__close(obj); return 4; }
    if (bpf_program__pin(prog, prog_pin)) {
        fprintf(stderr, "pin program failed\n");
        (void)bpf_object__unpin_maps(obj, maps);
        bpf_object__close(obj);
        return 4;
    }

    uint32_t attach_flags = flags | XDP_FLAGS_UPDATE_IF_NOEXIST;
    rc = bpf_xdp_attach(ifindex, bpf_program__fd(prog), attach_flags, NULL);
    if (rc) {
        fprintf(stderr, "XDP attach failed on %s: %s\n", iface, strerror(-rc));
        (void)bpf_program__unpin(prog, prog_pin);
        (void)bpf_object__unpin_maps(obj, maps);
        bpf_object__close(obj);
        return 5;
    }
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    (void)bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &info_len);
    printf("{\"attached\":true,\"ifindex\":%d,\"program_id\":%u,\"mode\":\"%s\"}\n",
           ifindex, info.id, mode ? mode : "auto");
    bpf_object__close(obj);
    return 0;
}

static int status_cmd(const char *iface, const char *pin_dir)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) return 2;
    uint32_t owned = 0, drv = 0, skb = 0;
    int owned_rc = owned_program_id(pin_dir, &owned);
    (void)query_id(ifindex, XDP_FLAGS_DRV_MODE, &drv);
    (void)query_id(ifindex, XDP_FLAGS_SKB_MODE, &skb);
    int active = owned_rc == 0 && (owned == drv || owned == skb);
    printf("{\"attached\":%s,\"ifindex\":%d,\"owned_program_id\":%u,\"native_program_id\":%u,\"generic_program_id\":%u}\n",
           active ? "true" : "false", ifindex, owned, drv, skb);
    return 0;
}

static int detach_cmd(const char *iface, const char *pin_dir)
{
    int ifindex = if_nametoindex(iface);
    if (!ifindex) return 2;
    uint32_t owned = 0;
    int rc = owned_program_id(pin_dir, &owned);
    if (rc) { fprintf(stderr, "owned XDP program pin missing\n"); return 3; }
    uint32_t drv = 0, skb = 0;
    (void)query_id(ifindex, XDP_FLAGS_DRV_MODE, &drv);
    (void)query_id(ifindex, XDP_FLAGS_SKB_MODE, &skb);
    if (drv == owned) rc = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    else if (skb == owned) rc = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    else if (drv || skb) {
        fprintf(stderr, "refusing to detach foreign XDP owner (owned=%u native=%u generic=%u)\n", owned, drv, skb);
        return 3;
    } else rc = 0;
    if (rc) { fprintf(stderr, "XDP detach failed: %s\n", strerror(-rc)); return 4; }
    printf("{\"detached\":true,\"program_id\":%u}\n", owned);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) goto usage;
    if (!strcmp(argv[1], "attach") && (argc == 5 || argc == 6))
        return attach_cmd(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : "auto");
    if (!strcmp(argv[1], "status") && argc == 4)
        return status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "detach") && argc == 4)
        return detach_cmd(argv[2], argv[3]);
usage:
    fprintf(stderr, "usage: %s attach IFACE OBJECT PIN_DIR [auto|native|generic] | status IFACE PIN_DIR | detach IFACE PIN_DIR\n", argv[0]);
    return 2;
}
