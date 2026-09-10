// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Minimal TCX/BPF-link lifecycle helper for FluxVM. The Rust control plane
// intentionally keeps libbpf out of its dependency graph and invokes this
// privileged helper only for link operations.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s probe  <iface> [ingress|egress]\n"
            "  %s attach <iface> <program-pin> <link-pin> [ingress|egress]\n"
            "  %s update <program-pin> <link-pin> [old-program-pin]\n"
            "  %s status <link-pin>\n"
            "  %s detach <link-pin>\n",
            argv0, argv0, argv0, argv0, argv0);
}

// Set 13 (schema v8): Pod-ingress-direction enforcement needs a second TCX
// link on the same interface, at BPF_TCX_EGRESS (host-side egress = traffic
// entering the VM) rather than BPF_TCX_INGRESS (the only direction this
// helper supported before -- host-side ingress = VM egress, used by every
// other FluxVM eBPF consumer). `update`/`status`/`detach` operate on an
// already-created link fd and need no direction argument; only `probe` and
// `attach` create/query against a specific hook. Omitting the argument
// keeps the pre-Set-13 ingress-only behavior unchanged for every existing
// caller.
static int parse_direction(const char *raw, enum bpf_attach_type *out)
{
    if (!raw || strcmp(raw, "ingress") == 0) {
        *out = BPF_TCX_INGRESS;
        return 0;
    }
    if (strcmp(raw, "egress") == 0) {
        *out = BPF_TCX_EGRESS;
        return 0;
    }
    return -EINVAL;
}

static int neg_errno_or(int rc)
{
    if (rc < 0)
        return rc;
    return errno ? -errno : -EIO;
}

static int mkdir_parent(const char *path)
{
    char *tmp = strdup(path);
    if (!tmp)
        return -ENOMEM;
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) {
        free(tmp);
        return 0;
    }
    *slash = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) && errno != EEXIST) {
            int err = -errno;
            free(tmp);
            return err;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0755) && errno != EEXIST) {
        int err = -errno;
        free(tmp);
        return err;
    }
    free(tmp);
    return 0;
}

static int ifindex_of(const char *iface)
{
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex)
        return errno ? -errno : -ENODEV;
    return (int)ifindex;
}

static int query_tcx(int ifindex, enum bpf_attach_type direction, __u64 *revision, __u32 *count)
{
    // A FluxVM-owned VM edge should have at most one TCX program, but keep
    // enough room to coexist with operator instrumentation. Supplying arrays
    // avoids kernel/version differences around a zero-length discovery query.
    __u32 prog_ids[64] = {};
    __u32 link_ids[64] = {};
    __u32 prog_flags[64] = {};
    __u32 link_flags[64] = {};
    struct bpf_prog_query_opts opts = {};
    opts.sz = sizeof(opts);
    opts.prog_cnt = 64;
    opts.prog_ids = prog_ids;
    opts.link_ids = link_ids;
    opts.prog_attach_flags = prog_flags;
    opts.link_attach_flags = link_flags;
    int rc = bpf_prog_query_opts(ifindex, direction, &opts);
    if (rc)
        return neg_errno_or(rc);
    if (revision)
        *revision = opts.revision;
    if (count)
        *count = opts.prog_cnt;
    return 0;
}

static int cmd_probe(const char *iface, const char *direction_arg)
{
    enum bpf_attach_type direction;
    if (parse_direction(direction_arg, &direction))
        return -EINVAL;
    int ifindex = ifindex_of(iface);
    if (ifindex < 0)
        return ifindex;
    __u64 revision = 0;
    __u32 count = 0;
    int rc = query_tcx(ifindex, direction, &revision, &count);
    if (rc)
        return rc;
    printf("{\"supported\":true,\"ifindex\":%d,\"revision\":%llu,\"program_count\":%u}\n",
           ifindex, (unsigned long long)revision, count);
    return 0;
}

static int cmd_attach(const char *iface, const char *program_pin, const char *link_pin, const char *direction_arg)
{
    enum bpf_attach_type direction;
    if (parse_direction(direction_arg, &direction))
        return -EINVAL;
    int ifindex = ifindex_of(iface);
    if (ifindex < 0)
        return ifindex;
    int prog_fd = bpf_obj_get(program_pin);
    if (prog_fd < 0)
        return -errno;

    __u64 before_revision = 0;
    __u32 before_count = 0;
    int rc = query_tcx(ifindex, direction, &before_revision, &before_count);
    if (rc) {
        close(prog_fd);
        return rc;
    }

    struct bpf_link_create_opts opts = {};
    opts.sz = sizeof(opts);
    opts.tcx.expected_revision = before_revision;
    int link_fd = bpf_link_create(prog_fd, ifindex, direction, &opts);
    if (link_fd < 0) {
        rc = neg_errno_or(link_fd);
        close(prog_fd);
        return rc;
    }

    rc = mkdir_parent(link_pin);
    if (rc)
        goto fail_link;
    if (unlink(link_pin) && errno != ENOENT) {
        rc = -errno;
        goto fail_link;
    }
    if (bpf_obj_pin(link_fd, link_pin)) {
        rc = -errno;
        goto fail_link;
    }

    struct bpf_link_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(link_fd, &info, &info_len)) {
        rc = -errno;
        unlink(link_pin);
        goto fail_link;
    }

    __u64 revision = 0;
    __u32 count = 0;
    rc = query_tcx(ifindex, direction, &revision, &count);
    if (rc) {
        unlink(link_pin);
        goto fail_link;
    }

    printf("{\"mode\":\"tcx\",\"ifindex\":%d,\"link_id\":%u,\"prog_id\":%u,\"revision\":%llu,\"program_count\":%u}\n",
           ifindex, info.id, info.prog_id, (unsigned long long)revision, count);
    close(link_fd);
    close(prog_fd);
    return 0;

fail_link:
    (void)bpf_link_detach(link_fd);
    close(link_fd);
    close(prog_fd);
    return rc;
}

static int cmd_update(const char *program_pin, const char *link_pin, const char *old_program_pin)
{
    int link_fd = bpf_obj_get(link_pin);
    if (link_fd < 0)
        return -errno;
    int prog_fd = bpf_obj_get(program_pin);
    if (prog_fd < 0) {
        int rc = -errno;
        close(link_fd);
        return rc;
    }

    struct bpf_link_update_opts opts = {};
    opts.sz = sizeof(opts);
    int old_fd = -1;
    if (old_program_pin) {
        old_fd = bpf_obj_get(old_program_pin);
        if (old_fd < 0) {
            int rc = -errno;
            close(prog_fd);
            close(link_fd);
            return rc;
        }
        opts.flags = BPF_F_REPLACE;
        opts.old_prog_fd = (__u32)old_fd;
    }

    int rc = bpf_link_update(link_fd, prog_fd, &opts);
    if (rc)
        rc = neg_errno_or(rc);
    if (old_fd >= 0)
        close(old_fd);
    close(prog_fd);
    close(link_fd);
    if (rc)
        return rc;
    printf("{\"updated\":true}\n");
    return 0;
}

static int cmd_status(const char *link_pin)
{
    int link_fd = bpf_obj_get(link_pin);
    if (link_fd < 0)
        return -errno;
    struct bpf_link_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(link_fd, &info, &info_len)) {
        int rc = -errno;
        close(link_fd);
        return rc;
    }
    printf("{\"mode\":\"tcx\",\"link_id\":%u,\"prog_id\":%u,\"link_type\":%u}\n",
           info.id, info.prog_id, info.type);
    close(link_fd);
    return 0;
}

static int cmd_detach(const char *link_pin)
{
    int link_fd = bpf_obj_get(link_pin);
    if (link_fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -errno;
    }
    int rc = bpf_link_detach(link_fd);
    if (rc && errno != ENOENT)
        rc = neg_errno_or(rc);
    else
        rc = 0;
    close(link_fd);
    if (unlink(link_pin) && errno != ENOENT && !rc)
        rc = -errno;
    if (!rc)
        printf("{\"detached\":true}\n");
    return rc;
}

int main(int argc, char **argv)
{
    int rc = -EINVAL;
    if ((argc == 3 || argc == 4) && strcmp(argv[1], "probe") == 0)
        rc = cmd_probe(argv[2], argc == 4 ? argv[3] : NULL);
    else if ((argc == 5 || argc == 6) && strcmp(argv[1], "attach") == 0)
        rc = cmd_attach(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : NULL);
    else if ((argc == 4 || argc == 5) && strcmp(argv[1], "update") == 0)
        rc = cmd_update(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    else if (argc == 3 && strcmp(argv[1], "status") == 0)
        rc = cmd_status(argv[2]);
    else if (argc == 3 && strcmp(argv[1], "detach") == 0)
        rc = cmd_detach(argv[2]);
    else {
        usage(argv[0]);
        return 2;
    }

    if (rc) {
        int e = rc < 0 ? -rc : rc;
        fprintf(stderr, "fluxvm-tcx: %s (%d)\n", strerror(e), e);
        return 1;
    }
    return 0;
}
