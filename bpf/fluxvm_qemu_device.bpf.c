// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Sentinel Set 7S: per-VM device-cgroup allowlist for the QEMU/VMM process.
//
// Attached (BPF_CGROUP_DEVICE) to the same fluxvm.slice/{id}.scope cgroup
// crates/fluxvm-cgroup already puts every VM's QEMU process into for
// cpu/memory/pids/io control. Complements (does not replace) the existing
// classic seccomp-bpf VMM process allowlist in
// crates/fluxvm-hypervisor/src/seccomp.rs: seccomp restricts *syscalls*,
// this restricts *which device nodes* those syscalls may target -- a
// compromised QEMU that can still call open()/mknod() should not be able to
// reach arbitrary /dev nodes on the host.
//
// Deliberately scoped to device access only, not a general host-process
// LSM: /dev/kvm, /dev/vhost-vsock and /dev/net/tun major:minor numbers are
// resolved at attach time by the userspace loader (misc chardevs get
// dynamically assigned minors, so these cannot be compile-time constants)
// and pushed into fluxvm_qemu_dev; VFIO passthrough device nodes are added
// the same way only when a VM actually has vfio_devices configured.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_QEMU_MAX_DEVICES 8

struct fluxvm_qemu_dev_rule {
    __u32 major;
    __u32 minor;
    __u32 dev_type;    // BPF_DEVCG_DEV_CHAR or BPF_DEVCG_DEV_BLOCK
    __u32 access_mask; // OR of BPF_DEVCG_ACC_{MKNOD,READ,WRITE}
};

struct fluxvm_qemu_dev_rules {
    __u32 n;
    struct fluxvm_qemu_dev_rule rules[FLUXVM_QEMU_MAX_DEVICES];
};
_Static_assert(sizeof(struct fluxvm_qemu_dev_rules) == 4 + FLUXVM_QEMU_MAX_DEVICES * 16,
               "qemu dev rules ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fluxvm_qemu_dev_rules);
} fluxvm_qemu_dev SEC(".maps");

SEC("cgroup/dev")
int fluxvm_qemu_device(struct bpf_cgroup_dev_ctx *ctx)
{
    __u32 zero = 0;
    struct fluxvm_qemu_dev_rules *cfg = bpf_map_lookup_elem(&fluxvm_qemu_dev, &zero);
    // Fail closed: an unconfigured cgroup (loader crashed between attach and
    // map population) denies all device access rather than allowing it.
    if (!cfg)
        return 0;

    __u32 dev_type = ctx->access_type & 0xFFFF;
    __u32 access = ctx->access_type >> 16;

    #pragma unroll
    for (__u32 i = 0; i < FLUXVM_QEMU_MAX_DEVICES; i++) {
        if (i >= cfg->n)
            break;
        struct fluxvm_qemu_dev_rule *r = &cfg->rules[i];
        if (r->dev_type == dev_type && r->major == ctx->major && r->minor == ctx->minor
            && (access & r->access_mask) == access)
            return 1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
