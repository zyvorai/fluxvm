// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM VMM Guard v1.
//
// BPF-LSM policy scoped by cgroup id. The program is attached system-wide,
// but it does nothing unless the current task belongs to a cgroup registered
// in guard_policies. Policy is intentionally VM-local: it does not own CNI,
// distributed identity, BGP, routing, or Zyvor Fabric intent.

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/mman.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef S_IFMT
#define S_IFMT   00170000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFCHR  0020000
#endif

#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif

#define FLUXVM_GUARD_AUDIT             (1u << 0)
#define FLUXVM_GUARD_DENY_EXEC         (1u << 1)
#define FLUXVM_GUARD_DENY_WX           (1u << 2)
#define FLUXVM_GUARD_RESTRICT_DEVICES  (1u << 3)
#define FLUXVM_GUARD_RESTRICT_WRITES   (1u << 4)

#define FLUXVM_GUARD_ACTION_EXEC         1u
#define FLUXVM_GUARD_ACTION_WX           2u
#define FLUXVM_GUARD_ACTION_DEVICE_OPEN  3u
#define FLUXVM_GUARD_ACTION_WRITE_OPEN   4u

#define FLUXVM_GUARD_DECISION_ALLOW      0u
#define FLUXVM_GUARD_DECISION_AUDIT      1u
#define FLUXVM_GUARD_DECISION_DENY       2u

#define FLUXVM_GUARD_KIND_CHAR           1u
#define FLUXVM_GUARD_KIND_BLOCK          2u

/* Minimal CO-RE views. Field offsets are resolved from kernel BTF. */
struct super_block {
    __u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
    unsigned short i_mode;
    __u32 i_rdev;
    unsigned long i_ino;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
    struct inode *f_inode;
    unsigned int f_mode;
} __attribute__((preserve_access_index));

struct vm_area_struct;
struct linux_binprm;

struct guard_policy {
    __u64 vm_key;
    __u32 flags;
    __u32 generation;
};
_Static_assert(sizeof(struct guard_policy) == 16, "guard policy ABI");

struct guard_device_key {
    __u64 vm_key;
    __u32 generation;
    __u32 rdev;
    __u32 kind;
    __u32 reserved;
};
_Static_assert(sizeof(struct guard_device_key) == 24, "guard device key ABI");

struct guard_file_key {
    __u64 vm_key;
    __u32 generation;
    __u32 sb_dev;
    __u64 ino;
};
_Static_assert(sizeof(struct guard_file_key) == 24, "guard file key ABI");

struct guard_stat_key {
    __u64 vm_key;
    __u32 action;
    __u32 decision;
};

struct guard_stat_value {
    __u64 events;
};

struct guard_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u64 object_id;
    __u64 aux;
    __u32 pid;
    __u32 action;
    __u32 decision;
    __u32 reserved;
};
_Static_assert(sizeof(struct guard_event) == 48, "guard event ABI");

/* cgroup id -> VM guard policy. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct guard_policy);
} guard_policies SEC(".maps");

/* Exact device allow-list, keyed by stable VM key + rdev + char/block kind. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct guard_device_key);
    __type(value, __u8);
} guard_devices SEC(".maps");

/* Exact regular-file writable allow-list, keyed by backing fs dev + inode. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct guard_file_key);
    __type(value, __u8);
} guard_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct guard_stat_key);
    __type(value, struct guard_stat_value);
} guard_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} guard_events SEC(".maps");

static __always_inline struct guard_policy *current_policy(void)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&guard_policies, &cgroup_id);
}

static __always_inline void count_event(__u64 vm_key, __u32 action, __u32 decision)
{
    struct guard_stat_key key = {
        .vm_key = vm_key,
        .action = action,
        .decision = decision,
    };
    struct guard_stat_value *v = bpf_map_lookup_elem(&guard_stats, &key);
    if (v) {
        v->events += 1;
        return;
    }
    struct guard_stat_value initial = {.events = 1};
    bpf_map_update_elem(&guard_stats, &key, &initial, BPF_NOEXIST);
}

static __always_inline void emit_event(
    const struct guard_policy *policy,
    __u32 action,
    __u32 decision,
    __u64 object_id,
    __u64 aux)
{
    count_event(policy->vm_key, action, decision);
    struct guard_event *event = bpf_ringbuf_reserve(&guard_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->vm_key = policy->vm_key;
    event->object_id = object_id;
    event->aux = aux;
    event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event->action = action;
    event->decision = decision;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int violation(
    const struct guard_policy *policy,
    __u32 action,
    __u64 object_id,
    __u64 aux)
{
    if (policy->flags & FLUXVM_GUARD_AUDIT) {
        emit_event(policy, action, FLUXVM_GUARD_DECISION_AUDIT, object_id, aux);
        return 0;
    }
    emit_event(policy, action, FLUXVM_GUARD_DECISION_DENY, object_id, aux);
    return -EPERM;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(fluxvm_guard_exec, struct linux_binprm *bprm, int ret)
{
    (void)bprm;
    if (ret)
        return ret;
    struct guard_policy *policy = current_policy();
    if (!policy || !(policy->flags & FLUXVM_GUARD_DENY_EXEC))
        return 0;
    return violation(policy, FLUXVM_GUARD_ACTION_EXEC, 0, 0);
}

SEC("lsm/file_mprotect")
int BPF_PROG(
    fluxvm_guard_mprotect,
    struct vm_area_struct *vma,
    unsigned long reqprot,
    unsigned long prot,
    int ret)
{
    (void)vma;
    (void)reqprot;
    if (ret)
        return ret;
    struct guard_policy *policy = current_policy();
    if (!policy || !(policy->flags & FLUXVM_GUARD_DENY_WX))
        return 0;
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        return violation(policy, FLUXVM_GUARD_ACTION_WX, 0, prot);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(fluxvm_guard_file_open, struct file *file, int ret)
{
    if (ret)
        return ret;
    struct guard_policy *policy = current_policy();
    if (!policy)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    unsigned int f_mode = BPF_CORE_READ(file, f_mode);
    __u32 type = mode & S_IFMT;

    if ((policy->flags & FLUXVM_GUARD_RESTRICT_DEVICES) &&
        (type == S_IFCHR || type == S_IFBLK)) {
        struct guard_device_key key = {
            .vm_key = policy->vm_key,
            .generation = policy->generation,
            .rdev = BPF_CORE_READ(inode, i_rdev),
            .kind = type == S_IFCHR ? FLUXVM_GUARD_KIND_CHAR : FLUXVM_GUARD_KIND_BLOCK,
        };
        __u8 *allowed = bpf_map_lookup_elem(&guard_devices, &key);
        if (!allowed || !*allowed) {
            __u64 object_id = ((__u64)key.kind << 32) | key.rdev;
            return violation(policy, FLUXVM_GUARD_ACTION_DEVICE_OPEN, object_id, f_mode);
        }
    }

    if ((policy->flags & FLUXVM_GUARD_RESTRICT_WRITES) &&
        type == S_IFREG && (f_mode & FMODE_WRITE)) {
        struct super_block *sb = BPF_CORE_READ(inode, i_sb);
        __u32 sb_dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;
        struct guard_file_key key = {
            .vm_key = policy->vm_key,
            .generation = policy->generation,
            .sb_dev = sb_dev,
            .ino = BPF_CORE_READ(inode, i_ino),
        };
        __u8 *allowed = bpf_map_lookup_elem(&guard_files, &key);
        if (!allowed || !*allowed) {
            __u64 object_id = ((__u64)sb_dev << 32) ^ key.ino;
            return violation(policy, FLUXVM_GUARD_ACTION_WRITE_OPEN, object_id, f_mode);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
