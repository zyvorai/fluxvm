// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Sentinel Set 9S — in-guest per-container eBPF LSM MAC.
//
// This is not a namespace replacement: LSM-BPF cannot fabricate namespace
// isolation, but it can mandatorily restrict what an unconfined process may
// touch, scoped per-container by cgroup id -- additive to the classic
// seccomp filter already applied in spawn_gated (crates/fluxvm-container-
// agent/src/main.rs), which can only filter by syscall name/argument, not
// by *which file* or *whether it's the container's own declared mount*.
//
// One loaded instance is shared across every container in this Pod VM, the
// same way bpf/fluxvm_guest_cgroup.bpf.c (Set 8S) is: the hooks are global
// LSM attachments, but every map lookup is keyed by the calling task's own
// cgroup id, so a cgroup with no fluxvm_lsmpol entry (i.e. not a FluxVM-
// managed container, or a container Set 9S wasn't attached for) is always
// allowed -- this program never touches processes outside FluxVM's own
// per-container cgroups.

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

#define FLUXVM_LSM_ENABLED             (1u << 0)
#define FLUXVM_LSM_AUDIT               (1u << 1)
#define FLUXVM_LSM_DENY_EXEC           (1u << 2)
#define FLUXVM_LSM_DENY_WX             (1u << 3)
#define FLUXVM_LSM_RESTRICT_DEVICES    (1u << 4)
#define FLUXVM_LSM_RESTRICT_WRITES     (1u << 5)

#define FLUXVM_LSM_ACTION_EXEC         1u
#define FLUXVM_LSM_ACTION_WX           2u
#define FLUXVM_LSM_ACTION_DEVICE_OPEN  3u
#define FLUXVM_LSM_ACTION_WRITE_OPEN   4u

#define FLUXVM_LSM_DECISION_ALLOW      0u
#define FLUXVM_LSM_DECISION_AUDIT      1u
#define FLUXVM_LSM_DECISION_DENY       2u

#define FLUXVM_LSM_KIND_CHAR           1u
#define FLUXVM_LSM_KIND_BLOCK          2u

// Bounded per-container write-prefix allowlist. 8 slots is enough for the
// OCI mounts a Pod container typically declares (a handful of PVC/emptyDir
// destinations); a container needing more can disable RESTRICT_WRITES for
// itself rather than force every hook here into unbounded map iteration.
#define FLUXVM_LSM_MAX_PREFIXES        8
#define FLUXVM_LSM_PREFIX_LEN          64
#define FLUXVM_LSM_PATH_LEN            192

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

struct dentry;
struct vfsmount;

/* libbpf's bpf_helper_defs.h only forward-declares `struct path` (as the
 * opaque first argument type for `bpf_d_path()`); a struct member of
 * incomplete type is illegal in C, so `struct file` embedding it by value
 * needs this CO-RE view to have a known layout. Nothing here reads either
 * field directly -- `&file->f_path` is only ever passed opaquely into
 * `bpf_d_path()`. */
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct inode *f_inode;
    unsigned int f_mode;
    struct path f_path;
} __attribute__((preserve_access_index));

struct vm_area_struct;
struct linux_binprm;

struct fluxvm_lsm_policy {
    __u32 flags;
    __u32 generation;
};
_Static_assert(sizeof(struct fluxvm_lsm_policy) == 8, "guest lsm policy ABI");

struct fluxvm_lsm_device_key {
    __u64 cgroup_id;
    __u32 rdev;
    __u32 kind;
};

struct fluxvm_lsm_prefix_key {
    __u64 cgroup_id;
    __u32 slot;
    // Explicit trailing padding, not implicit compiler padding: a BPF map
    // key's bytes are compared exactly, and implicit padding is only
    // zeroed by convention, not guaranteed identically on both the kernel
    // program's stack-initialized key and userspace's struct -- see
    // Cid4Key's `reserved` field (Set 8S) for the same reasoning.
    __u32 reserved;
};

struct fluxvm_lsm_prefix_value {
    __u32 len;
    __u8 bytes[FLUXVM_LSM_PREFIX_LEN];
};

/* Per-container (cgroup id) policy flags. Absent = not a FluxVM-managed
 * container's cgroup, or Set 9S not attached for it -- always allow. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct fluxvm_lsm_policy);
} fluxvm_lsmpol SEC(".maps");

/* Exact device allow-list, keyed by cgroup id + rdev + char/block kind. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct fluxvm_lsm_device_key);
    __type(value, __u8);
} fluxvm_lsmdev SEC(".maps");

/* Bounded write-path prefix allow-list, keyed by cgroup id + slot. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct fluxvm_lsm_prefix_key);
    __type(value, struct fluxvm_lsm_prefix_value);
} fluxvm_lsmwrite SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} fluxvm_lsmevents SEC(".maps");

struct fluxvm_lsm_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 object_id;
    __u32 pid;
    __u32 action;
    __u32 decision;
    __u32 reserved;
};

static __always_inline struct fluxvm_lsm_policy *current_policy(__u64 *cgroup_id_out)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id_out)
        *cgroup_id_out = cgroup_id;
    return bpf_map_lookup_elem(&fluxvm_lsmpol, &cgroup_id);
}

static __always_inline void emit_event(
    __u64 cgroup_id,
    __u32 action,
    __u32 decision,
    __u64 object_id)
{
    struct fluxvm_lsm_event *event = bpf_ringbuf_reserve(&fluxvm_lsmevents, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->object_id = object_id;
    event->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    event->action = action;
    event->decision = decision;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int violation(
    __u64 cgroup_id,
    const struct fluxvm_lsm_policy *policy,
    __u32 action,
    __u64 object_id)
{
    if (policy->flags & FLUXVM_LSM_AUDIT) {
        emit_event(cgroup_id, action, FLUXVM_LSM_DECISION_AUDIT, object_id);
        return 0;
    }
    emit_event(cgroup_id, action, FLUXVM_LSM_DECISION_DENY, object_id);
    return -EPERM;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(fluxvm_lsm_exec, struct linux_binprm *bprm, int ret)
{
    (void)bprm;
    if (ret)
        return ret;
    __u64 cgroup_id;
    struct fluxvm_lsm_policy *policy = current_policy(&cgroup_id);
    if (!policy || !(policy->flags & FLUXVM_LSM_DENY_EXEC))
        return 0;
    return violation(cgroup_id, policy, FLUXVM_LSM_ACTION_EXEC, 0);
}

SEC("lsm/file_mprotect")
int BPF_PROG(
    fluxvm_lsm_mprotect,
    struct vm_area_struct *vma,
    unsigned long reqprot,
    unsigned long prot,
    int ret)
{
    (void)vma;
    (void)reqprot;
    if (ret)
        return ret;
    __u64 cgroup_id;
    struct fluxvm_lsm_policy *policy = current_policy(&cgroup_id);
    if (!policy || !(policy->flags & FLUXVM_LSM_DENY_WX))
        return 0;
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
        return violation(cgroup_id, policy, FLUXVM_LSM_ACTION_WX, prot);
    return 0;
}

/* Returns 1 if `path[0..plen]` is a byte-exact match against the first
 * `plen` bytes of `prefix`, 0 otherwise. Both lengths are bounded by the
 * compile-time constant FLUXVM_LSM_PREFIX_LEN. Must stay `#pragma unroll`:
 * a non-unrolled version of this loop compiles to a variable-offset stack
 * read (`path[i]` with a runtime-ranged `i`) that the verifier rejects as
 * "invalid unbounded variable-offset read from stack" even though `i` is
 * provably bounded by the loop condition -- a fully unrolled loop turns
 * every access into a compile-time-constant offset instead, which the
 * verifier always accepts. FLUXVM_LSM_PREFIX_LEN is kept small (64) instead
 * of the OCI-spec-legal maximum specifically to bound the code size of this
 * loop nested inside write_path_allowed's own unrolled per-slot loop. No
 * `break`/early `return` inside it either -- clang's unroll pass rejects
 * loops with non-linear exits under -Werror (see bpf/fluxvm_tcp_intel.bpf.c's
 * bucket_for() for the same fix), so this still accumulates a flag. */
static __always_inline int prefix_matches(
    const char *path, __u32 path_len,
    const __u8 *prefix, __u32 prefix_len)
{
    // The upper bound must be the compile-time constant FLUXVM_LSM_PREFIX_LEN,
    // not just `prefix_len > path_len`: `prefix_len` comes from a map value
    // (untrusted from the verifier's point of view even though this program
    // is the only writer), and the boundary check below indexes `path[]` at
    // `prefix_len` -- without this the verifier cannot prove that index stays
    // inside `path`'s FLUXVM_LSM_PATH_LEN-sized stack buffer.
    if (prefix_len == 0 || prefix_len > path_len || prefix_len >= FLUXVM_LSM_PREFIX_LEN)
        return 0;
    int mismatch = 0;
    #pragma unroll
    for (__u32 i = 0; i < FLUXVM_LSM_PREFIX_LEN; i++) {
        if (i < prefix_len && (__u8)path[i] != prefix[i])
            mismatch = 1;
    }
    if (mismatch)
        return 0;
    // A prefix must land exactly on a path component boundary: "/data"
    // must not match "/database". The full path is either exactly the
    // prefix or continues with '/'.
    if (prefix_len == path_len)
        return 1;
    return path[prefix_len] == '/';
}

static __always_inline int write_path_allowed(__u64 cgroup_id, const char *path, __u32 path_len)
{
    int allowed = 0;
    #pragma unroll
    for (__u32 slot = 0; slot < FLUXVM_LSM_MAX_PREFIXES; slot++) {
        struct fluxvm_lsm_prefix_key key = {.cgroup_id = cgroup_id, .slot = slot};
        struct fluxvm_lsm_prefix_value *value = bpf_map_lookup_elem(&fluxvm_lsmwrite, &key);
        if (value && prefix_matches(path, path_len, value->bytes, value->len))
            allowed = 1;
    }
    return allowed;
}

SEC("lsm/file_open")
int BPF_PROG(fluxvm_lsm_file_open, struct file *file, int ret)
{
    if (ret)
        return ret;
    __u64 cgroup_id;
    struct fluxvm_lsm_policy *policy = current_policy(&cgroup_id);
    if (!policy)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    unsigned int f_mode = BPF_CORE_READ(file, f_mode);
    __u32 type = mode & S_IFMT;

    if ((policy->flags & FLUXVM_LSM_RESTRICT_DEVICES) &&
        (type == S_IFCHR || type == S_IFBLK)) {
        struct fluxvm_lsm_device_key key = {
            .cgroup_id = cgroup_id,
            .rdev = BPF_CORE_READ(inode, i_rdev),
            .kind = type == S_IFCHR ? FLUXVM_LSM_KIND_CHAR : FLUXVM_LSM_KIND_BLOCK,
        };
        __u8 *allowed = bpf_map_lookup_elem(&fluxvm_lsmdev, &key);
        if (!allowed || !*allowed) {
            __u64 object_id = ((__u64)key.kind << 32) | key.rdev;
            return violation(cgroup_id, policy, FLUXVM_LSM_ACTION_DEVICE_OPEN, object_id);
        }
    }

    if ((policy->flags & FLUXVM_LSM_RESTRICT_WRITES) &&
        type == S_IFREG && (f_mode & FMODE_WRITE)) {
        char path[FLUXVM_LSM_PATH_LEN];
        // bpf_d_path() returns the strictly positive string length
        // *including* the trailing NUL on success -- the actual string
        // length is one less.
        long path_len = bpf_d_path(&file->f_path, path, sizeof(path));
        if (path_len <= 0)
            return violation(cgroup_id, policy, FLUXVM_LSM_ACTION_WRITE_OPEN, 0);
        __u32 str_len = (__u32)path_len - 1;
        __u32 len = str_len >= FLUXVM_LSM_PATH_LEN ? FLUXVM_LSM_PATH_LEN - 1 : str_len;
        if (!write_path_allowed(cgroup_id, path, len)) {
            __u64 object_id = BPF_CORE_READ(inode, i_ino);
            return violation(cgroup_id, policy, FLUXVM_LSM_ACTION_WRITE_OPEN, object_id);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
