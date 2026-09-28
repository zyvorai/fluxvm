// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! seccomp-bpf denylist of syscalls a confined process has no business making.
//!
//! Filters are compiled in the parent and installed in the child, last,
//! after Landlock. `PR_SET_NO_NEW_PRIVS` is set before either.

use crate::policy::SeccompMode;
use anyhow::{anyhow, Result};
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::io;

#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;

/// Syscalls denied outright.
pub fn denied_syscalls() -> Vec<(&'static str, i64)> {
    vec![
        ("ptrace", libc::SYS_ptrace),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("chroot", libc::SYS_chroot),
        ("kexec_load", libc::SYS_kexec_load),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("keyctl", libc::SYS_keyctl),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("reboot", libc::SYS_reboot),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("userfaultfd", libc::SYS_userfaultfd),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
    ]
}

/// Namespace-creating syscalls, denied unless the policy allows namespaces.
fn namespace_syscalls() -> Vec<(&'static str, i64)> {
    vec![("unshare", libc::SYS_unshare), ("setns", libc::SYS_setns)]
}

const CLONE_NEW_FLAGS: [u64; 7] = [
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

fn errno_or_kill(mode: SeccompMode) -> SeccompAction {
    match mode {
        SeccompMode::Errno => SeccompAction::Errno(libc::EPERM as u32),
        SeccompMode::Kill => SeccompAction::KillProcess,
    }
}

/// Compile the filters. Two programs are stacked: the denylist (EPERM or
/// kill), and `clone3` -> `ENOSYS` so libc falls back to `clone`, whose
/// namespace flags the first filter can inspect (clone3 takes them from
/// user memory, which seccomp cannot read).
pub fn compile(mode: SeccompMode, allow_namespaces: bool) -> Result<Vec<BpfProgram>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (_, nr) in denied_syscalls() {
        rules.insert(nr, vec![]);
    }
    let mut programs = Vec::new();
    if !allow_namespaces {
        for (_, nr) in namespace_syscalls() {
            rules.insert(nr, vec![]);
        }
        let mut clone_rules = Vec::new();
        for flag in CLONE_NEW_FLAGS {
            let cond = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(|e| anyhow!("building clone flag condition: {e:?}"))?;
            clone_rules.push(
                SeccompRule::new(vec![cond]).map_err(|e| anyhow!("building clone rule: {e:?}"))?,
            );
        }
        rules.insert(libc::SYS_clone, clone_rules);

        let mut clone3 = BTreeMap::new();
        clone3.insert(libc::SYS_clone3, vec![]);
        let filter = SeccompFilter::new(
            clone3,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32),
            ARCH,
        )
        .map_err(|e| anyhow!("building clone3 filter: {e:?}"))?;
        programs.push(
            BpfProgram::try_from(filter).map_err(|e| anyhow!("compiling clone3 filter: {e:?}"))?,
        );
    }
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, errno_or_kill(mode), ARCH)
        .map_err(|e| anyhow!("building seccomp denylist: {e:?}"))?;
    programs.push(
        BpfProgram::try_from(filter).map_err(|e| anyhow!("compiling seccomp denylist: {e:?}"))?,
    );
    Ok(programs)
}

/// Install the compiled filters on the calling thread. Also sets
/// `PR_SET_NO_NEW_PRIVS` (idempotent).
pub fn apply(programs: &[BpfProgram]) -> io::Result<()> {
    for p in programs {
        apply_filter(p).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
    }
    Ok(())
}

/// Whether the kernel supports seccomp filters at all.
pub fn available() -> bool {
    unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_covers_the_dangerous_calls() {
        let names: Vec<_> = denied_syscalls().into_iter().map(|(n, _)| n).collect();
        for want in [
            "ptrace",
            "mount",
            "pivot_root",
            "chroot",
            "kexec_load",
            "finit_module",
            "bpf",
            "perf_event_open",
            "keyctl",
            "reboot",
            "open_by_handle_at",
            "userfaultfd",
            "process_vm_readv",
        ] {
            assert!(names.contains(&want), "missing {want}");
        }
    }

    #[test]
    fn filters_compile_in_both_modes() {
        assert_eq!(compile(SeccompMode::Errno, false).unwrap().len(), 2);
        assert_eq!(compile(SeccompMode::Kill, false).unwrap().len(), 2);
        // Allowing namespaces drops the clone3/clone/unshare handling.
        assert_eq!(compile(SeccompMode::Errno, true).unwrap().len(), 1);
    }
}
