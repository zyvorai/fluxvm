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
    compile_with(mode, allow_namespaces, &[], &[])
}

/// Look up a syscall by name: everything in the default denylist plus a
/// curated set of calls a profile may reasonably want to deny.
pub fn syscall_by_name(name: &str) -> Option<i64> {
    if let Some((_, nr)) = denied_syscalls()
        .into_iter()
        .chain(namespace_syscalls())
        .find(|(n, _)| *n == name)
    {
        return Some(nr);
    }
    let nr = match name {
        "fchmod" => libc::SYS_fchmod,
        "fchmodat" => libc::SYS_fchmodat,
        "fchown" => libc::SYS_fchown,
        "fchownat" => libc::SYS_fchownat,
        "kill" => libc::SYS_kill,
        "tkill" => libc::SYS_tkill,
        "tgkill" => libc::SYS_tgkill,
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "accept" => libc::SYS_accept,
        "accept4" => libc::SYS_accept4,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "unlinkat" => libc::SYS_unlinkat,
        "renameat" => libc::SYS_renameat,
        "renameat2" => libc::SYS_renameat2,
        "mkdirat" => libc::SYS_mkdirat,
        "symlinkat" => libc::SYS_symlinkat,
        "linkat" => libc::SYS_linkat,
        "truncate" => libc::SYS_truncate,
        "ftruncate" => libc::SYS_ftruncate,
        "mknodat" => libc::SYS_mknodat,
        "setuid" => libc::SYS_setuid,
        "setgid" => libc::SYS_setgid,
        "setreuid" => libc::SYS_setreuid,
        "setregid" => libc::SYS_setregid,
        "setresuid" => libc::SYS_setresuid,
        "setresgid" => libc::SYS_setresgid,
        "setgroups" => libc::SYS_setgroups,
        "prctl" => libc::SYS_prctl,
        "personality" => libc::SYS_personality,
        "syslog" => libc::SYS_syslog,
        "acct" => libc::SYS_acct,
        "settimeofday" => libc::SYS_settimeofday,
        "clock_settime" => libc::SYS_clock_settime,
        "sethostname" => libc::SYS_sethostname,
        "setdomainname" => libc::SYS_setdomainname,
        "mlock" => libc::SYS_mlock,
        "mlockall" => libc::SYS_mlockall,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "memfd_create" => libc::SYS_memfd_create,
        "seccomp" => libc::SYS_seccomp,
        "capset" => libc::SYS_capset,
        "fanotify_init" => libc::SYS_fanotify_init,
        "name_to_handle_at" => libc::SYS_name_to_handle_at,
        "kcmp" => libc::SYS_kcmp,
        "quotactl" => libc::SYS_quotactl,
        "setpriority" => libc::SYS_setpriority,
        "sched_setaffinity" => libc::SYS_sched_setaffinity,
        #[cfg(target_arch = "x86_64")]
        "chmod" => libc::SYS_chmod,
        #[cfg(target_arch = "x86_64")]
        "chown" => libc::SYS_chown,
        #[cfg(target_arch = "x86_64")]
        "lchown" => libc::SYS_lchown,
        #[cfg(target_arch = "x86_64")]
        "unlink" => libc::SYS_unlink,
        #[cfg(target_arch = "x86_64")]
        "rename" => libc::SYS_rename,
        #[cfg(target_arch = "x86_64")]
        "mkdir" => libc::SYS_mkdir,
        #[cfg(target_arch = "x86_64")]
        "rmdir" => libc::SYS_rmdir,
        #[cfg(target_arch = "x86_64")]
        "symlink" => libc::SYS_symlink,
        #[cfg(target_arch = "x86_64")]
        "link" => libc::SYS_link,
        #[cfg(target_arch = "x86_64")]
        "mknod" => libc::SYS_mknod,
        #[cfg(target_arch = "x86_64")]
        "fork" => libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        "vfork" => libc::SYS_vfork,
        #[cfg(target_arch = "x86_64")]
        "iopl" => libc::SYS_iopl,
        #[cfg(target_arch = "x86_64")]
        "ioperm" => libc::SYS_ioperm,
        #[cfg(target_arch = "x86_64")]
        "modify_ldt" => libc::SYS_modify_ldt,
        _ => return None,
    };
    Some(nr)
}

/// Which `socket()` calls to refuse. seccomp cannot read a `sockaddr`, so
/// pathname Unix sockets are stopped at creation (`AF_UNIX`), not at
/// `connect`; `socketpair` is a different syscall and stays allowed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetDeny {
    /// `SOCK_DGRAM` and `SOCK_RAW` (UDP, ICMP, raw IP).
    pub dgram_raw: bool,
    /// `AF_PACKET` and `AF_NETLINK`.
    pub packet_netlink: bool,
    /// `AF_UNIX`.
    pub unix: bool,
}

impl NetDeny {
    pub fn any(&self) -> bool {
        self.dgram_raw || self.packet_netlink || self.unix
    }
}

const AF_UNIX: u64 = 1;
const AF_NETLINK: u64 = 16;
const AF_PACKET: u64 = 17;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
/// Low bits of the `type` argument; the rest are SOCK_NONBLOCK/SOCK_CLOEXEC.
const SOCK_TYPE_MASK: u64 = 0xf;

/// Argument rules for `socket()` implementing `net`.
pub fn socket_rules(net: &NetDeny) -> Result<Vec<SeccompRule>> {
    let mut rules = Vec::new();
    let mut push = |cond: SeccompCondition| -> Result<()> {
        rules.push(
            SeccompRule::new(vec![cond]).map_err(|e| anyhow!("building socket rule: {e:?}"))?,
        );
        Ok(())
    };
    let cond = |arg: u8, op: SeccompCmpOp, v: u64| -> Result<SeccompCondition> {
        SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, v)
            .map_err(|e| anyhow!("building socket condition: {e:?}"))
    };
    if net.dgram_raw {
        for t in [SOCK_DGRAM, SOCK_RAW] {
            push(cond(1, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), t)?)?;
        }
    }
    if net.packet_netlink {
        for d in [AF_PACKET, AF_NETLINK] {
            push(cond(0, SeccompCmpOp::Eq, d)?)?;
        }
    }
    if net.unix {
        push(cond(0, SeccompCmpOp::Eq, AF_UNIX)?)?;
    }
    Ok(rules)
}

/// Like [`compile`], with per-profile edits to the denylist: every name in
/// `extra_deny` is denied too, and every name in `allow` is removed from the
/// default denylist (allowing `clone3` also drops the `ENOSYS` shim).
pub fn compile_with(
    mode: SeccompMode,
    allow_namespaces: bool,
    extra_deny: &[String],
    allow: &[String],
) -> Result<Vec<BpfProgram>> {
    compile_full(
        mode,
        allow_namespaces,
        extra_deny,
        allow,
        &NetDeny::default(),
    )
}

/// [`compile_with`] plus `socket()` argument filters.
pub fn compile_full(
    mode: SeccompMode,
    allow_namespaces: bool,
    extra_deny: &[String],
    allow: &[String],
    net: &NetDeny,
) -> Result<Vec<BpfProgram>> {
    let lookup = |n: &String| {
        syscall_by_name(n)
            .ok_or_else(|| anyhow!("unknown syscall name {n:?} in the seccomp overrides"))
    };
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

        if !allow.iter().any(|n| n == "clone3") {
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
                BpfProgram::try_from(filter)
                    .map_err(|e| anyhow!("compiling clone3 filter: {e:?}"))?,
            );
        }
    }
    if net.any() {
        rules.insert(libc::SYS_socket, socket_rules(net)?);
    }
    for n in allow {
        rules.remove(&lookup(n)?);
    }
    for n in extra_deny {
        rules.insert(lookup(n)?, vec![]);
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
    fn syscall_names_resolve_and_unknown_ones_do_not() {
        assert_eq!(syscall_by_name("ptrace"), Some(libc::SYS_ptrace));
        assert_eq!(syscall_by_name("unshare"), Some(libc::SYS_unshare));
        assert_eq!(syscall_by_name("prctl"), Some(libc::SYS_prctl));
        assert_eq!(syscall_by_name("definitely_not_a_syscall"), None);
    }

    #[test]
    fn overrides_compile_and_reject_unknown_names() {
        let deny = vec!["prctl".to_string()];
        let allow = vec!["ptrace".to_string()];
        assert_eq!(
            compile_with(SeccompMode::Errno, false, &deny, &allow)
                .unwrap()
                .len(),
            2
        );
        // Allowing clone3 drops its ENOSYS shim program.
        let a = vec!["clone3".to_string()];
        assert_eq!(
            compile_with(SeccompMode::Errno, false, &[], &a)
                .unwrap()
                .len(),
            1
        );
        assert!(compile_with(SeccompMode::Errno, false, &["nope".to_string()], &[]).is_err());
    }

    #[test]
    fn socket_rules_follow_the_requested_denials() {
        assert!(socket_rules(&NetDeny::default()).unwrap().is_empty());
        let all = NetDeny {
            dgram_raw: true,
            packet_netlink: true,
            unix: true,
        };
        // DGRAM + RAW + PACKET + NETLINK + UNIX
        assert_eq!(socket_rules(&all).unwrap().len(), 5);
        let unix_only = NetDeny {
            unix: true,
            ..NetDeny::default()
        };
        assert_eq!(socket_rules(&unix_only).unwrap().len(), 1);
        assert!(all.any() && !NetDeny::default().any());
    }

    #[test]
    fn net_filters_compile_alongside_the_denylist() {
        let net = NetDeny {
            dgram_raw: true,
            packet_netlink: true,
            unix: true,
        };
        let progs = compile_full(SeccompMode::Errno, false, &[], &[], &net).unwrap();
        assert_eq!(progs.len(), 2);
        // Allowing `socket` by name removes the argument rules again.
        let allow = vec!["socket".to_string()];
        assert!(compile_full(SeccompMode::Errno, false, &[], &allow, &net).is_ok());
    }

    #[test]
    fn filters_compile_in_both_modes() {
        assert_eq!(compile(SeccompMode::Errno, false).unwrap().len(), 2);
        assert_eq!(compile(SeccompMode::Kill, false).unwrap().len(), 2);
        // Allowing namespaces drops the clone3/clone/unshare handling.
        assert_eq!(compile(SeccompMode::Errno, true).unwrap().len(), 1);
    }
}
