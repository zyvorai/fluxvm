// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;

/// Apply process hardening for the FluxVM hypervisor control plane.
///
/// On Linux: `PR_SET_NO_NEW_PRIVS`, disable core dumps, then install a
/// seccomp-bpf allowlist via `seccompiler` (KillProcess on mismatch).
pub fn apply_minimal() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "PR_SET_NO_NEW_PRIVS failed"
                );
            }
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        apply_seccomp_filter().context("installing seccomp-bpf filter")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_seccomp_filter() -> Result<()> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    let allowed: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_ioctl,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_access,
        libc::SYS_pipe,
        libc::SYS_select,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_madvise,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_socketpair,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_clone,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_wait4,
        libc::SYS_kill,
        libc::SYS_uname,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_rename,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_unlink,
        libc::SYS_readlink,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_chown,
        libc::SYS_umask,
        libc::SYS_gettimeofday,
        libc::SYS_getrlimit,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getppid,
        libc::SYS_setsid,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_sigaltstack,
        libc::SYS_arch_prctl,
        libc::SYS_prctl,
        libc::SYS_setrlimit,
        libc::SYS_sync,
        libc::SYS_gettid,
        libc::SYS_futex,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getaffinity,
        libc::SYS_set_tid_address,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_exit_group,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_ctl,
        libc::SYS_tgkill,
        libc::SYS_openat,
        libc::SYS_mkdirat,
        libc::SYS_newfstatat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_faccessat,
        libc::SYS_ppoll,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_epoll_create1,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_prlimit64,
        libc::SYS_setns,
        libc::SYS_getrandom,
        libc::SYS_memfd_create,
        libc::SYS_statx,
        libc::SYS_clone3,
        libc::SYS_close_range,
        libc::SYS_rseq,
        libc::SYS_epoll_pwait,
        libc::SYS_accept4,
        libc::SYS_eventfd2,
        libc::SYS_fallocate,
    ];

    let map: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        allowed.iter().map(|&nr| (nr, vec![])).collect();

    let filter = SeccompFilter::new(
        map,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| anyhow::anyhow!("building seccomp filter: {e:?}"))?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("compiling seccomp filter: {e:?}"))?;
    apply_filter(&prog).map_err(|e| anyhow::anyhow!("applying seccomp filter: {e:?}"))?;
    tracing::info!("seccomp-bpf allowlist installed");
    Ok(())
}
