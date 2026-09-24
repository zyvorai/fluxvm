// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Seccomp filter for a QEMU or Cloud Hypervisor child. Installed in the
//! child before exec, so it never attaches to `fluxctl serve`. The filter
//! is an allowlist. The default action is `SECCOMP_RET_LOG` (the syscall
//! still runs, and the kernel logs it). `FLUXVM_VMM_SECCOMP=kill` makes a
//! syscall outside the allowlist fatal. `FLUXVM_VMM_SECCOMP=off` skips the
//! filter. A foreign syscall ABI (for example i386 via `int 0x80`) is
//! killed even in log mode, because the allowlist numbers are native.

use crate::policy::{VmmSeccompMode, vmm_seccomp_mode_from};

pub fn mode_from_env() -> VmmSeccompMode {
    vmm_seccomp_mode_from(std::env::var("FLUXVM_VMM_SECCOMP").ok().as_deref())
}

/// Install the filter. Safe to call from `pre_exec` (no allocation).
/// Log mode ignores a kernel that rejects `SECCOMP_RET_LOG`. Kill mode
/// surfaces that failure so the VMM does not start unconfined.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn install(mode: VmmSeccompMode) -> std::io::Result<()> {
    if mode == VmmSeccompMode::Off {
        return Ok(());
    }
    let kill = mode == VmmSeccompMode::Kill;
    // SAFETY: the filter is a stack array, and prctl does not run other
    // code that allocates. Called only after fork, before exec.
    unsafe { install_filter(kill) }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn install(_mode: VmmSeccompMode) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn allow_syscalls() -> &'static [i64] {
    &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
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
        libc::SYS_pipe2,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
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
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
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
        libc::SYS_fchdir,
        libc::SYS_umask,
        libc::SYS_gettimeofday,
        libc::SYS_getrlimit,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getppid,
        libc::SYS_setsid,
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_sigaltstack,
        libc::SYS_prctl,
        libc::SYS_setrlimit,
        libc::SYS_sync,
        libc::SYS_gettid,
        libc::SYS_futex,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_yield,
        libc::SYS_set_tid_address,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_tgkill,
        libc::SYS_openat,
        libc::SYS_mkdirat,
        libc::SYS_newfstatat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_faccessat,
        libc::SYS_readlinkat,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_prlimit64,
        libc::SYS_getrandom,
        libc::SYS_memfd_create,
        libc::SYS_statx,
        libc::SYS_clone3,
        libc::SYS_close_range,
        libc::SYS_rseq,
        libc::SYS_eventfd2,
        libc::SYS_fallocate,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_signalfd4,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        libc::SYS_splice,
        libc::SYS_copy_file_range,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_getdents64,
        libc::SYS_waitid,
        libc::SYS_seccomp,
        libc::SYS_userfaultfd,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_epoll_wait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rename,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mkdir,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rmdir,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_unlink,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_readlink,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fchmod,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown,
    ]
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
unsafe fn install_filter(kill: bool) -> std::io::Result<()> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    let allowed = allow_syscalls();
    let default_action = if kill {
        SECCOMP_RET_KILL_PROCESS
    } else {
        SECCOMP_RET_LOG
    };
    // arch check (3) + load nr (1) + two instructions per syscall + default.
    let mut filter = [libc::sock_filter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    }; 512];
    let mut n = 0usize;
    let mut push = |insn: libc::sock_filter| {
        filter[n] = insn;
        n += 1;
    };
    push(libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 4, // seccomp_data.arch
    });
    push(libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1, // matching arch skips the kill
        jf: 0,
        k: AUDIT_ARCH,
    });
    push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    push(libc::sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: 0, // seccomp_data.nr
    });
    for nr in allowed {
        push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: *nr as u32,
        });
        push(libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
    }
    push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: default_action,
    });
    let prog = libc::sock_fprog {
        len: n as u16,
        filter: filter.as_mut_ptr(),
    };
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = libc::prctl(
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_FILTER,
        &prog as *const libc::sock_fprog as libc::c_ulong,
        0,
        0,
    );
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if !kill && err.raw_os_error() == Some(libc::EINVAL) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}
