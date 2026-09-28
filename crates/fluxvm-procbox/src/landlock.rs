// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Landlock: filesystem, TCP port and IPC-scope confinement via raw syscalls.
//!
//! [`plan`] is portable and pure: given a policy and a kernel ABI it decides
//! what can be enforced and, in strict mode, refuses to continue if the kernel
//! cannot enforce something the policy asks for. The Linux-only half builds
//! the ruleset in the parent and applies it in the child.

use crate::policy::{Enforcement, Policy, TcpRule};
use anyhow::{bail, Result};

pub const ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2.
pub const ACCESS_FS_REFER: u64 = 1 << 13;
/// ABI 3.
pub const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
/// ABI 5.
pub const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// ABI 4.
pub const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// ABI 6.
pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const SCOPE_SIGNAL: u64 = 1 << 1;

const READ_RIGHTS: u64 = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
const WRITE_ONLY_RIGHTS: u64 = ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;
/// Rights that may be attached to a non-directory path.
const FILE_RIGHTS: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV;

/// Minimum ABI for strict filesystem confinement (truncate + refer control).
pub const STRICT_MIN_FS_ABI: u32 = 3;

/// All filesystem rights a given ABI can handle.
pub fn fs_rights_for_abi(abi: u32) -> u64 {
    if abi == 0 {
        return 0;
    }
    let mut r = (1u64 << 13) - 1;
    if abi >= 2 {
        r |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        r |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        r |= ACCESS_FS_IOCTL_DEV;
    }
    r
}

/// Rights granted for a `-r` path.
pub fn read_rights(handled: u64) -> u64 {
    READ_RIGHTS & handled
}

/// Rights granted for a `-w` path (write implies read).
pub fn write_rights(handled: u64) -> u64 {
    (READ_RIGHTS | WRITE_ONLY_RIGHTS) & handled
}

pub fn file_rights(rights: u64) -> u64 {
    rights & FILE_RIGHTS
}

/// What will be handled (denied unless granted), decided from the policy and
/// the kernel.
#[derive(Debug, Clone)]
pub struct Plan {
    pub effective_abi: u32,
    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
    pub enforcement: Enforcement,
}

/// Decide what can be enforced. Strict mode (the default) fails closed when
/// the kernel cannot enforce something the policy asks for; `best_effort`
/// records the gaps in `enforcement.not_enforced` instead.
pub fn plan(policy: &Policy, kernel_abi: u32) -> Result<Plan> {
    let eff = policy.max_abi.map_or(kernel_abi, |m| m.min(kernel_abi));
    let mut enf = Enforcement {
        landlock_abi: eff,
        ..Enforcement::default()
    };
    let mut fatal: Vec<String> = Vec::new();
    let mut info: Vec<String> = Vec::new();

    let mut handled_fs = 0;
    if eff == 0 {
        fatal.push("filesystem confinement (Landlock is unavailable)".into());
    } else {
        handled_fs = fs_rights_for_abi(eff);
        enf.filesystem = true;
        if eff < STRICT_MIN_FS_ABI {
            fatal.push(format!(
                "filesystem truncate/refer control (needs Landlock ABI >= {STRICT_MIN_FS_ABI}, have {eff})"
            ));
        }
        if eff < 5 {
            info.push(format!(
                "filesystem device ioctl control (needs Landlock ABI >= 5, have {eff})"
            ));
        }
    }

    let mut handled_net = 0;
    let connect = policy.tcp_connect != TcpRule::Any;
    let bind = policy.tcp_bind != TcpRule::Any;
    if connect || bind {
        if eff >= 4 {
            if connect {
                handled_net |= ACCESS_NET_CONNECT_TCP;
                enf.tcp_connect = true;
            }
            if bind {
                handled_net |= ACCESS_NET_BIND_TCP;
                enf.tcp_bind = true;
            }
        } else {
            if connect {
                fatal.push(format!(
                    "TCP connect port rules (needs Landlock ABI >= 4, have {eff})"
                ));
            }
            if bind {
                fatal.push(format!(
                    "TCP bind port rules (needs Landlock ABI >= 4, have {eff})"
                ));
            }
        }
    }

    let mut scoped = 0;
    if policy.scope_ipc {
        if eff >= 6 {
            scoped = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL;
            enf.scope_abstract_unix = true;
            enf.scope_signal = true;
        } else {
            fatal.push(format!(
                "abstract-unix-socket and signal scoping (needs Landlock ABI >= 6, have {eff})"
            ));
        }
    }

    if !fatal.is_empty() && !policy.best_effort {
        bail!(
            "strict mode: this host cannot enforce the requested policy: {}; \
             relax the policy, use a newer kernel, or pass --best-effort to run with the gaps reported",
            fatal.join("; ")
        );
    }
    enf.not_enforced.extend(fatal);
    enf.not_enforced.extend(info);

    Ok(Plan {
        effective_abi: eff,
        handled_fs,
        handled_net,
        scoped,
        enforcement: enf,
    })
}

#[cfg(target_os = "linux")]
pub use sys::{add_path_raw, kernel_abi, prepare, restrict_self, Prepared};

/// Non-Linux hosts have no Landlock.
#[cfg(not(target_os = "linux"))]
pub fn kernel_abi() -> u32 {
    0
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use anyhow::Context;
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const SYS_CREATE_RULESET: libc::c_long = 444;
    const SYS_ADD_RULE: libc::c_long = 445;
    const SYS_RESTRICT_SELF: libc::c_long = 446;
    const CREATE_RULESET_VERSION: u32 = 1 << 0;
    const RULE_PATH_BENEATH: u32 = 1;
    const RULE_NET_PORT: u32 = 2;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    struct NetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    /// Landlock ABI of the running kernel, or 0 if unavailable or disabled.
    pub fn kernel_abi() -> u32 {
        let v = unsafe {
            libc::syscall(
                SYS_CREATE_RULESET,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        if v < 0 {
            0
        } else {
            v as u32
        }
    }

    /// A ruleset built in the parent. `restrict_self` is called in the child.
    pub struct Prepared {
        fd: OwnedFd,
    }

    impl Prepared {
        pub fn raw_fd(&self) -> i32 {
            self.fd.as_raw_fd()
        }
    }

    /// Build the ruleset for `plan`. Returns the ruleset (if anything is
    /// handled) and notes about rules skipped in best-effort mode.
    pub fn prepare(plan: &Plan, policy: &Policy) -> Result<(Option<Prepared>, Vec<String>)> {
        if plan.handled_fs == 0 && plan.handled_net == 0 && plan.scoped == 0 {
            return Ok((None, Vec::new()));
        }
        let attr = RulesetAttr {
            handled_access_fs: plan.handled_fs,
            handled_access_net: plan.handled_net,
            scoped: plan.scoped,
        };
        let raw = unsafe {
            libc::syscall(
                SYS_CREATE_RULESET,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("landlock_create_ruleset");
        }
        // SAFETY: a fresh fd we own; created O_CLOEXEC by the kernel.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let mut notes = Vec::new();

        if plan.handled_fs != 0 {
            for p in &policy.read {
                add_path(&fd, p, read_rights(plan.handled_fs), policy, &mut notes)?;
            }
            for p in &policy.write {
                add_path(&fd, p, write_rights(plan.handled_fs), policy, &mut notes)?;
            }
        }
        if plan.handled_net & ACCESS_NET_CONNECT_TCP != 0 {
            if let TcpRule::Ports(ports) = &policy.tcp_connect {
                for &port in ports {
                    add_port(&fd, port, ACCESS_NET_CONNECT_TCP)?;
                }
            }
        }
        if plan.handled_net & ACCESS_NET_BIND_TCP != 0 {
            if let TcpRule::Ports(ports) = &policy.tcp_bind {
                for &port in ports {
                    add_port(&fd, port, ACCESS_NET_BIND_TCP)?;
                }
            }
        }
        Ok((Some(Prepared { fd }), notes))
    }

    fn add_path(
        ruleset: &OwnedFd,
        path: &Path,
        rights: u64,
        policy: &Policy,
        notes: &mut Vec<String>,
    ) -> Result<()> {
        let c = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("path {} contains a NUL byte", path.display()))?;
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            if policy.best_effort {
                notes.push(format!(
                    "path {} skipped (not enforced as an allow rule): {err}",
                    path.display()
                ));
                return Ok(());
            }
            return Err(err).with_context(|| format!("cannot open {} for a rule", path.display()));
        }
        // SAFETY: fresh fd we own.
        let pfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(pfd.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error()).context("fstat rule path");
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let allowed = if is_dir { rights } else { file_rights(rights) };
        let rule = PathBeneathAttr {
            allowed_access: allowed,
            parent_fd: pfd.as_raw_fd(),
        };
        let rc = unsafe {
            libc::syscall(
                SYS_ADD_RULE,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("landlock_add_rule for {}", path.display()));
        }
        Ok(())
    }

    fn add_port(ruleset: &OwnedFd, port: u16, access: u64) -> Result<()> {
        let rule = NetPortAttr {
            allowed_access: access,
            port: port as u64,
        };
        let rc = unsafe {
            libc::syscall(
                SYS_ADD_RULE,
                ruleset.as_raw_fd(),
                RULE_NET_PORT,
                &rule as *const NetPortAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("landlock_add_rule for TCP port {port}"));
        }
        Ok(())
    }

    /// Add a path-beneath rule for a directory to an existing ruleset fd.
    /// Async-signal-safe (open, add_rule, close), so it can run in the child
    /// after the private root exists.
    pub fn add_path_raw(ruleset_fd: i32, path: &std::ffi::CStr, rights: u64) -> io::Result<()> {
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let rule = PathBeneathAttr {
            allowed_access: rights,
            parent_fd: raw,
        };
        let rc = unsafe {
            libc::syscall(
                SYS_ADD_RULE,
                ruleset_fd,
                RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        let err = io::Error::last_os_error();
        unsafe { libc::close(raw) };
        if rc != 0 {
            return Err(err);
        }
        Ok(())
    }

    /// Enforce the ruleset on the calling thread (and its future children).
    /// Requires `PR_SET_NO_NEW_PRIVS`. Async-signal-safe.
    pub fn restrict_self(fd: i32) -> io::Result<()> {
        let rc = unsafe { libc::syscall(SYS_RESTRICT_SELF, fd, 0u32) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TcpRule;

    fn strict() -> Policy {
        Policy::default()
    }

    #[test]
    fn full_abi_enforces_everything_requested() {
        let mut p = strict();
        p.tcp_connect = TcpRule::Ports(vec![443]);
        p.tcp_bind = TcpRule::Deny;
        let plan = plan(&p, 7).unwrap();
        assert!(plan.enforcement.filesystem);
        assert!(plan.enforcement.tcp_connect && plan.enforcement.tcp_bind);
        assert!(plan.enforcement.scope_abstract_unix && plan.enforcement.scope_signal);
        assert!(plan.enforcement.not_enforced.is_empty());
        assert_ne!(plan.handled_fs & ACCESS_FS_IOCTL_DEV, 0);
    }

    #[test]
    fn strict_fails_closed_when_scoping_is_unavailable() {
        let e = plan(&strict(), 5).unwrap_err().to_string();
        assert!(e.contains("scoping"), "{e}");
        assert!(e.contains("--best-effort"), "{e}");
    }

    #[test]
    fn strict_fails_closed_when_net_rules_are_unavailable() {
        let mut p = strict();
        p.scope_ipc = false;
        p.tcp_connect = TcpRule::Ports(vec![443]);
        let e = plan(&p, 3).unwrap_err().to_string();
        assert!(e.contains("TCP connect"), "{e}");
    }

    #[test]
    fn strict_fails_closed_without_landlock() {
        let mut p = strict();
        p.scope_ipc = false;
        let e = plan(&p, 0).unwrap_err().to_string();
        assert!(e.contains("Landlock is unavailable"), "{e}");
    }

    #[test]
    fn best_effort_reports_exactly_what_is_missing() {
        let mut p = strict();
        p.best_effort = true;
        p.tcp_connect = TcpRule::Deny;
        let plan = plan(&p, 3).unwrap();
        let gaps = plan.enforcement.not_enforced.join(" | ");
        assert!(gaps.contains("TCP connect"), "{gaps}");
        assert!(gaps.contains("scoping"), "{gaps}");
        assert!(gaps.contains("ioctl"), "{gaps}");
        assert!(plan.enforcement.filesystem);
        assert!(!plan.enforcement.tcp_connect);
        assert_eq!(plan.handled_net, 0);
        assert_eq!(plan.scoped, 0);
    }

    #[test]
    fn unrestricted_net_is_not_reported_as_a_gap() {
        let mut p = strict();
        p.scope_ipc = false;
        let plan = plan(&p, 3).unwrap();
        assert!(plan
            .enforcement
            .not_enforced
            .iter()
            .all(|g| g.contains("ioctl")));
        assert_eq!(plan.handled_net, 0);
    }

    #[test]
    fn max_abi_caps_the_kernel_abi() {
        let mut p = strict();
        p.max_abi = Some(3);
        p.tcp_connect = TcpRule::Deny;
        assert!(plan(&p, 7).is_err());
        p.best_effort = true;
        assert_eq!(plan(&p, 7).unwrap().effective_abi, 3);
    }

    #[test]
    fn rights_are_masked_to_the_abi_and_to_files() {
        let v1 = fs_rights_for_abi(1);
        assert_eq!(
            v1 & (ACCESS_FS_REFER | ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV),
            0
        );
        let w = write_rights(v1);
        assert_eq!(w & ACCESS_FS_TRUNCATE, 0);
        assert_ne!(w & ACCESS_FS_WRITE_FILE, 0);
        // Directory-only rights must not reach a file rule (kernel: EINVAL).
        let f = file_rights(write_rights(fs_rights_for_abi(7)));
        assert_eq!(f & ACCESS_FS_MAKE_REG, 0);
        assert_eq!(f & ACCESS_FS_READ_DIR, 0);
        assert_ne!(f & ACCESS_FS_WRITE_FILE, 0);
    }
}
