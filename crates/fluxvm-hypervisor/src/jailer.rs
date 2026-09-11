// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style jailer: drop privileges / isolate before KVM_RUN.
//! Enabled when `FLUXVM_JAILER=1` or `BootConfig`/config `jailer=true`.

use crate::error::{FluxError, Result};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct JailerConfig {
    pub enabled: bool,
    pub chroot: Option<std::path::PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl JailerConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("FLUXVM_JAILER").ok().as_deref() == Some("1");
        Self {
            enabled,
            chroot: std::env::var_os("FLUXVM_JAILER_CHROOT").map(Into::into),
            uid: std::env::var("FLUXVM_JAILER_UID")
                .ok()
                .and_then(|s| s.parse().ok()),
            gid: std::env::var("FLUXVM_JAILER_GID")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }
}

/// Apply jailer steps. Safe no-op when disabled. Must run after opening
/// `/dev/kvm` / guest fds that need to stay alive across chroot.
pub fn apply(cfg: &JailerConfig) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // New mount / UTS / IPC / PID namespaces (best-effort).
        unsafe {
            let flags = libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
            if libc::unshare(flags) != 0 {
                eprintln!(
                    "[jailer] unshare partial errno={}",
                    std::io::Error::last_os_error()
                );
            }
        }
        if let Some(root) = &cfg.chroot {
            chroot_into(root)?;
        }
        if let Some(gid) = cfg.gid {
            if unsafe { libc::setgid(gid) } != 0 {
                return Err(FluxError::Hypervisor(format!(
                    "jailer setgid({gid}): {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        if let Some(uid) = cfg.uid {
            if unsafe { libc::setuid(uid) } != 0 {
                return Err(FluxError::Hypervisor(format!(
                    "jailer setuid({uid}): {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        // Enter a dedicated cgroup when FLUXVM_JAILER_CGROUP is set.
        if let Ok(cg) = std::env::var("FLUXVM_JAILER_CGROUP") {
            enter_cgroup(&cg)?;
        }
        eprintln!("[jailer] applied");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn chroot_into(root: &Path) -> Result<()> {
    use std::ffi::CString;
    let c = CString::new(root.as_os_str().as_encoded_bytes()).map_err(|_| {
        FluxError::Hypervisor("jailer chroot path contains NUL".into())
    })?;
    if unsafe { libc::chroot(c.as_ptr()) } != 0 {
        return Err(FluxError::Hypervisor(format!(
            "chroot {}: {}",
            root.display(),
            std::io::Error::last_os_error()
        )));
    }
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(FluxError::Hypervisor(format!(
            "chdir / after chroot: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_cgroup(path: &str) -> Result<()> {
    let procs = format!("{path}/cgroup.procs");
    let pid = std::process::id().to_string();
    std::fs::write(&procs, pid).map_err(|e| {
        FluxError::Hypervisor(format!("jailer cgroup {procs}: {e}"))
    })?;
    Ok(())
}
