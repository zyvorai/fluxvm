// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! H4 / P3: virtio-fs (vhost-user-fs) attach for the in-tree KVM engine.
//!
//! Cloud Hypervisor SoT: spawn `virtiofsd`, then attach the Unix socket as a
//! virtio-mmio virtio-fs device. Full FUSE queue servicing is delegated to
//! virtiofsd once the guest programs the rings; this module owns spawn,
//! socket readiness, and the guest-visible device tag/config.

use crate::error::{FluxError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Virtio device id for virtio-fs (virtio spec).
pub const VIRTIO_ID_FS: u32 = 26;
/// Config-space tag length (virtio_fs_config.tag).
pub const FS_TAG_LEN: usize = 36;

#[derive(Debug, Clone)]
pub struct VirtioFsConfig {
    pub tag: String,
    /// Existing vhost-user socket (virtiofsd already running).
    pub socket: PathBuf,
    /// When set, `attach` spawns virtiofsd for this host directory first.
    pub host_path: Option<PathBuf>,
    /// Binary name/path (default `virtiofsd`).
    pub virtiofsd_binary: String,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        Self {
            tag: "fs0".into(),
            socket: PathBuf::from("/run/fluxvm/virtiofs-0.sock"),
            host_path: None,
            virtiofsd_binary: "virtiofsd".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VirtioFsAttachment {
    pub tag: String,
    pub socket: PathBuf,
    pub pid: Option<u32>,
}

impl Drop for VirtioFsAttachment {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

/// Attach virtio-fs: optionally spawn virtiofsd, wait for the socket, validate tag.
pub fn attach(cfg: &VirtioFsConfig) -> Result<VirtioFsAttachment> {
    validate_tag(&cfg.tag)?;
    let mut pid = None;
    if let Some(host) = &cfg.host_path {
        if !host.is_dir() {
            return Err(FluxError::Unsupported(format!(
                "virtio-fs host_path {} is not a directory",
                host.display()
            )));
        }
        if let Some(parent) = cfg.socket.parent() {
            fs::create_dir_all(parent).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        }
        let _ = fs::remove_file(&cfg.socket);
        pid = Some(spawn_virtiofsd(
            &cfg.virtiofsd_binary,
            host,
            &cfg.socket,
        )?);
        wait_for_socket(&cfg.socket, Duration::from_secs(15))?;
    } else if !cfg.socket.exists() {
        return Err(FluxError::Unsupported(format!(
            "virtio-fs socket {} missing (start virtiofsd or set host_path)",
            cfg.socket.display()
        )));
    }
    Ok(VirtioFsAttachment {
        tag: cfg.tag.clone(),
        socket: cfg.socket.clone(),
        pid,
    })
}

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() || tag.len() >= FS_TAG_LEN {
        return Err(FluxError::Unsupported(format!(
            "virtio-fs tag must be 1..{} bytes, got {:?}",
            FS_TAG_LEN - 1,
            tag
        )));
    }
    if tag.bytes().any(|b| b == 0) {
        return Err(FluxError::Unsupported(
            "virtio-fs tag must not contain NUL".into(),
        ));
    }
    Ok(())
}

/// Pack tag into virtio_fs_config.tag (36 bytes, NUL-padded).
pub fn tag_config_bytes(tag: &str) -> Result<[u8; FS_TAG_LEN]> {
    validate_tag(tag)?;
    let mut out = [0u8; FS_TAG_LEN];
    out[..tag.len()].copy_from_slice(tag.as_bytes());
    Ok(out)
}

fn spawn_virtiofsd(bin: &str, host: &Path, socket: &Path) -> Result<u32> {
    let child = Command::new(bin)
        .args([
            "--sandbox",
            "none",
            "--seccomp",
            "none",
            "--socket-path",
            &socket.to_string_lossy(),
            "--shared-dir",
            &host.to_string_lossy(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            FluxError::Hypervisor(format!(
                "spawning virtiofsd ({bin}) for {}: {e}",
                host.display()
            ))
        })?;
    Ok(child.id())
}

fn wait_for_socket(socket: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            // Ensure we can connect (virtiofsd finished bind/listen).
            if std::os::unix::net::UnixStream::connect(socket).is_ok() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(FluxError::Hypervisor(format!(
        "virtiofsd socket {} not ready within {timeout:?}",
        socket.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_validation() {
        assert!(validate_tag("fs0").is_ok());
        assert!(validate_tag("").is_err());
        assert!(validate_tag(&"x".repeat(FS_TAG_LEN)).is_err());
        let bytes = tag_config_bytes("fs0").unwrap();
        assert_eq!(&bytes[..3], b"fs0");
        assert_eq!(bytes[3], 0);
    }

    #[test]
    fn attach_requires_socket_or_host() {
        let cfg = VirtioFsConfig {
            tag: "fs0".into(),
            socket: PathBuf::from("/tmp/fluxvm-no-such-virtiofs.sock"),
            host_path: None,
            virtiofsd_binary: "virtiofsd".into(),
        };
        assert!(attach(&cfg).is_err());
    }
}
