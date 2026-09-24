// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Confidential-computing capability of this host, and what a sandbox asked
//! for versus what it got.
//!
//! A caller can ask for `auto` (use hardware memory encryption when the host has
//! it, otherwise run a normal VM and say why) or `required` (refuse to run
//! without it). Detection reads the kernel's own switches, so it reports what
//! KVM can actually offer rather than what the CPU model implies.
//!
//! **Launch is not wired up yet.** Building a correct SEV-SNP or TDX QEMU
//! command line here (memory backends, no hotplug slots, firmware, CPU model,
//! per-CPU C-bit position) interacts with the rest of the QEMU arguments and
//! cannot be verified without the hardware. Until that exists, a host that has
//! the hardware reports it but does not use it, so `required` fails closed and
//! `auto` falls back to a normal VM with an accurate reason. Flip
//! [`LAUNCH_SUPPORTED`] only together with the launch code.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Whether the QEMU launch path for confidential guests exists.
pub const LAUNCH_SUPPORTED: bool = false;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfidentialMode {
    Auto,
    Required,
}

/// What this host's kernel offers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostCapability {
    pub sev_snp: bool,
    pub tdx: bool,
    /// Whether FluxVM can launch a confidential guest on this host today.
    pub launch_supported: bool,
    pub detail: String,
}

/// The outcome recorded for a sandbox that asked for `confidential`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialStatus {
    pub active: bool,
    #[serde(default)]
    pub tech: Option<String>,
    #[serde(default)]
    pub reason: String,
}

const STATUS_FILE: &str = "confidential.json";

fn switch_on(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|v| matches!(v.trim(), "Y" | "y" | "1"))
        .unwrap_or(false)
}

/// Probe a filesystem root (`/` on a real host; a temporary tree in tests).
pub fn detect_at(root: &Path) -> HostCapability {
    let sev_snp = switch_on(&root.join("sys/module/kvm_amd/parameters/sev_snp"))
        && root.join("dev/sev").exists();
    let tdx = switch_on(&root.join("sys/module/kvm_intel/parameters/tdx"));
    let detail = match (sev_snp, tdx) {
        (true, _) => "AMD SEV-SNP is enabled in KVM".to_string(),
        (_, true) => "Intel TDX is enabled in KVM".to_string(),
        _ => "this host has neither SEV-SNP (kvm_amd sev_snp and /dev/sev) nor TDX (kvm_intel tdx) enabled".to_string(),
    };
    HostCapability {
        sev_snp,
        tdx,
        launch_supported: (sev_snp || tdx) && LAUNCH_SUPPORTED,
        detail,
    }
}

pub fn detect() -> HostCapability {
    detect_at(Path::new("/"))
}

/// Decide a sandbox's confidential outcome. `None` means it did not ask.
pub fn resolve(
    mode: Option<ConfidentialMode>,
    cap: &HostCapability,
) -> Result<Option<ConfidentialStatus>> {
    let Some(mode) = mode else {
        return Ok(None);
    };
    let tech = if cap.sev_snp {
        Some("sev-snp")
    } else if cap.tdx {
        Some("tdx")
    } else {
        None
    };
    if let (Some(tech), true) = (tech, cap.launch_supported) {
        return Ok(Some(ConfidentialStatus {
            active: true,
            tech: Some(tech.into()),
            reason: String::new(),
        }));
    }
    let reason = match tech {
        Some(tech) => format!(
            "{tech} is available on this host but FluxVM cannot launch confidential guests yet"
        ),
        None => cap.detail.clone(),
    };
    if mode == ConfidentialMode::Required {
        bail!("confidential computing is required but unavailable: {reason}");
    }
    Ok(Some(ConfidentialStatus {
        active: false,
        tech: None,
        reason,
    }))
}

pub async fn write_status(workspace: &Path, status: &ConfidentialStatus) -> Result<()> {
    tokio::fs::write(workspace.join(STATUS_FILE), serde_json::to_vec(status)?).await?;
    Ok(())
}

pub async fn read_status(workspace: &Path) -> Option<ConfidentialStatus> {
    let raw = tokio::fs::read(workspace.join(STATUS_FILE)).await.ok()?;
    serde_json::from_slice(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempdir::Root {
        tempdir::Root::new(files)
    }

    /// A minimal scratch directory, so the crate needs no extra dev-dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Root(PathBuf);
        impl Root {
            pub fn new(files: &[(&str, &str)]) -> Self {
                let root = std::env::temp_dir().join(format!("fluxvm-conf-{}", uuid::Uuid::new_v4()));
                for (path, content) in files {
                    let full = root.join(path);
                    std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                    std::fs::write(full, content).unwrap();
                }
                std::fs::create_dir_all(&root).unwrap();
                Self(root)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn a_host_with_nothing_enabled_reports_none() {
        let root = tree(&[]);
        let cap = detect_at(root.path());
        assert!(!cap.sev_snp && !cap.tdx && !cap.launch_supported);
        assert!(cap.detail.contains("neither"));
    }

    #[test]
    fn sev_snp_needs_both_the_kvm_switch_and_the_device() {
        let switch_only = tree(&[("sys/module/kvm_amd/parameters/sev_snp", "Y\n")]);
        assert!(!detect_at(switch_only.path()).sev_snp);
        let both = tree(&[
            ("sys/module/kvm_amd/parameters/sev_snp", "Y\n"),
            ("dev/sev", ""),
        ]);
        assert!(detect_at(both.path()).sev_snp);
        let off = tree(&[("sys/module/kvm_amd/parameters/sev_snp", "N\n"), ("dev/sev", "")]);
        assert!(!detect_at(off.path()).sev_snp);
    }

    #[test]
    fn tdx_follows_the_kvm_intel_switch() {
        assert!(detect_at(tree(&[("sys/module/kvm_intel/parameters/tdx", "1")]).path()).tdx);
        assert!(!detect_at(tree(&[("sys/module/kvm_intel/parameters/tdx", "N")]).path()).tdx);
    }

    fn cap(sev_snp: bool, tdx: bool, launch_supported: bool) -> HostCapability {
        HostCapability {
            sev_snp,
            tdx,
            launch_supported,
            detail: "no hardware".into(),
        }
    }

    #[test]
    fn not_asking_records_nothing() {
        assert_eq!(resolve(None, &cap(true, false, true)).unwrap(), None);
    }

    #[test]
    fn auto_falls_back_with_a_reason_when_there_is_no_hardware() {
        let status = resolve(Some(ConfidentialMode::Auto), &cap(false, false, false))
            .unwrap()
            .unwrap();
        assert!(!status.active);
        assert_eq!(status.reason, "no hardware");
    }

    #[test]
    fn required_refuses_without_hardware() {
        let error = resolve(Some(ConfidentialMode::Required), &cap(false, false, false))
            .unwrap_err()
            .to_string();
        assert!(error.contains("required") && error.contains("no hardware"), "{error}");
    }

    #[test]
    fn hardware_without_a_launch_path_is_reported_honestly() {
        let auto = resolve(Some(ConfidentialMode::Auto), &cap(true, false, false))
            .unwrap()
            .unwrap();
        assert!(!auto.active);
        assert!(auto.reason.contains("sev-snp") && auto.reason.contains("cannot launch"));
        assert!(resolve(Some(ConfidentialMode::Required), &cap(true, false, false)).is_err());
    }

    #[test]
    fn hardware_with_a_launch_path_is_active() {
        let status = resolve(Some(ConfidentialMode::Required), &cap(false, true, true))
            .unwrap()
            .unwrap();
        assert!(status.active);
        assert_eq!(status.tech.as_deref(), Some("tdx"));
    }

    #[test]
    fn launch_is_not_claimed_until_it_exists() {
        // If this fails, someone flipped LAUNCH_SUPPORTED: the launch code and
        // its hardware verification must land in the same change.
        assert!(!LAUNCH_SUPPORTED);
    }

    #[tokio::test]
    async fn status_round_trips_through_the_workspace() {
        let dir = std::env::temp_dir().join(format!("fluxvm-conf-ws-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        assert_eq!(read_status(&dir).await, None);
        let status = ConfidentialStatus {
            active: false,
            tech: None,
            reason: "x".into(),
        };
        write_status(&dir, &status).await.unwrap();
        assert_eq!(read_status(&dir).await, Some(status));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
