// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use fluxvm_core::{
    backend::LaunchContext,
    model::{AppleGuest, CreateVmRequest, NetworkSpec},
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// JSON handed to `fluxvm-vz-runner --config`.
#[derive(Debug, Clone, Serialize)]
pub struct RunnerConfig {
    pub id: String,
    pub workspace: PathBuf,
    pub cpus: u8,
    pub memory_mib: u64,
    pub guest_os: &'static str,
    pub disk: PathBuf,
    pub seed: Option<PathBuf>,
    pub media: Option<PathBuf>,
    pub mac: String,
    pub control_socket: PathBuf,
    pub serial_log: PathBuf,
    pub vsock_socket: Option<PathBuf>,
    pub ip_file: PathBuf,
    pub window: bool,
    pub display_count: u8,
    pub clipboard: bool,
    pub bridge_interface: Option<String>,
    pub asif_overlay: bool,
    pub provision_full_name: Option<String>,
    pub provision_username: Option<String>,
    pub provision_password_file: Option<PathBuf>,
    pub provision_auto_login: bool,
    pub provision_remote_login: bool,
    pub display_width: u32,
    pub display_height: u32,
    pub display_ppi: u32,
    pub audio_output: bool,
    pub microphone: bool,
    pub rosetta: bool,
    pub nested_virtualization: bool,
    pub usb_controller: bool,
    pub vmnet: Option<fluxvm_core::model::AppleVmnetSpec>,
    pub custom_virtio: bool,
    /// virtiofs shares, tagged `fs0`, `fs1`, … in request order (the tags the guest-side mount uses).
    pub shares: Vec<ShareConfig>,
    /// Host `127.0.0.1:host_port` listeners that relay TCP to the guest's NAT address.
    pub forwards: Vec<ForwardConfig>,
    /// Attach no network device (`network.mode = "none"`).
    pub network_none: bool,
    /// Hosts the guest may reach through the vsock proxy on `EGRESS_PORT` (empty: no proxy).
    pub egress_allow: Vec<String>,
    /// A state file written by a snapshot; the runner resumes from it instead of cold-booting.
    pub restore_state: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareConfig {
    pub tag: String,
    pub host_path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForwardConfig {
    pub host_port: u16,
    pub guest_port: u16,
    /// Listen on the NAT gateway so other guests can connect (see `PortForward::guests`).
    pub guests: bool,
}

impl RunnerConfig {
    pub fn for_launch(req: &CreateVmRequest, ctx: &LaunchContext) -> Result<Self> {
        let apple = req.apple.clone().unwrap_or_default();
        let id8: String = ctx.id.simple().to_string().chars().take(8).collect();
        Ok(Self {
            id: ctx.id.to_string(),
            workspace: ctx.workspace.clone(),
            cpus: req.vcpus,
            memory_mib: req.memory_mib,
            guest_os: match apple.guest_os {
                AppleGuest::Linux => "linux",
                AppleGuest::Macos => "macos",
            },
            disk: ctx.disk.clone(),
            seed: ctx.seed_disk.clone(),
            media: apple.media,
            mac: stable_mac(&ctx.workspace)?,
            control_socket: control_socket_path(&id8)?,
            serial_log: ctx.log_path.clone(),
            // Always present: the daemon reaches an offline guest's sshd through it (the guest listens on vsock port 22).
            vsock_socket: Some(short_socket(
                &id8,
                "vsock",
                ctx.vsock_socket
                    .clone()
                    .unwrap_or_else(|| ctx.workspace.join("vsock.sock")),
            )),
            ip_file: ip_file(&ctx.workspace),
            window: apple.window,
            display_count: apple.display_count.clamp(1, 8),
            clipboard: apple.clipboard,
            bridge_interface: apple.bridge_interface.clone(),
            asif_overlay: apple.asif_overlay,
            provision_full_name: apple.provision_full_name.clone(),
            provision_username: apple.provision_username.clone(),
            provision_password_file: apple.provision_password_file.clone(),
            provision_auto_login: apple.provision_auto_login,
            provision_remote_login: apple.provision_remote_login,
            display_width: apple.display_width.clamp(800, 5120),
            display_height: apple.display_height.clamp(600, 2880),
            display_ppi: apple.display_ppi.clamp(72, 300),
            audio_output: apple.audio_output,
            microphone: apple.microphone,
            rosetta: apple.rosetta,
            nested_virtualization: apple.nested_virtualization,
            usb_controller: apple.usb_controller,
            vmnet: apple.vmnet.clone(),
            custom_virtio: apple.custom_virtio,
            restore_state: req
                .loadvm_tag
                .as_deref()
                .map(|tag| snapshot_dir(&ctx.workspace, tag).join(STATE_FILE)),
            shares: req
                .shared_folders
                .iter()
                .enumerate()
                .map(|(i, f)| ShareConfig {
                    tag: format!("fs{i}"),
                    host_path: f.host_path.clone(),
                    read_only: f.read_only,
                })
                .collect(),
            network_none: matches!(req.network, NetworkSpec::None),
            egress_allow: apple.egress_allow.clone(),
            forwards: match &req.network {
                NetworkSpec::User { forwards } => forwards
                    .iter()
                    .map(|f| ForwardConfig {
                        host_port: f.host_port,
                        guest_port: f.guest_port,
                        guests: f.guests,
                    })
                    .collect(),
                _ => Vec::new(),
            },
        })
    }

    pub fn write(&self, workspace: &Path) -> Result<PathBuf> {
        let p = workspace.join("vz-config.json");
        fs::write(&p, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("writing {}", p.display()))?;
        Ok(p)
    }
}

/// The vsock port the runner's egress proxy listens on (guest to host); the guest forwards 127.0.0.1:3128 to it.
pub const EGRESS_PORT: u32 = 3128;

pub const STATE_FILE: &str = "state.vzvmsave";
/// Files cloned alongside the saved state, so a restore gets the disk exactly as it was when the state was saved.
pub const SNAPSHOT_FILES: &[&str] = &["disk.raw", "disk-overlay.asif", "efi.bin"];

pub fn snapshot_dir(workspace: &Path, tag: &str) -> PathBuf {
    workspace.join("snapshots").join(tag)
}

/// Copy-on-write clone on APFS (`cp -c`), a plain copy elsewhere. Replaces `to` if it exists.
pub fn clone_file(from: &Path, to: &Path) -> Result<()> {
    let _ = fs::remove_file(to);
    let cloned = std::process::Command::new("cp")
        .arg("-c")
        .arg(from)
        .arg(to)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !cloned {
        fs::copy(from, to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    Ok(())
}

/// Files that make a macOS guest the machine it is, kept beside its disk by the installer. A clone of a prepared guest takes
/// the hardware model and auxiliary storage (NVRAM) from the template; its machine identifier is deliberately not copied, so the
/// runner gives every clone its own and two clones are two machines.
pub const MACOS_TEMPLATE_FILES: &[&str] = &["hardware.bin", "auxiliary.bin"];

/// Clones a prepared macOS guest's files into `workspace`. `image` is the template's disk (`<dir>/disk.raw`); the files sit
/// beside it. `Ok(false)` means `image` is not a prepared guest.
pub fn adopt_macos_template(image: &Path, workspace: &Path) -> Result<bool> {
    let Some(dir) = image.parent() else {
        return Ok(false);
    };
    if MACOS_TEMPLATE_FILES.iter().any(|f| !dir.join(f).is_file()) {
        return Ok(false);
    }
    for f in MACOS_TEMPLATE_FILES {
        clone_file(&dir.join(f), &workspace.join(f))?;
    }
    Ok(true)
}

/// unix socket paths are limited to ~104 bytes on macOS, so sockets live under a short per-user directory.
fn socket_dir() -> Result<PathBuf> {
    let uid = unsafe { libc::getuid() };
    let dir = PathBuf::from(format!("/tmp/fluxvm-{uid}"));
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn control_socket_path(id8: &str) -> Result<PathBuf> {
    Ok(socket_dir()?.join(format!("{id8}.ctl")))
}

fn short_socket(id8: &str, kind: &str, requested: PathBuf) -> PathBuf {
    // Keep the requested path if it already fits; otherwise relocate under the short directory.
    if requested.as_os_str().len() < 100 {
        return requested;
    }
    socket_dir()
        .map(|d| d.join(format!("{id8}.{kind}")))
        .unwrap_or(requested)
}

/// A locally-administered MAC kept in the workspace so a VM keeps its identity (and DHCP lease) across restarts.
fn stable_mac(workspace: &Path) -> Result<String> {
    let f = workspace.join("vz-mac");
    if let Ok(m) = fs::read_to_string(&f) {
        let m = m.trim().to_owned();
        if m.len() == 17 {
            return Ok(m);
        }
    }
    let u = uuid::Uuid::new_v4();
    let b = u.as_bytes();
    let mac = format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4]
    );
    fs::write(&f, &mac)?;
    Ok(mac)
}

/// Where the runner writes the guest's address once the guest reports it on the serial console.
pub fn ip_file(workspace: &Path) -> PathBuf {
    workspace.join("vz-ip")
}

pub fn read_guest_ip(workspace: &Path) -> Option<String> {
    let s = fs::read_to_string(ip_file(workspace)).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

pub(crate) fn open_runner_log(workspace: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(workspace.join("vz-runner.log"))
        .context("opening the runner log")
}

pub(crate) fn tail_runner_log(workspace: &Path) -> String {
    let s = fs::read_to_string(workspace.join("vz-runner.log")).unwrap_or_default();
    let lines: Vec<&str> = s.lines().rev().take(6).collect();
    let mut v = lines;
    v.reverse();
    if v.is_empty() {
        "(no runner output)".into()
    } else {
        v.join(" | ")
    }
}

/// Locates the signed runner: `FLUXVM_VZ_RUNNER`, then next to the daemon binary, then the copy built by this crate.
pub fn find_runner() -> Result<PathBuf> {
    let mut tried = Vec::new();
    if let Some(p) = std::env::var_os("FLUXVM_VZ_RUNNER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        tried.push(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let p = dir.join("fluxvm-vz-runner");
        if p.is_file() {
            return Ok(p);
        }
        tried.push(p);
    }
    if let Some(p) = option_env!("FLUXVM_VZ_RUNNER_BUILT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        tried.push(p);
    }
    bail!(
        "the Apple runner `fluxvm-vz-runner` was not found (looked at: {}). Build it with `cargo build -p fluxvm-apple` on macOS or set FLUXVM_VZ_RUNNER.",
        tried
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod template_tests {
    use super::*;

    #[test]
    fn a_prepared_guest_is_cloned_without_its_machine_identifier() {
        let d = tempfile::tempdir().unwrap();
        let (tmpl, ws) = (d.path().join("tmpl"), d.path().join("ws"));
        fs::create_dir_all(&tmpl).unwrap();
        fs::create_dir_all(&ws).unwrap();
        for f in ["disk.raw", "hardware.bin", "auxiliary.bin", "identity.bin"] {
            fs::write(tmpl.join(f), f).unwrap();
        }
        assert!(adopt_macos_template(&tmpl.join("disk.raw"), &ws).unwrap());
        assert_eq!(
            fs::read_to_string(ws.join("hardware.bin")).unwrap(),
            "hardware.bin"
        );
        assert_eq!(
            fs::read_to_string(ws.join("auxiliary.bin")).unwrap(),
            "auxiliary.bin"
        );
        assert!(
            !ws.join("identity.bin").exists(),
            "each clone gets its own identity"
        );
    }

    #[test]
    fn a_plain_disk_is_not_a_prepared_guest() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("disk.raw"), "x").unwrap();
        assert!(!adopt_macos_template(&d.path().join("disk.raw"), d.path()).unwrap());
    }
}
