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
#[derive(Debug, Clone, Default, Serialize)]
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
    /// Direct boot (`VZLinuxBootLoader`): an uncompressed arm64 `Image`. None boots EFI from the disk.
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub root_read_only: bool,
    pub extra_disks: Vec<fluxvm_core::model::AppleDisk>,
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
            media: if crate::macos_install::is_macos_install(req) {
                Some(crate::macos_install::install_media(req))
            } else {
                apple.media.clone()
            },
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
                .chain(apple.tagged_shares.iter().map(|s| ShareConfig {
                    tag: s.tag.clone(),
                    host_path: s.host_path.clone(),
                    read_only: s.read_only,
                }))
                .chain(apple.init_config.is_some().then(|| ShareConfig {
                    tag: fluxvm_oci_init::config::META_TAG.into(),
                    host_path: oci_meta_dir(&ctx.workspace),
                    read_only: true,
                }))
                .chain(
                    (apple.guest_os == AppleGuest::Macos && apple.firstboot.is_some()).then(|| {
                        ShareConfig {
                            tag: crate::macos_install::FIRSTBOOT_DIR.into(),
                            host_path: ctx.workspace.join(crate::macos_install::FIRSTBOOT_DIR),
                            read_only: true,
                        }
                    }),
                )
                .collect(),
            kernel: req.kernel.clone(),
            initrd: req.initrd.clone(),
            cmdline: req.kernel_args.clone(),
            root_read_only: apple.root_read_only,
            extra_disks: apple.extra_disks.clone(),
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

/// Where an OCI sandbox's `config.json` and agent token live (shared into the guest as `fluxvm-meta`).
pub fn oci_meta_dir(workspace: &Path) -> PathBuf {
    workspace.join("meta")
}

/// Writes `apple.init_config` and the agent token into [`oci_meta_dir`], replacing what a previous boot left.
pub fn write_oci_meta(req: &CreateVmRequest, workspace: &Path) -> Result<()> {
    use fluxvm_oci_init::config::{CONFIG_FILE, SECRETS_FILE, TOKEN_FILE};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let Some(apple) = req.apple.as_ref() else {
        return Ok(());
    };
    let Some(init) = apple.init_config.as_ref() else {
        return Ok(());
    };
    let dir = oci_meta_dir(workspace);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    fs::write(dir.join(CONFIG_FILE), serde_json::to_vec_pretty(init)?)?;
    // Only the creating launch carries secrets (they are never persisted); later boots keep the file it wrote.
    if !apple.secret_env.is_empty() {
        let values: std::collections::BTreeMap<&str, &str> = apple
            .secret_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        let path = dir.join(SECRETS_FILE);
        let tmp = dir.join(format!("{SECRETS_FILE}.tmp"));
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, &serde_json::to_vec(&values)?)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
    }
    let token_path = dir.join(TOKEN_FILE);
    match req
        .agent
        .as_ref()
        .filter(|a| a.enabled)
        .and_then(|a| a.token.as_deref())
    {
        Some(token) => {
            fs::write(&token_path, token)?;
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;
        }
        None => {
            let _ = fs::remove_file(&token_path);
        }
    }
    Ok(())
}

/// The vsock port the runner's egress proxy listens on (guest to host); the guest forwards 127.0.0.1:3128 to it.
pub const EGRESS_PORT: u32 = 3128;

pub const STATE_FILE: &str = "state.vzvmsave";
/// Files cloned alongside the saved state, so a restore gets the disk exactly as it was when the state was saved.
/// `auxiliary.bin` is a macOS guest's NVRAM.
pub const SNAPSHOT_FILES: &[&str] = &["disk.raw", "disk-overlay.asif", "efi.bin", "auxiliary.bin"];

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

/// A headless direct-boot Linux VM with no network card that runs until its guest powers off (the OCI rootfs builder).
#[derive(Debug, Clone)]
pub struct OneShotVm {
    pub workspace: PathBuf,
    pub disk: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub cmdline: String,
    pub cpus: u8,
    pub memory_mib: u64,
    pub shares: Vec<ShareConfig>,
}

impl OneShotVm {
    pub fn runner_config(&self) -> Result<RunnerConfig> {
        let id = uuid::Uuid::new_v4();
        let id8: String = id.simple().to_string().chars().take(8).collect();
        Ok(RunnerConfig {
            id: id.to_string(),
            workspace: self.workspace.clone(),
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            guest_os: "linux",
            disk: self.disk.clone(),
            mac: stable_mac(&self.workspace)?,
            control_socket: control_socket_path(&id8)?,
            serial_log: self.serial_log(),
            ip_file: ip_file(&self.workspace),
            display_count: 1,
            display_width: 1280,
            display_height: 800,
            display_ppi: 220,
            shares: self.shares.clone(),
            network_none: true,
            kernel: Some(self.kernel.clone()),
            initrd: Some(self.initrd.clone()),
            cmdline: Some(self.cmdline.clone()),
            ..RunnerConfig::default()
        })
    }

    pub fn serial_log(&self) -> PathBuf {
        self.workspace.join("serial.log")
    }

    /// Boots the VM and waits for the runner to exit (the guest powered off), killing it after `timeout`.
    /// Returns the guest's serial console output.
    pub async fn run(&self, timeout: std::time::Duration) -> Result<String> {
        let runner = find_runner()?;
        let conf = self.runner_config()?;
        let conf_path = conf.write(&self.workspace)?;
        let log = open_runner_log(&self.workspace)?;
        let mut child = tokio::process::Command::new(&runner)
            .args(["run", "--config"])
            .arg(&conf_path)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().context("cloning the runner log")?)
            .stderr(log)
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", runner.display()))?;
        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(s) => s?,
            Err(_) => {
                let _ = child.kill().await;
                bail!(
                    "the VM did not power off within {}s: {}",
                    timeout.as_secs(),
                    tail_runner_log(&self.workspace)
                );
            }
        };
        let serial = fs::read_to_string(self.serial_log()).unwrap_or_default();
        if !status.success() {
            bail!(
                "the Apple runner exited ({status}): {}",
                tail_runner_log(&self.workspace)
            );
        }
        Ok(serial)
    }
}

#[cfg(test)]
mod one_shot_tests {
    use super::*;

    #[test]
    fn one_shot_vm_is_headless_offline_direct_boot() {
        let dir = tempfile::tempdir().unwrap();
        let vm = OneShotVm {
            workspace: dir.path().into(),
            disk: dir.path().join("disk.raw"),
            kernel: "/k/oci-kernel".into(),
            initrd: "/k/oci-initrd".into(),
            cmdline: "console=hvc0".into(),
            cpus: 2,
            memory_mib: 1024,
            shares: vec![ShareConfig {
                tag: "fluxvm-meta".into(),
                host_path: dir.path().join("meta"),
                read_only: true,
            }],
        };
        let c = vm.runner_config().unwrap();
        assert_eq!(c.guest_os, "linux");
        assert!(
            c.network_none && !c.window && c.vsock_socket.is_none() && c.egress_allow.is_empty()
        );
        assert_eq!(c.kernel.as_deref(), Some(Path::new("/k/oci-kernel")));
        assert_eq!(c.shares[0].tag, "fluxvm-meta");
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["cmdline"], "console=hvc0");
        assert_eq!(
            json["serial_log"],
            dir.path().join("serial.log").display().to_string()
        );
    }

    #[test]
    fn secrets_go_only_to_a_private_meta_file_that_later_boots_keep() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut req: CreateVmRequest = serde_json::from_value(serde_json::json!({
            "name": "s", "backend": "vz", "image": "/r.ext4", "kernel": "/k",
            "apple": {"init_config": {"mode": "boot", "hostname": "s"}},
        }))
        .unwrap();
        req.apple.as_mut().unwrap().secret_env.insert(
            "DB_PASSWORD".into(),
            fluxvm_core::grants::Secret::new("hunter2"),
        );
        assert!(!serde_json::to_string(&req).unwrap().contains("hunter2"));
        assert!(!format!("{req:?}").contains("hunter2"));
        write_oci_meta(&req, dir.path()).unwrap();
        let meta = oci_meta_dir(dir.path());
        let secrets = meta.join("secrets.json");
        assert_eq!(
            fs::read_to_string(&secrets).unwrap(),
            r#"{"DB_PASSWORD":"hunter2"}"#
        );
        assert_eq!(
            fs::metadata(&secrets).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !fs::read_to_string(meta.join("config.json"))
                .unwrap()
                .contains("hunter2")
        );

        let reloaded: CreateVmRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        write_oci_meta(&reloaded, dir.path()).unwrap();
        assert!(fs::read_to_string(&secrets).unwrap().contains("hunter2"));
    }

    #[test]
    fn oci_sandbox_meta_holds_config_and_token() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let req: CreateVmRequest = serde_json::from_value(serde_json::json!({
            "name": "s", "backend": "vz", "image": "/r.ext4", "kernel": "/k",
            "agent": {"enabled": true, "port": 17777, "token": "t0k"},
            "apple": {"init_config": {"mode": "boot", "hostname": "s"}},
        }))
        .unwrap();
        write_oci_meta(&req, dir.path()).unwrap();
        let meta = oci_meta_dir(dir.path());
        let cfg: serde_json::Value =
            serde_json::from_slice(&fs::read(meta.join("config.json")).unwrap()).unwrap();
        assert_eq!(cfg["hostname"], "s");
        assert_eq!(fs::read_to_string(meta.join("agent.token")).unwrap(), "t0k");
        let mode = fs::metadata(meta.join("agent.token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let ctx = fluxvm_core::backend::LaunchContext {
            id: uuid::Uuid::new_v4(),
            workspace: dir.path().into(),
            disk: dir.path().join("root.raw"),
            seed_disk: None,
            log_path: dir.path().join("console.log"),
            network: fluxvm_core::backend::PreparedNetwork {
                spec: NetworkSpec::None,
                tap_name: None,
                tap_fd: None,
                netns: None,
                dhcp_leasefile: None,
                guest_ip: None,
                guest_cidr: None,
                gateway: None,
                extra_tap_fds: vec![],
            },
            guest_cid: Some(3),
            vsock_socket: None,
            disk_format: "raw".into(),
            nbd_export: None,
        };
        let conf = RunnerConfig::for_launch(&req, &ctx).unwrap();
        let share = conf.shares.iter().find(|s| s.tag == "fluxvm-meta").unwrap();
        assert!(share.read_only && share.host_path == meta);
    }
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
